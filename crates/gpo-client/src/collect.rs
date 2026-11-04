use pc_common::gpo::*;
use roxmltree::{Document, Node};
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::process::Command;

const PS_SCRIPT: &str = r#"
param([string]$Out)
$ErrorActionPreference = 'Stop'
Import-Module GroupPolicy
Get-GPOReport -All -ReportType Xml -Path (Join-Path $Out 'gpos.xml')

$gpos = New-Object System.Collections.ArrayList
$groupSids = @{}
foreach ($g in (Get-GPO -All)) {
    $perms = New-Object System.Collections.ArrayList
    try {
        foreach ($p in (Get-GPPermission -Guid $g.Id -All)) {
            $t = $p.Trustee
            [void]$perms.Add([ordered]@{
                sid = [string]$t.Sid.Value; name = [string]$t.Name; domain = [string]$t.Domain
                sidType = [string]$t.SidType; permission = [string]$p.Permission
                denied = [bool]$p.Denied; inherited = [bool]$p.Inherited })
            if (($t.SidType -in 'Group','Alias','WellKnownGroup') -and -not $p.Denied -and [string]$p.Permission -eq 'GpoApply') {
                $groupSids[[string]$t.Sid.Value] = [string]$t.Name
            }
        }
    } catch { Write-Warning ("Berechtigungen von {0} nicht lesbar: {1}" -f $g.DisplayName, $_) }
    [void]$gpos.Add([ordered]@{ id = $g.Id.ToString(); permissions = @($perms) })
}

$groups = New-Object System.Collections.ArrayList
$hasAd = [bool](Get-Module -ListAvailable ActiveDirectory)
foreach ($sid in $groupSids.Keys) {
    $members = @(); $trunc = $false
    if ($hasAd -and $sid -ne 'S-1-5-11' -and $sid -ne 'S-1-1-0') {
        try {
            Import-Module ActiveDirectory
            $all = @(Get-ADGroupMember -Identity $sid -Recursive -ErrorAction Stop)
            if ($all.Count -gt 200) { $trunc = $true }
            $members = @($all | Select-Object -First 200 | ForEach-Object {
                [ordered]@{ name = [string]$_.name; sam = [string]$_.SamAccountName; class = [string]$_.objectClass } })
        } catch { }
    }
    [void]$groups.Add([ordered]@{ sid = $sid; name = $groupSids[$sid]; members = @($members); truncated = $trunc })
}

$result = [ordered]@{ gpos = @($gpos); groups = @($groups) }
$json = $result | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText((Join-Path $Out 'perms.json'), $json, (New-Object System.Text.UTF8Encoding($false)))
"#;

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawPerm {
    sid: String,
    name: String,
    domain: String,
    #[serde(rename = "sidType")]
    sid_type: String,
    permission: String,
    denied: bool,
    inherited: bool,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawGpo {
    id: String,
    permissions: Vec<RawPerm>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawPermFile {
    gpos: Vec<RawGpo>,
    groups: Vec<GpoGroup>,
}

pub fn run_powershell(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let script = dir.join("collect.ps1");
    // UTF-8 mit BOM, damit Windows PowerShell 5.1 Umlaute korrekt liest
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(PS_SCRIPT.as_bytes());
    fs::write(&script, bytes).map_err(|e| e.to_string())?;
    let out = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script)
        .arg("-Out")
        .arg(dir)
        .output()
        .map_err(|e| format!("powershell.exe konnte nicht gestartet werden: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "Datensammlung fehlgeschlagen:\n{}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

fn read_text(path: &Path) -> Result<String, String> {
    let b = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let s = if b.starts_with(&[0xFF, 0xFE]) {
        let u: Vec<u16> = b[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u)
    } else if b.starts_with(&[0xFE, 0xFF]) {
        let u: Vec<u16> = b[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u)
    } else if b.starts_with(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8_lossy(&b[3..]).into_owned()
    } else {
        String::from_utf8_lossy(&b).into_owned()
    };
    Ok(s)
}

fn norm_id(s: &str) -> String {
    s.trim()
        .trim_matches(|c| c == '{' || c == '}')
        .to_lowercase()
}

fn child<'a, 'b>(n: Node<'a, 'b>, name: &str) -> Option<Node<'a, 'b>> {
    n.children()
        .find(|c| c.is_element() && c.tag_name().name() == name)
}

fn text_of(n: Node, name: &str) -> String {
    child(n, name)
        .map(|c| c.text().unwrap_or("").trim().to_string())
        .unwrap_or_default()
}

fn has_elem_children(n: Node) -> bool {
    n.children().any(|c| c.is_element())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max).collect();
        format!("{t}…")
    }
}

const NAME_KEYS: &[&str] = &[
    "Name",
    "KeyName",
    "DisplayName",
    "Path",
    "Command",
    "Action",
    "SettingName",
    "Setting",
    "FilterName",
];
const SKIP_KEYS: &[&str] = &["Explain", "Supported", "Comment"];

fn walk(n: Node, ctx: &mut Vec<String>, scope: &str, area: &str, out: &mut Vec<GpoSetting>) {
    let mut leaves: Vec<(String, String)> = Vec::new();
    for c in n.children().filter(|c| c.is_element()) {
        if !has_elem_children(c) {
            let t = c.text().unwrap_or("").trim();
            let key = c.tag_name().name();
            if !t.is_empty() && !SKIP_KEYS.contains(&key) {
                leaves.push((key.to_string(), t.to_string()));
            }
        }
    }
    let mut pushed = false;
    if !leaves.is_empty() {
        let own = NAME_KEYS
            .iter()
            .find_map(|k| {
                leaves
                    .iter()
                    .find(|(lk, _)| lk == k)
                    .map(|(_, v)| v.clone())
            })
            .unwrap_or_else(|| n.tag_name().name().to_string());
        let mut full = ctx.clone();
        full.push(own.clone());
        let detail = leaves
            .iter()
            .map(|(k, v)| format!("{k}: {}", truncate(v, 300)))
            .collect::<Vec<_>>()
            .join(" | ");
        out.push(GpoSetting {
            scope: scope.to_string(),
            area: area.to_string(),
            name: truncate(&full.join(" › "), 400),
            detail,
        });
        if leaves.iter().any(|(k, _)| NAME_KEYS.contains(&k.as_str())) {
            ctx.push(own);
            pushed = true;
        }
    }
    for c in n
        .children()
        .filter(|c| c.is_element() && has_elem_children(*c))
    {
        walk(c, ctx, scope, area, out);
    }
    if pushed {
        ctx.pop();
    }
}

fn extract_settings(scope_node: Node, scope: &str, out: &mut Vec<GpoSetting>) {
    for ed in scope_node
        .children()
        .filter(|c| c.is_element() && c.tag_name().name() == "ExtensionData")
    {
        let area = {
            let n = text_of(ed, "Name");
            if n.is_empty() {
                "Unbekannt".to_string()
            } else {
                n
            }
        };
        if let Some(ext) = child(ed, "Extension") {
            let mut ctx = Vec::new();
            walk(ext, &mut ctx, scope, &area, out);
        }
    }
}

pub fn load(dir: &Path) -> Result<GpoSnapshot, String> {
    let mut xml = read_text(&dir.join("gpos.xml"))?;
    if xml.trim_start().starts_with("<?xml") {
        if let Some(i) = xml.find("?>") {
            xml = xml[i + 2..].to_string();
        }
    }
    let doc = Document::parse(&xml).map_err(|e| format!("gpos.xml ungueltig: {e}"))?;

    let perm_text = read_text(&dir.join("perms.json"))?;
    let pf: RawPermFile = serde_json::from_str(perm_text.trim_start_matches('\u{feff}'))
        .map_err(|e| format!("perms.json ungueltig: {e}"))?;

    let mut ds = GpoSnapshot {
        groups: pf.groups.clone(),
        ..Default::default()
    };

    for n in doc.descendants().filter(|n| {
        n.is_element() && n.tag_name().name() == "GPO" && child(*n, "Identifier").is_some()
    }) {
        let ident = child(n, "Identifier").unwrap();
        let id = norm_id(&text_of(ident, "Identifier"));
        let mut g = GpoItem {
            id: id.clone(),
            domain: text_of(ident, "Domain"),
            name: text_of(n, "Name"),
            created: text_of(n, "CreatedTime"),
            modified: text_of(n, "ModifiedTime"),
            wmi_filter: text_of(n, "FilterName"),
            ..Default::default()
        };
        if let Some(sd) = child(n, "SecurityDescriptor") {
            if let Some(o) = child(sd, "Owner") {
                g.owner = text_of(o, "Name");
            }
        }
        for (scope, label) in [("Computer", "Computer"), ("User", "Benutzer")] {
            if let Some(sn) = child(n, scope) {
                let enabled = text_of(sn, "Enabled").eq_ignore_ascii_case("true");
                let ver = format!(
                    "AD {} / SYSVOL {}",
                    text_of(sn, "VersionDirectory"),
                    text_of(sn, "VersionSysvol")
                );
                if scope == "Computer" {
                    g.computer_enabled = enabled;
                    g.computer_version = ver;
                } else {
                    g.user_enabled = enabled;
                    g.user_version = ver;
                }
                extract_settings(sn, label, &mut g.settings);
            }
        }
        for l in n
            .children()
            .filter(|c| c.is_element() && c.tag_name().name() == "LinksTo")
        {
            g.links.push(GpoLink {
                som_name: text_of(l, "SOMName"),
                som_path: text_of(l, "SOMPath"),
                enabled: text_of(l, "Enabled").eq_ignore_ascii_case("true"),
                enforced: text_of(l, "NoOverride").eq_ignore_ascii_case("true"),
            });
        }
        if let Some(pg) = pf.gpos.iter().find(|p| norm_id(&p.id) == id) {
            g.permissions = pg
                .permissions
                .iter()
                .map(|p| GpoPerm {
                    sid: p.sid.clone(),
                    name: p.name.clone(),
                    domain: p.domain.clone(),
                    sid_type: p.sid_type.clone(),
                    permission: p.permission.clone(),
                    denied: p.denied,
                    inherited: p.inherited,
                })
                .collect();
        }
        if ds.domain.is_empty() {
            ds.domain = g.domain.clone();
        }
        ds.gpos.push(g);
    }
    ds.gpos
        .sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(ds)
}
