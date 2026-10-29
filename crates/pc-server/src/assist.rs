//! Audit-Assist: Schritt-für-Schritt-Anleitung, betroffene Objekte und ein
//! PowerShell-Skript zum Beheben eines einzelnen Befunds.
//!
//! Der Server ändert selbst nichts. Die erzeugten Skripte laufen ohne Parameter
//! als Probelauf, sichern vor jeder Änderung den bisherigen Stand und wenden
//! Änderungen erst mit `-Apply` an.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use chrono::Local;
use serde::Serialize;
use tokio_postgres::GenericClient;

use crate::config::AnalysisConfig;
use crate::directory::Directory;
use pc_common::rights::{can_change_permissions, Rights};
use pc_common::sid::rid;
use pc_common::wellknown;

/// Höchstzahl der Objekte in Liste und Skript.
const MAX_OBJECTS: usize = 1000;

/// Der zu behebende Befund.
pub struct FindingRef {
    pub system_id: Option<i64>,
    pub hostname: Option<String>,
    pub rule: String,
    pub title: String,
    pub path: Option<String>,
    pub sid: Option<String>,
}

#[derive(Serialize)]
pub struct Guide {
    /// Was zu tun ist, in Reihenfolge.
    pub steps: Vec<String>,
    /// Wichtiger Hinweis vor dem Ausführen (Risiko der Änderung).
    pub warning: Option<String>,
    pub objects: Vec<Obj>,
    pub objects_total: usize,
    pub script: Option<Script>,
    /// Wie PermissionCenter die Behebung bestätigt.
    pub verify: String,
}

#[derive(Serialize)]
pub struct Obj {
    pub label: String,
    pub info: String,
}

#[derive(Serialize)]
pub struct Script {
    pub file_name: String,
    /// Wo das Skript auszuführen ist.
    pub target: String,
    /// `change` (mit Probelauf/-Apply) oder `review` (nur lesend)
    pub kind: &'static str,
    pub body: String,
}

struct AceObj {
    path: String,
    sid: String,
    ace_type: String,
    mask: u32,
    rights: Rights,
    flags: i32,
}

/// PowerShell-Zeichenkette in einfachen Anführungszeichen.
fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Vererbungsflags eines ACE im icacls-Format, z. B. `(OI)(CI)`.
fn inherit_flags(flags: i32) -> String {
    let mut s = String::new();
    for (bit, f) in [(0x1, "(OI)"), (0x2, "(CI)"), (0x4, "(NP)"), (0x8, "(IO)")] {
        if flags & bit != 0 {
            s.push_str(f);
        }
    }
    s
}

fn icacls_perm(r: Rights) -> Option<&'static str> {
    match r {
        Rights::FullControl => Some("F"),
        Rights::Modify => Some("M"),
        Rights::Write => Some("W"),
        Rights::ReadExecute => Some("RX"),
        Rights::Read => Some("R"),
        Rights::Special | Rights::None => None,
    }
}

const PS_CHANGE_HEAD: &str = r#"<#
  PermissionCenter Audit-Assist
  Befund:  {TITLE}
  Ziel:    {TARGET}
  Erzeugt: {DATE}

  Ohne Parameter läuft das Skript als PROBELAUF und zeigt nur an, was es ändern würde.
  Änderungen anwenden (PowerShell als Administrator):  .\{FILE} -Apply{EXTRA_HELP}
#>
param(
    [switch] $Apply{EXTRA_PARAM}
)
$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

function Invoke-Step([string] $Text, [scriptblock] $Action) {
    if (-not $Apply) { Write-Host "[Probelauf] $Text"; return }
    Write-Host "-> $Text"
    try { & $Action } catch { Write-Warning "Fehlgeschlagen: $Text - $($_.Exception.Message)" }
}
"#;

const PS_ACL_HELPERS: &str = r#"
# Vor jeder Änderung wird die bisherige ACL (SDDL) gesichert.
$backup = Join-Path $env:ProgramData "PermissionCenter\acl-backup\$stamp-{RULE}.txt"

function Backup-Acl([string] $Path) {
    $dir = Split-Path $backup
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
    $sddl = (Get-Acl -LiteralPath $Path).Sddl
    Add-Content -LiteralPath $backup -Value ("{0}`t{1}" -f $Path, $sddl) -Encoding UTF8
}

# Entfernt explizite Einträge einer SID (Type: All, Allow oder Deny). Anders als icacls
# funktioniert das auch für verwaiste SIDs, die sich nicht mehr auflösen lassen.
function Remove-AceFor([string] $Path, [string] $Sid, [string] $Type = 'All') {
    $item = Get-Item -LiteralPath $Path -Force
    $acl = $item.GetAccessControl('Access')
    $id = New-Object Security.Principal.SecurityIdentifier $Sid
    $rules = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference -eq $id -and ($Type -eq 'All' -or "$($_.AccessControlType)" -eq $Type) })
    if ($rules.Count -eq 0) { Write-Host '   (kein expliziter Eintrag mehr vorhanden)'; return }
    foreach ($r in $rules) { $acl.RemoveAccessRuleSpecific($r) }
    $item.SetAccessControl($acl)
}

function Invoke-Icacls {
    $ErrorActionPreference = 'Continue'
    $out = & icacls.exe @args 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "icacls $($args -join ' '): $($out.Trim())" }
}

"#;

const PS_ACL_FOOT: &str = r#"
if ($Apply -and (Test-Path $backup)) { Write-Host "Sicherung der vorherigen Berechtigungen: $backup" }
# Wiederherstellen aus der Sicherung:
#   Get-Content <Sicherungsdatei> | ForEach-Object {
#       $p, $sddl = $_ -split "`t", 2
#       $item = Get-Item -LiteralPath $p -Force; $acl = $item.GetAccessControl('Access')
#       $acl.SetSecurityDescriptorSddlForm($sddl, 'Access'); $item.SetAccessControl($acl)
#   }
"#;

const PS_AD_HELPERS: &str = r#"
# Sicherung gelöschter bzw. geänderter AD-Objekte
$backupDir = Join-Path ([Environment]::GetFolderPath('MyDocuments')) "PermissionCenter-Sicherung\$stamp-{RULE}"
if ($Apply) {
    Import-Module ActiveDirectory
    New-Item -ItemType Directory -Force $backupDir | Out-Null
}

function Backup-AdGroup([string] $Sid) {
    $g = Get-ADGroup -Identity $Sid -Properties *
    $g | Export-Clixml (Join-Path $backupDir "$($g.SamAccountName).xml")
    Get-ADGroupMember -Identity $Sid | Select-Object SamAccountName, SID, objectClass |
        Export-Csv (Join-Path $backupDir "$($g.SamAccountName)-Mitglieder.csv") -NoTypeInformation -Encoding UTF8
}

"#;

const PS_FOOT: &str = r#"
if (-not $Apply) { Write-Host ''; Write-Host 'Probelauf beendet - nichts geändert. Zum Anwenden mit -Apply starten.' -ForegroundColor Yellow }
"#;

struct ScriptBuilder {
    rule: String,
    title: String,
    target: String,
    extra_param: String,
    extra_help: String,
    kind: &'static str,
    acl: bool,
    ad: bool,
    body: String,
}

impl ScriptBuilder {
    fn new(f: &FindingRef, target: String) -> Self {
        Self {
            rule: f.rule.clone(),
            title: f.title.clone(),
            target,
            extra_param: String::new(),
            extra_help: String::new(),
            kind: "change",
            acl: false,
            ad: false,
            body: String::new(),
        }
    }
    fn line(&mut self, s: impl AsRef<str>) {
        self.body.push_str(s.as_ref());
        self.body.push('\n');
    }
    fn step(&mut self, text: &str, action: &str) {
        self.line(format!("Invoke-Step {} {{ {action} }}", q(text)));
    }
    fn file_name(&self) -> String {
        format!("pc-fix-{}.ps1", self.rule.to_lowercase().replace('_', "-"))
    }
    fn build(self) -> Script {
        let file_name = self.file_name();
        let date = Local::now().format("%d.%m.%Y %H:%M").to_string();
        let mut out = PS_CHANGE_HEAD
            .replace("{TITLE}", &self.title.replace("#>", "# >"))
            .replace("{TARGET}", &self.target)
            .replace("{DATE}", &date)
            .replace("{FILE}", &file_name)
            .replace("{EXTRA_PARAM}", &self.extra_param)
            .replace("{EXTRA_HELP}", &self.extra_help);
        if self.kind == "review" {
            // Nur lesend: kein Probelauf nötig
            out = out
                .replace(
                    "  Ohne Parameter läuft das Skript als PROBELAUF und zeigt nur an, was es ändern würde.\n",
                    "  Das Skript ändert nichts, es zeigt nur den aktuellen Stand zur Prüfung an.\n",
                )
                .replace(
                    &format!("  Änderungen anwenden (PowerShell als Administrator):  .\\{file_name} -Apply\n"),
                    &format!("  Ausführen (PowerShell als Administrator):  .\\{file_name}\n"),
                );
        }
        if self.acl {
            out.push_str(&PS_ACL_HELPERS.replace("{RULE}", &self.rule));
        }
        if self.ad {
            out.push_str(&PS_AD_HELPERS.replace("{RULE}", &self.rule));
        }
        if !self.acl && !self.ad {
            out.push('\n');
        }
        out.push_str(&self.body);
        if self.acl {
            out.push_str(PS_ACL_FOOT);
        }
        if self.kind == "change" {
            out.push_str(PS_FOOT);
        }
        Script {
            file_name,
            target: self.target,
            kind: self.kind,
            body: out.replace('\n', "\r\n"),
        }
    }
}

async fn explicit_aces(
    c: &impl GenericClient,
    system_id: i64,
    sid: Option<&str>,
    path: Option<&str>,
    ace_type: Option<&str>,
) -> Result<Vec<AceObj>> {
    Ok(c
        .query(
            "SELECT f.path, a.sid, a.ace_type, a.mask, a.rights, a.flags
             FROM aces a JOIN folders f ON f.system_id = a.system_id AND f.local_id = a.folder_local_id
             WHERE a.system_id = $1 AND NOT a.inherited AND a.ace_type IN ('allow', 'deny')
               AND ($2::text IS NULL OR a.sid = $2)
               AND ($3::text IS NULL OR f.path = $3)
               AND ($4::text IS NULL OR a.ace_type = $4)
             ORDER BY lower(f.path), a.sid",
            &[&system_id, &sid, &path, &ace_type],
        )
        .await?
        .iter()
        .map(|r| AceObj {
            path: r.get(0),
            sid: r.get(1),
            ace_type: r.get(2),
            mask: r.get::<_, i64>(3) as u32,
            rights: Rights::parse(r.get(4)),
            flags: r.get(5),
        })
        .collect())
}

/// Gruppiert ACEs nach Pfad (Reihenfolge bleibt erhalten).
fn by_path(aces: Vec<AceObj>) -> BTreeMap<String, Vec<AceObj>> {
    let mut m: BTreeMap<String, Vec<AceObj>> = BTreeMap::new();
    for a in aces {
        m.entry(a.path.clone()).or_default().push(a);
    }
    m
}

fn ace_info(a: &AceObj) -> String {
    let flags = inherit_flags(a.flags);
    format!(
        "{}{}{}",
        if a.ace_type == "deny" {
            "Verweigern: "
        } else {
            ""
        },
        a.rights.label_de(),
        if flags.is_empty() {
            String::new()
        } else {
            format!(" {flags}")
        }
    )
}

fn truncate<T>(mut v: Vec<T>) -> (Vec<T>, usize) {
    let total = v.len();
    v.truncate(MAX_OBJECTS);
    (v, total)
}

fn steps(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// Erstellt die Anleitung für einen Befund.
pub async fn guide(c: &impl GenericClient, f: &FindingRef, cfg: &AnalysisConfig) -> Result<Guide> {
    let dir = Directory::load(c, cfg.inactive_days).await?;
    let host = f.hostname.clone().unwrap_or_else(|| "?".into());
    let host_target = format!("{host} (lokal auf dem Server)");
    let ad_target =
        "Rechner mit RSAT-Modul ActiveDirectory (z. B. Domänencontroller), Konto mit Rechten auf die Objekte"
            .to_string();
    let sid = f.sid.as_deref().unwrap_or("");
    let name = dir.view(sid).name;
    let verify = match f.system_id {
        Some(_) if f.rule == "STALE_SYSTEM" => format!(
            "Sobald ein neuer Scan von {host} eingeht, verschwindet der Befund automatisch."
        ),
        Some(_) => format!(
            "Nach dem nächsten Scan von {host} prüft PermissionCenter automatisch, ob der Befund behoben ist. \
             Sofort prüfen: auf {host} „pc-client scan“ ausführen."
        ),
        None => "Nach dem nächsten AD-Abgleich prüft PermissionCenter automatisch, ob der Befund behoben ist."
            .into(),
    };

    let mut g = Guide {
        steps: Vec::new(),
        warning: None,
        objects: Vec::new(),
        objects_total: 0,
        script: None,
        verify,
    };
    let sys = f.system_id.unwrap_or_default();

    match f.rule.as_str() {
        "ORPHANED_SID" | "DISABLED_USER_ACE" | "INACTIVE_USER_ACE" => {
            let aces = explicit_aces(c, sys, Some(sid), None, None).await?;
            let groups = by_path(aces);
            g.steps = match f.rule.as_str() {
                "ORPHANED_SID" => steps(&[
                    "Prüfen, ob eine Nachfolgegruppe die Rechte des gelöschten Kontos übernehmen muss (Liste unten).",
                    "Falls ja: der Nachfolgegruppe auf denselben Ordnern die Rechte geben.",
                    "Skript zunächst ohne -Apply auf dem Server ausführen und die Ausgabe prüfen.",
                    "Skript mit -Apply ausführen – es sichert jede ACL und entfernt die verwaisten Einträge.",
                    "Als erledigt markieren; der nächste Scan bestätigt die Behebung.",
                ]),
                "DISABLED_USER_ACE" => steps(&[
                    "Kurz klären, ob jemand die Aufgaben des ausgeschiedenen Benutzers übernimmt und dessen Zugriff braucht.",
                    "Skript ohne -Apply ausführen und die Liste prüfen.",
                    "Skript mit -Apply ausführen – die Einträge des deaktivierten Kontos werden entfernt.",
                    "Austrittsprozess ergänzen, damit Berechtigungen künftig beim Deaktivieren entfernt werden.",
                ]),
                _ => steps(&[
                    "Mit Fachabteilung bzw. Vorgesetzten klären, ob das Konto noch gebraucht wird.",
                    "Wird es nicht mehr gebraucht: Konto deaktivieren (siehe Befund „Inaktives Benutzerkonto“) und dieses Skript mit -Apply ausführen.",
                    "Wird es weiter gebraucht: als Ausnahme mit Begründung akzeptieren.",
                ]),
            };
            let mut s = ScriptBuilder::new(f, host_target.clone());
            s.acl = true;
            for (path, aces) in groups.iter().take(MAX_OBJECTS) {
                s.step(
                    &format!("{path}: alle expliziten Einträge für {name} entfernen"),
                    &format!(
                        "Backup-Acl {p}; Remove-AceFor {p} {sid}",
                        p = q(path),
                        sid = q(sid)
                    ),
                );
                g.objects.push(Obj {
                    label: path.clone(),
                    info: aces.iter().map(ace_info).collect::<Vec<_>>().join(", "),
                });
            }
            g.objects_total = groups.len();
            g.script = Some(s.build());
        }

        "DIRECT_USER_ACE" => {
            let aces = explicit_aces(c, sys, Some(sid), None, Some("allow")).await?;
            let groups = by_path(aces);
            let in_ad = dir.users.contains_key(sid);
            g.steps = steps(&[
                "Passende Berechtigungsgruppe festlegen oder anlegen (AGDLP: z. B. „DL_Projekt_Ändern“), die genau diese Rechte bekommen soll.",
                "Den Benutzer in die Gruppe aufnehmen (das Skript erledigt das bei AD-Konten mit).",
                "Skript mit -Group \"DOMÄNE\\Gruppe\" ohne -Apply ausführen und prüfen.",
                "Skript mit -Group … -Apply ausführen: die Gruppe erhält dieselben Rechte (Vollzugriff wird zu Ändern), danach wird der Direkteintrag entfernt.",
                "Der Benutzer muss sich ggf. neu anmelden, damit die neue Gruppenmitgliedschaft wirkt.",
            ]);
            g.warning = Some(
                "Die Gruppenmitgliedschaft wirkt erst nach einer neuen Anmeldung des Benutzers. Bis dahin kann der Zugriff kurz fehlen – am besten außerhalb der Arbeitszeit umstellen."
                    .into(),
            );
            let mut s = ScriptBuilder::new(f, host_target.clone());
            s.acl = true;
            s.extra_param =
                ",\n    # Zielgruppe, z. B. \"FIRMA\\DL_Projekt_Aendern\"\n    [string] $Group"
                    .into();
            s.extra_help = " -Group \"DOMÄNE\\Gruppe\"".into();
            s.line("if (-not $Group) { $Group = '<Gruppe>'; if ($Apply) { throw 'Bitte die Zielgruppe angeben: -Group \"DOMÄNE\\Gruppe\"' } }");
            if in_ad {
                s.step(
                    &format!("{name} in die Gruppe aufnehmen"),
                    &format!(
                        "Import-Module ActiveDirectory; Add-ADGroupMember -Identity ($Group -split '\\\\')[-1] -Members {}",
                        q(sid)
                    ),
                );
            }
            for (path, aces) in groups.iter().take(MAX_OBJECTS) {
                // Vollzugriff wird zu Ändern, sonst entstünde gleich ein neuer Befund
                let grants: BTreeSet<String> = aces
                    .iter()
                    .filter_map(|a| {
                        let perm = if can_change_permissions(a.mask) {
                            Some("M")
                        } else {
                            icacls_perm(a.rights)
                        };
                        perm.map(|p| format!("{}{p}", inherit_flags(a.flags)))
                    })
                    .collect();
                g.objects.push(Obj {
                    label: path.clone(),
                    info: aces.iter().map(ace_info).collect::<Vec<_>>().join(", "),
                });
                if grants.len() < aces.len() {
                    s.line(format!("# {path}: Sonderrechte – bitte manuell übertragen"));
                    continue;
                }
                let mut action = format!("Backup-Acl {}", q(path));
                for gr in &grants {
                    action.push_str(&format!(
                        "; Invoke-Icacls {} /grant (\"{{0}}:{gr}\" -f $Group)",
                        q(path)
                    ));
                }
                action.push_str(&format!("; Remove-AceFor {} {} Allow", q(path), q(sid)));
                s.step(
                    &format!("{path}: Rechte von {name} auf die Zielgruppe übertragen"),
                    &action,
                );
            }
            g.objects_total = groups.len();
            g.script = Some(s.build());
        }

        "BROAD_WRITE" | "PERMISSION_DELEGATION" => {
            let broad = f.rule == "BROAD_WRITE";
            let aces = explicit_aces(
                c,
                sys,
                Some(sid),
                if broad { f.path.as_deref() } else { None },
                Some("allow"),
            )
            .await?;
            let groups = by_path(aces);
            if broad {
                g.steps = steps(&[
                    "Klären, wer in diesem Ordner tatsächlich schreiben muss.",
                    "Diesen Personen Schreibrechte über eine Fachgruppe geben (z. B. „DL_Abteilung_Ändern“ mit Ändern).",
                    "Skript ohne -Apply ausführen und prüfen.",
                    "Skript mit -Apply ausführen: die breite Gruppe behält nur noch Lesen & Ausführen.",
                ]);
                g.warning = Some(format!(
                    "Danach kann „{name}“ nicht mehr schreiben. Wer weiterhin schreiben muss, braucht vorher Rechte über eine Fachgruppe."
                ));
            } else {
                g.steps = steps(&[
                    "Prüfen, ob das Konto die Berechtigungen selbst verwalten muss (das ist fast nie nötig).",
                    "Skript ohne -Apply ausführen und prüfen.",
                    "Skript mit -Apply ausführen: Vollzugriff wird zu Ändern – Lesen, Schreiben und Löschen bleiben möglich.",
                ]);
            }
            let mut s = ScriptBuilder::new(f, host_target.clone());
            s.acl = true;
            for (path, aces) in groups.iter().take(MAX_OBJECTS) {
                g.objects.push(Obj {
                    label: path.clone(),
                    info: aces.iter().map(ace_info).collect::<Vec<_>>().join(", "),
                });
                // Neue Rechte je ACE (Vererbungsflags bleiben erhalten)
                let new: Option<BTreeSet<String>> = aces
                    .iter()
                    .map(|a| {
                        let perm = if broad {
                            Some("RX")
                        } else if can_change_permissions(a.mask) {
                            Some("M")
                        } else {
                            icacls_perm(a.rights)
                        };
                        perm.map(|p| format!("{}{p}", inherit_flags(a.flags)))
                    })
                    .collect();
                let Some(new) = new else {
                    s.line(format!("# {path}: Sonderrechte – bitte manuell anpassen"));
                    continue;
                };
                let mut action = format!(
                    "Backup-Acl {p}; Remove-AceFor {p} {s} Allow",
                    p = q(path),
                    s = q(sid)
                );
                for n in &new {
                    action.push_str(&format!(
                        "; Invoke-Icacls {} /grant {}",
                        q(path),
                        q(&format!("*{sid}:{n}"))
                    ));
                }
                let what = if broad {
                    "nur noch Lesen"
                } else {
                    "Ändern statt Vollzugriff"
                };
                s.step(&format!("{path}: {name} – {what}"), &action);
            }
            g.objects_total = groups.len();
            g.script = Some(s.build());
        }

        "DENY_ACE" => {
            let aces = explicit_aces(c, sys, None, None, Some("deny")).await?;
            g.steps = steps(&[
                "Für jeden Verweigern-Eintrag klären, wen er aussperren soll.",
                "Das Ziel stattdessen über Gruppen lösen: Betroffene aus der berechtigten Gruppe nehmen oder eine engere Gruppe berechtigen.",
                "Erst danach die Verweigern-Einträge mit dem Skript (-Apply) entfernen.",
            ]);
            g.warning = Some(
                "Das Entfernen eines Verweigern-Eintrags erweitert den Zugriff. Nur ausführen, wenn die Gruppenstruktur vorher angepasst wurde."
                    .into(),
            );
            let (aces, total) = truncate(aces);
            let mut s = ScriptBuilder::new(f, host_target.clone());
            s.acl = true;
            for a in &aces {
                let n = dir.view(&a.sid).name;
                g.objects.push(Obj {
                    label: a.path.clone(),
                    info: format!("{n}: {}", ace_info(a)),
                });
                s.step(
                    &format!("{}: Verweigern-Eintrag für {n} entfernen", a.path),
                    &format!(
                        "Backup-Acl {p}; Remove-AceFor {p} {s} Deny",
                        p = q(&a.path),
                        s = q(&a.sid)
                    ),
                );
            }
            g.objects_total = total;
            g.script = Some(s.build());
        }

        "DEEP_EXPLICIT" => {
            let rows = c
                .query(
                    "SELECT f.path, COUNT(*) FROM aces a
                     JOIN folders f ON f.system_id = a.system_id AND f.local_id = a.folder_local_id
                     WHERE a.system_id = $1 AND NOT a.inherited AND f.depth >= $2
                     GROUP BY f.path ORDER BY lower(f.path)",
                    &[&sys, &(cfg.deep_explicit_depth as i32)],
                )
                .await?;
            g.steps = steps(&[
                "Liste der tief liegenden Ordner mit eigenen Berechtigungen durchgehen (Prüfskript zeigt die ACLs).",
                "Für jeden Ordner entscheiden: Berechtigung auf eine höhere Ebene verlagern oder Ordner in eine passend berechtigte Struktur verschieben.",
                "Lässt sich die Struktur nicht ändern: als Ausnahme mit Begründung akzeptieren.",
            ]);
            let mut s = ScriptBuilder::new(f, host_target.clone());
            s.kind = "review";
            let total = rows.len();
            for r in rows.iter().take(MAX_OBJECTS) {
                let path: String = r.get(0);
                let n: i64 = r.get(1);
                s.line(format!(
                    "Write-Host ('=== ' + {p}) -ForegroundColor Cyan; icacls.exe {p}",
                    p = q(&path)
                ));
                g.objects.push(Obj {
                    label: path,
                    info: format!("{n} explizite Einträge"),
                });
            }
            g.objects_total = total;
            g.script = Some(s.build());
        }

        "INHERITANCE_BROKEN" => {
            let rows = c
                .query(
                    "SELECT path FROM folders WHERE system_id = $1 AND protected AND NOT is_root ORDER BY lower(path)",
                    &[&sys],
                )
                .await?;
            g.steps = steps(&[
                "Für jeden Ordner prüfen, ob die Unterbrechung gewollt ist (z. B. vertrauliche Bereiche).",
                "Gewollte Unterbrechungen dokumentieren und den Befund als Ausnahme akzeptieren.",
                "Nicht nötige Unterbrechungen mit dem Skript aufheben – entweder für einzelne Ordner (Zeilen löschen) oder alle mit -Apply.",
                "Nach dem Aktivieren bleiben die bisher kopierten Einträge erhalten; doppelte Einträge können danach entfernt werden.",
            ]);
            g.warning = Some(
                "Beim Aktivieren der Vererbung kommen die Rechte des übergeordneten Ordners hinzu – der Zugriff kann sich dadurch erweitern."
                    .into(),
            );
            let mut s = ScriptBuilder::new(f, host_target.clone());
            s.acl = true;
            let total = rows.len();
            for r in rows.iter().take(MAX_OBJECTS) {
                let path: String = r.get(0);
                s.step(
                    &format!("{path}: Vererbung aktivieren"),
                    &format!(
                        "Backup-Acl {p}; Invoke-Icacls {p} /inheritance:e",
                        p = q(&path)
                    ),
                );
                g.objects.push(Obj {
                    label: path,
                    info: "Vererbung unterbrochen".into(),
                });
            }
            g.objects_total = total;
            g.script = Some(s.build());
        }

        "ORPHANED_OWNER" => {
            let owners: Vec<String> = c
                .query(
                    "SELECT DISTINCT owner_sid FROM folders WHERE system_id = $1 AND owner_sid IS NOT NULL",
                    &[&sys],
                )
                .await?
                .iter()
                .map(|r| r.get::<_, String>(0))
                .filter(|o| dir.is_orphaned(o))
                .collect();
            let rows = c
                .query(
                    "SELECT path, owner_sid FROM folders WHERE system_id = $1 AND owner_sid = ANY($2) ORDER BY lower(path)",
                    &[&sys, &owners],
                )
                .await?;
            g.steps = steps(&[
                "Skript ohne -Apply ausführen und die Liste prüfen.",
                "Skript mit -Apply ausführen: Besitzer wird die lokale Gruppe Administratoren (nur der Ordner selbst, keine Unterordner).",
            ]);
            let mut s = ScriptBuilder::new(f, host_target.clone());
            s.acl = true;
            let total = rows.len();
            for r in rows.iter().take(MAX_OBJECTS) {
                let path: String = r.get(0);
                let owner: String = r.get(1);
                s.step(
                    &format!("{path}: Besitzer auf Administratoren setzen"),
                    &format!(
                        "Backup-Acl {p}; Invoke-Icacls {p} /setowner {a}",
                        p = q(&path),
                        a = q(&format!("*{}", wellknown::BUILTIN_ADMINISTRATORS))
                    ),
                );
                g.objects.push(Obj {
                    label: path,
                    info: format!("Besitzer {owner}"),
                });
            }
            g.objects_total = total;
            g.script = Some(s.build());
        }

        "SCAN_ERRORS" => {
            let rows = c
                .query(
                    "SELECT path, error FROM folders WHERE system_id = $1 AND error IS NOT NULL ORDER BY lower(path)",
                    &[&sys],
                )
                .await?;
            g.steps = steps(&[
                "Sicherstellen, dass der Client als Dienst bzw. geplante Aufgabe unter SYSTEM läuft oder in einer Administrator-Konsole gestartet wird (SeBackupPrivilege).",
                "Prüfskript auf dem Server ausführen: es zeigt, welche Ordner für das aktuelle Konto lesbar sind.",
                "Bleiben Ordner unlesbar (z. B. gesperrte Dateisysteme, getrennte Netzlaufwerke): Ursache beheben oder Ordner in der Client-Konfiguration ausschließen ([scan] exclude).",
                "Danach erneut scannen.",
            ]);
            let mut s = ScriptBuilder::new(f, host_target.clone());
            s.kind = "review";
            let total = rows.len();
            for r in rows.iter().take(MAX_OBJECTS) {
                let path: String = r.get(0);
                let err: String = r.get(1);
                s.line(format!(
                    "try {{ $null = Get-Acl -LiteralPath {p}; Write-Host ('OK      ' + {p}) -ForegroundColor Green }} catch {{ Write-Host ('FEHLER  ' + {p} + ': ' + $_.Exception.Message) -ForegroundColor Red }}",
                    p = q(&path)
                ));
                g.objects.push(Obj {
                    label: path,
                    info: err,
                });
            }
            g.objects_total = total;
            g.script = Some(s.build());
        }

        "SHARE_OPEN" => {
            let shares: Vec<String> = c
                .query(
                    "SELECT name FROM shares WHERE system_id = $1 AND path = $2 AND NOT is_special ORDER BY name",
                    &[&sys, &f.path],
                )
                .await?
                .iter()
                .map(|r| r.get(0))
                .collect();
            g.steps = steps(&[
                "Sicherstellen, dass die NTFS-Berechtigungen des freigegebenen Ordners den Zugriff sauber regeln (Befunde dieses Ordners zuerst beheben).",
                "Skript ohne -Apply ausführen und prüfen.",
                "Skript mit -Apply ausführen: Administratoren – Vollzugriff, Authentifizierte Benutzer – Ändern, die breite Freigabeberechtigung wird entfernt.",
            ]);
            g.warning = Some(
                "Anonyme bzw. nicht angemeldete Zugriffe auf die Freigabe sind danach nicht mehr möglich.".into(),
            );
            let mut s = ScriptBuilder::new(f, host_target.clone());
            s.line("$ErrorActionPreference = 'Continue'");
            s.line("function Get-AccountName([string] $Sid) { ([Security.Principal.SecurityIdentifier] $Sid).Translate([Security.Principal.NTAccount]).Value }");
            s.line("$backup = Join-Path $env:ProgramData \"PermissionCenter\\acl-backup\\$stamp-SHARE_OPEN.csv\"");
            s.line("");
            for share in &shares {
                let sn = q(share);
                s.step(
                    &format!("Freigabe {share}: Freigabeberechtigungen sichern"),
                    &format!("New-Item -ItemType Directory -Force (Split-Path $backup) | Out-Null; Get-SmbShareAccess -Name {sn} | Export-Csv $backup -Append -NoTypeInformation -Encoding UTF8"),
                );
                s.step(
                    &format!("Freigabe {share}: Administratoren – Vollzugriff"),
                    &format!(
                        "Grant-SmbShareAccess -Name {sn} -AccountName (Get-AccountName {}) -AccessRight Full -Force | Out-Null",
                        q(wellknown::BUILTIN_ADMINISTRATORS)
                    ),
                );
                s.step(
                    &format!("Freigabe {share}: {name} entfernen"),
                    &format!(
                        "Revoke-SmbShareAccess -Name {sn} -AccountName (Get-AccountName {}) -Force | Out-Null",
                        q(sid)
                    ),
                );
                s.step(
                    &format!("Freigabe {share}: Authentifizierte Benutzer – Ändern"),
                    &format!(
                        "Grant-SmbShareAccess -Name {sn} -AccountName (Get-AccountName {}) -AccessRight Change -Force | Out-Null",
                        q(wellknown::AUTHENTICATED_USERS)
                    ),
                );
                g.objects.push(Obj {
                    label: format!("\\\\{host}\\{share}"),
                    info: f.path.clone().unwrap_or_default(),
                });
            }
            s.line("if ($Apply) { Write-Host \"Sicherung der vorherigen Freigabeberechtigungen: $backup\" }");
            g.objects_total = shares.len();
            g.script = Some(s.build());
        }

        "STALE_SYSTEM" => {
            g.steps = steps(&[
                "Auf dem Server prüfen, ob der Client installiert ist und der Dienst bzw. die geplante Aufgabe läuft (das Skript zeigt den Status).",
                "Logdatei auf Fehler prüfen, z. B. Server nicht erreichbar oder Token abgelehnt.",
                "Skript mit -Apply ausführen: startet sofort einen Scan mit Upload.",
                "Wird das System nicht mehr betrieben: unter Systeme löschen.",
            ]);
            let mut s = ScriptBuilder::new(f, host_target.clone());
            s.line("$ErrorActionPreference = 'Continue'");
            s.line("$exe = Join-Path $env:ProgramFiles 'PermissionCenter\\pc-client.exe'");
            s.line("$config = Join-Path $env:ProgramData 'PermissionCenter\\pc-client.toml'");
            s.line("if (-not (Test-Path $exe)) { Write-Warning \"pc-client.exe nicht gefunden: $exe - Client mit Install-PcClient.ps1 installieren\"; return }");
            s.line("Get-Service PermissionCenterClient -ErrorAction SilentlyContinue | Format-Table Name, Status, StartType -AutoSize");
            s.line("Get-ScheduledTask -TaskName PermissionCenter-Scan -ErrorAction SilentlyContinue | Get-ScheduledTaskInfo | Format-List LastRunTime, LastTaskResult, NextRunTime");
            s.line("& $exe --config $config status");
            s.line("& $exe --config $config logs --errors --lines 30");
            s.step(
                "Scan jetzt ausführen und hochladen",
                "& $exe --config $config scan",
            );
            g.objects.push(Obj {
                label: host.clone(),
                info: "Letzter Scan zu alt".into(),
            });
            g.objects_total = 1;
            g.script = Some(s.build());
        }

        "AD_EMPTY_GROUP" | "AD_UNUSED_GROUP" | "AD_ORPHANED_GROUP" => {
            let usage = c
                .query(
                    "SELECT y.hostname, f.path, a.rights FROM aces a
                     JOIN folders f ON f.system_id = a.system_id AND f.local_id = a.folder_local_id
                     JOIN systems y ON y.id = a.system_id
                     WHERE a.sid = $1 AND NOT a.inherited
                     UNION ALL
                     SELECT y.hostname, '\\\\' || y.hostname || '\\' || s.name, x.rights FROM share_aces x
                     JOIN shares s ON s.id = x.share_id JOIN systems y ON y.id = s.system_id
                     WHERE x.sid = $1
                     ORDER BY 1, 2",
                    &[&sid],
                )
                .await?;
            g.steps = match f.rule.as_str() {
                "AD_ORPHANED_GROUP" => steps(&[
                    "Klären, ob die Gruppe noch gebraucht wird (Beschreibung, Verantwortliche, Fachabteilung).",
                    "Wird sie gebraucht: aktuelle Mitglieder aufnehmen und den Befund damit beheben.",
                    "Wird sie nicht gebraucht: zuerst ihre Berechtigungen (Liste unten) entfernen, dann die Gruppe mit dem Skript löschen.",
                ]),
                "AD_UNUSED_GROUP" => steps(&[
                    "Prüfen, ob die Gruppe außerhalb der Dateiberechtigungen genutzt wird: GPOs, Anwendungen, Exchange/Teams, Druck, VPN, Fremdsysteme.",
                    "Wird sie genutzt: als Ausnahme mit Begründung akzeptieren.",
                    "Wird sie nicht genutzt: Skript ohne -Apply prüfen, dann mit -Apply löschen (Sicherung als XML wird angelegt).",
                ]),
                _ => steps(&[
                    "Prüfen, ob die Gruppe als Vorlage oder für künftige Mitglieder vorgesehen ist.",
                    "Ist sie in Berechtigungen eingetragen (Liste unten), diese zuerst entfernen – sonst entstehen verwaiste Einträge.",
                    "Skript ohne -Apply prüfen, dann mit -Apply löschen (Sicherung als XML wird angelegt).",
                ]),
            };
            if !usage.is_empty() {
                g.warning = Some(format!(
                    "Die Gruppe ist noch in {} Berechtigungen eingetragen. Nach dem Löschen würden diese als verwaiste SIDs zurückbleiben – vorher entfernen.",
                    usage.len()
                ));
            }
            let mut s = ScriptBuilder::new(f, ad_target.clone());
            s.ad = true;
            s.step(
                &format!("Gruppe {name} sichern und löschen"),
                &format!(
                    "Backup-AdGroup {s}; Remove-ADGroup -Identity {s} -Confirm:$false",
                    s = q(sid)
                ),
            );
            s.line("# Löschschutz verhindert das Löschen? Erst aufheben:");
            s.line(format!(
                "#   Set-ADObject -Identity (Get-ADGroup -Identity {}).DistinguishedName -ProtectedFromAccidentalDeletion $false",
                q(sid)
            ));
            g.objects.push(Obj {
                label: name.clone(),
                info: dir
                    .groups
                    .get(sid)
                    .and_then(|x| x.description.clone())
                    .unwrap_or_else(|| "Gruppe".into()),
            });
            if f.rule == "AD_ORPHANED_GROUP" {
                for u in dir.transitive_user_members(sid).iter().take(MAX_OBJECTS) {
                    g.objects.push(Obj {
                        label: dir.view(u).name,
                        info: "Mitglied (deaktiviert)".into(),
                    });
                }
            }
            for r in usage.iter().take(MAX_OBJECTS) {
                let (h, p, rights): (String, String, String) = (r.get(0), r.get(1), r.get(2));
                g.objects.push(Obj {
                    label: format!("{h}: {p}"),
                    info: format!("Berechtigung: {}", Rights::parse(&rights).label_de()),
                });
            }
            g.objects_total = g.objects.len();
            g.script = Some(s.build());
        }

        "AD_INACTIVE_USER" => {
            g.steps = steps(&[
                "Mit Fachabteilung bzw. Personalabteilung klären, ob das Konto noch gebraucht wird (z. B. Elternzeit, Dienstkonto).",
                "Wird es nicht gebraucht: Skript mit -Apply ausführen – das Konto wird deaktiviert (rückgängig mit Enable-ADAccount).",
                "Nach einer Karenzzeit (z. B. 90 Tage) Konto löschen und Berechtigungen bereinigen.",
                "Dienstkonten ohne interaktive Anmeldung als Ausnahme mit Begründung akzeptieren.",
            ]);
            let mut s = ScriptBuilder::new(f, ad_target.clone());
            s.ad = true;
            s.step(
                &format!("Konto {name} deaktivieren"),
                &format!("Disable-ADAccount -Identity {}", q(sid)),
            );
            let info = dir
                .users
                .get(sid)
                .map(|u| match u.last_logon {
                    Some(t) => format!("Letzte Anmeldung {}", t.format("%d.%m.%Y")),
                    None => "Nie angemeldet".into(),
                })
                .unwrap_or_default();
            g.objects.push(Obj {
                label: name.clone(),
                info,
            });
            g.objects_total = 1;
            g.script = Some(s.build());
        }

        "AD_DISABLED_IN_GROUPS" => {
            let mut pairs: Vec<(String, String)> = Vec::new();
            let mut users: Vec<_> = dir
                .users
                .iter()
                .filter(|(s, u)| !u.enabled && !u.is_computer && rid(s).is_some_and(|r| r >= 1000))
                .collect();
            users.sort_by(|a, b| a.1.sam.cmp(&b.1.sam));
            for (usid, _) in users {
                for gsid in dir.member_of.get(usid).into_iter().flatten() {
                    if dir.groups.contains_key(gsid) && rid(gsid).is_some_and(|r| r >= 1000) {
                        pairs.push((usid.clone(), gsid.clone()));
                    }
                }
            }
            g.steps = steps(&[
                "Skript ohne -Apply ausführen und die Liste prüfen.",
                "Skript mit -Apply ausführen: deaktivierte Konten werden aus den Gruppen entfernt (Liste der Mitgliedschaften wird gesichert).",
                "Austrittsprozess ergänzen, damit Gruppenmitgliedschaften beim Deaktivieren entfernt werden.",
            ]);
            let (pairs, total) = truncate(pairs);
            let mut s = ScriptBuilder::new(f, ad_target.clone());
            s.ad = true;
            s.line("if ($Apply) {");
            s.line("@'");
            s.line("Gruppe;GruppenSID;Benutzer;BenutzerSID");
            for (u, gr) in &pairs {
                s.line(format!(
                    "{};{gr};{};{u}",
                    dir.view(gr).name,
                    dir.view(u).name
                ));
            }
            s.line("'@ | Set-Content (Join-Path $backupDir 'Mitgliedschaften.csv') -Encoding UTF8");
            s.line("}");
            for (u, gr) in &pairs {
                let (un, gn) = (dir.view(u).name, dir.view(gr).name);
                s.step(
                    &format!("{gn}: {un} entfernen"),
                    &format!(
                        "Remove-ADGroupMember -Identity {} -Members {} -Confirm:$false",
                        q(gr),
                        q(u)
                    ),
                );
                g.objects.push(Obj {
                    label: un,
                    info: format!("Mitglied von {gn}"),
                });
            }
            g.objects_total = total;
            g.script = Some(s.build());
        }

        "AD_PRIVILEGED_STALE" => {
            let privileged = crate::analysis::privileged_groups(&dir);
            // Direkte Gruppen, über die das Konto in eine privilegierte Gruppe gelangt
            let mut direct: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for (g, path) in dir.transitive_groups(sid) {
                if privileged.contains(&g) {
                    if let Some(first) = path.first() {
                        direct
                            .entry(first.clone())
                            .or_default()
                            .push(dir.view(&g).name);
                    }
                }
            }
            g.steps = steps(&[
                "Klären, ob das Konto noch gebraucht wird – meist ist es ein ausgeschiedener Admin oder ein altes Dienstkonto.",
                "Skript ohne -Apply prüfen: es entfernt das Konto aus den Gruppen, über die es administrative Rechte erhält.",
                "Skript mit -Apply ausführen (die Mitgliedschaften werden vorher gesichert).",
                "Wird das Konto gar nicht mehr gebraucht: zusätzlich deaktivieren bzw. löschen.",
            ]);
            if direct.keys().any(|d| !privileged.contains(d)) {
                g.warning = Some(
                    "Das Konto ist über eine Zwischengruppe privilegiert. Beim Entfernen aus dieser Gruppe verliert es auch deren übrige Rechte."
                        .into(),
                );
            }
            let mut s = ScriptBuilder::new(f, ad_target.clone());
            s.ad = true;
            for (d, via) in &direct {
                let dn = dir.view(d).name;
                s.step(
                    &format!("{name} aus {dn} entfernen"),
                    &format!(
                        "Backup-AdGroup {d}; Remove-ADGroupMember -Identity {d} -Members {u} -Confirm:$false",
                        d = q(d),
                        u = q(sid)
                    ),
                );
                g.objects.push(Obj {
                    label: dn,
                    info: format!("führt zu: {}", via.join(", ")),
                });
            }
            g.objects_total = g.objects.len();
            g.script = Some(s.build());
        }

        "AD_PRIVILEGED_MANY" => {
            let members: Vec<String> = dir
                .transitive_user_members(sid)
                .into_iter()
                .filter(|u| dir.users.get(u).is_some_and(|x| !x.is_computer))
                .collect();
            g.steps = steps(&[
                "Mitgliederliste mit den Verantwortlichen durchgehen: Wer braucht diese Rechte wirklich dauerhaft?",
                "Für Admin-Aufgaben persönliche, getrennte Admin-Konten verwenden – nicht das Alltagskonto.",
                "Aufgaben wie Kennwort zurücksetzen oder Computer aufnehmen über delegierte Rechte lösen, nicht über Domänen-Admins.",
                "Nicht mehr benötigte Mitglieder entfernen (Remove-ADGroupMember) und Befund erledigen.",
            ]);
            let mut s = ScriptBuilder::new(f, ad_target.clone());
            s.kind = "review";
            s.line(format!(
                "Get-ADGroupMember -Identity {} -Recursive | Where-Object objectClass -eq 'user' |\n    Get-ADUser -Properties LastLogonDate, PasswordLastSet, Enabled |\n    Sort-Object LastLogonDate | Format-Table SamAccountName, Enabled, LastLogonDate, PasswordLastSet -AutoSize",
                q(sid)
            ));
            for u in members.iter().take(MAX_OBJECTS) {
                let info = dir
                    .users
                    .get(u)
                    .map(|x| {
                        let state = if !x.enabled {
                            "deaktiviert"
                        } else if dir.is_inactive(x) {
                            "inaktiv"
                        } else {
                            "aktiv"
                        };
                        match x.last_logon {
                            Some(t) => {
                                format!("{state}, letzte Anmeldung {}", t.format("%d.%m.%Y"))
                            }
                            None => format!("{state}, nie angemeldet"),
                        }
                    })
                    .unwrap_or_default();
                g.objects.push(Obj {
                    label: dir.view(u).name,
                    info,
                });
            }
            g.objects_total = members.len();
            g.script = Some(s.build());
        }

        "AD_KERBEROASTABLE" => {
            let spns = dir
                .users
                .get(sid)
                .map(|u| u.spns.clone())
                .unwrap_or_default();
            g.steps = steps(&[
                "Herausfinden, welcher Dienst das Konto nutzt (SPNs unten, z. B. MSSQLSvc/… für SQL Server).",
                "Am besten: Dienst auf ein gruppenverwaltetes Dienstkonto (gMSA) umstellen – das Kennwort wechselt dann automatisch und ist 120 Zeichen lang.",
                "Falls nicht möglich: Kennwort mit mindestens 25 zufälligen Zeichen setzen und nur AES erlauben (Konto-Option „Dieses Konto unterstützt Kerberos AES 256“).",
                "Wird ein SPN nicht mehr gebraucht: entfernen (Befehl im Skript als Kommentar).",
                "Danach als erledigt markieren oder – bei gMSA-Umstellung später – als Ausnahme mit Begründung dokumentieren.",
            ]);
            g.warning = Some("SPNs nicht ohne Rücksprache entfernen – der zugehörige Dienst funktioniert sonst nicht mehr.".into());
            let mut s = ScriptBuilder::new(f, ad_target.clone());
            s.kind = "review";
            s.line(format!(
                "Get-ADUser -Identity {} -Properties ServicePrincipalNames, PasswordLastSet, 'msDS-SupportedEncryptionTypes', MemberOf |\n    Format-List SamAccountName, Enabled, PasswordLastSet, ServicePrincipalNames, msDS-SupportedEncryptionTypes, MemberOf",
                q(sid)
            ));
            s.line("# Nur AES erlauben (0x18 = AES128 + AES256):");
            s.line(format!(
                "#   Set-ADUser -Identity {} -Replace @{{'msDS-SupportedEncryptionTypes' = 24}}",
                q(sid)
            ));
            for spn in &spns {
                s.line(format!(
                    "# SPN entfernen:  Set-ADUser -Identity {} -ServicePrincipalNames @{{Remove = {}}}",
                    q(sid),
                    q(spn)
                ));
                g.objects.push(Obj {
                    label: spn.clone(),
                    info: "SPN".into(),
                });
            }
            g.objects_total = spns.len();
            g.script = Some(s.build());
        }

        "AD_PWD_NEVER_EXPIRES" | "AD_OLD_PASSWORD" => {
            let never = f.rule == "AD_PWD_NEVER_EXPIRES";
            g.steps = if never {
                steps(&[
                    "Prüfen, ob es ein Dienstkonto ist (Name, Beschreibung, SPNs). Dienstkonten möglichst auf gMSA umstellen.",
                    "Für persönliche Konten: Skript mit -Apply ausführen – das Kennwort unterliegt dann wieder der Kennwortrichtlinie.",
                    "Ist das Kennwort älter als die maximale Gültigkeit, muss es bei der nächsten Anmeldung geändert werden – den Benutzer vorher informieren.",
                    "Dienstkonten, die vorerst so bleiben müssen: als Ausnahme mit Begründung akzeptieren (langes Kennwort dokumentieren).",
                ])
            } else {
                steps(&[
                    "Klären, ob das Konto noch genutzt wird. Ungenutzte Konten besser deaktivieren.",
                    "Skript mit -Apply ausführen: der Benutzer muss das Kennwort bei der nächsten Anmeldung ändern.",
                    "Benutzer vorher informieren. Dienstkonten nicht so behandeln – deren Dienste würden ausfallen.",
                ])
            };
            g.warning = Some(
                "Bei Dienstkonten fällt der Dienst aus, sobald das Kennwort abläuft bzw. geändert werden muss. Nur für persönliche Konten anwenden."
                    .into(),
            );
            let mut s = ScriptBuilder::new(f, ad_target.clone());
            s.ad = true;
            if never {
                s.step(
                    &format!("{name}: „Kennwort läuft nie ab“ entfernen"),
                    &format!(
                        "Set-ADUser -Identity {} -PasswordNeverExpires $false",
                        q(sid)
                    ),
                );
            } else {
                s.step(
                    &format!("{name}: Kennwortänderung bei nächster Anmeldung erzwingen"),
                    &format!(
                        "Set-ADUser -Identity {} -ChangePasswordAtLogon $true",
                        q(sid)
                    ),
                );
            }
            let info = dir
                .users
                .get(sid)
                .map(|u| match u.pwd_last_set {
                    Some(t) => format!("Kennwort gesetzt {}", t.format("%d.%m.%Y")),
                    None => "Kennwort nie gesetzt".into(),
                })
                .unwrap_or_default();
            g.objects.push(Obj {
                label: name.clone(),
                info,
            });
            g.objects_total = 1;
            g.script = Some(s.build());
        }

        "AD_STALE_COMPUTER" => {
            let mut computers: Vec<(&String, &crate::directory::AdUserRow)> = dir
                .users
                .iter()
                .filter(|(_, u)| u.is_computer && u.enabled && dir.is_inactive(u))
                .collect();
            computers.sort_by(|a, b| a.1.sam.cmp(&b.1.sam));
            g.steps = steps(&[
                "Liste prüfen: Sind die Geräte wirklich ausgemustert? (Server in Wartung, Notebooks in Elternzeit …)",
                "Skript mit -Apply ausführen: die Konten werden deaktiviert und mit Datum beschrieben – nicht gelöscht.",
                "Nach einer Karenzzeit (z. B. 90 Tage) deaktivierte Konten löschen.",
            ]);
            let mut s = ScriptBuilder::new(f, ad_target.clone());
            s.ad = true;
            s.line("$note = 'Deaktiviert ' + (Get-Date -Format 'dd.MM.yyyy') + ' (PermissionCenter: inaktiv)'");
            let total = computers.len();
            for (csid, u) in computers.into_iter().take(MAX_OBJECTS) {
                let host = u.sam.trim_end_matches('$');
                s.step(
                    &format!("Computerkonto {host} deaktivieren"),
                    &format!(
                        "Disable-ADAccount -Identity {c}; Set-ADComputer -Identity {c} -Description $note",
                        c = q(csid)
                    ),
                );
                g.objects.push(Obj {
                    label: host.to_string(),
                    info: match u.last_logon {
                        Some(t) => format!("letzte Anmeldung {}", t.format("%d.%m.%Y")),
                        None => "nie angemeldet".into(),
                    },
                });
            }
            g.objects_total = total;
            g.script = Some(s.build());
        }

        "LOCAL_ADMIN_BROAD" | "LOCAL_ADMIN_ORPHANED" | "LOCAL_ADMIN_USER" => {
            g.steps = match f.rule.as_str() {
                "LOCAL_ADMIN_BROAD" => steps(&[
                    "Sofort handeln: Jeder Anwender kann den Server derzeit vollständig übernehmen.",
                    "Prüfen, wer tatsächlich administrieren muss, und dafür eine Domänengruppe (z. B. „GG_Server_Admins“) in die lokale Gruppe aufnehmen.",
                    "Skript mit -Apply ausführen: die breite Gruppe wird aus den lokalen Administratoren entfernt.",
                ]),
                "LOCAL_ADMIN_ORPHANED" => steps(&[
                    "Skript ohne -Apply prüfen.",
                    "Skript mit -Apply ausführen: der verwaiste Eintrag wird aus den lokalen Administratoren entfernt.",
                ]),
                _ => steps(&[
                    "Klären, ob das Konto weiterhin Administrator sein muss.",
                    "Wenn ja: über eine Domänengruppe berechtigen (Gruppe in die lokalen Administratoren aufnehmen, Benutzer in die Gruppe).",
                    "Skript mit -Apply ausführen: der Direkteintrag wird entfernt. Neue Gruppenmitgliedschaft wirkt nach Neuanmeldung.",
                ]),
            };
            if f.rule != "LOCAL_ADMIN_ORPHANED" {
                g.warning = Some(
                    "Nicht das eigene Konto oder die einzige Admin-Gruppe entfernen – sonst ist der Server nicht mehr administrierbar."
                        .into(),
                );
            }
            let mut s = ScriptBuilder::new(f, host_target.clone());
            s.line("# Lokale Gruppe Administratoren (Name in Landessprache)");
            s.line("$group = ([Security.Principal.SecurityIdentifier] 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\\')[1]");
            s.line("$backup = Join-Path $env:ProgramData \"PermissionCenter\\acl-backup\\$stamp-lokale-admins.txt\"");
            s.step(
                "Mitgliederliste der lokalen Administratoren sichern",
                "New-Item -ItemType Directory -Force (Split-Path $backup) | Out-Null; net localgroup $group | Out-File $backup -Encoding UTF8",
            );
            s.step(
                &format!("{name} aus den lokalen Administratoren entfernen"),
                &format!(
                    "([ADSI] \"WinNT://$env:COMPUTERNAME/$group,group\").Remove({})",
                    q(&format!("WinNT://{sid}"))
                ),
            );
            s.line("if ($Apply) { Write-Host \"Sicherung: $backup\"; net localgroup $group }");
            g.objects.push(Obj {
                label: name.clone(),
                info: format!("Mitglied der lokalen Administratoren auf {host}"),
            });
            g.objects_total = 1;
            g.script = Some(s.build());
        }

        "FILE_EXPLICIT" => {
            let rows = c
                .query(
                    "SELECT f.path, f.protected, COUNT(a.sid) FILTER (WHERE NOT a.inherited)
                     FROM files f LEFT JOIN file_aces a ON a.system_id = f.system_id AND a.file_id = f.file_id
                     WHERE f.system_id = $1 GROUP BY f.path, f.protected ORDER BY lower(f.path)",
                    &[&sys],
                )
                .await?;
            g.steps = steps(&[
                "Liste prüfen: Sind die abweichenden Dateirechte gewollt (z. B. vertrauliche Einzeldokumente)?",
                "Gewollte Ausnahmen besser in einen eigenen Ordner mit passenden Rechten verschieben.",
                "Skript mit -Apply ausführen: die Dateien erhalten wieder nur die Rechte ihres Ordners (icacls /reset).",
            ]);
            g.warning = Some(
                "Nach dem Zurücksetzen gelten für die Dateien die Ordnerrechte – Personen mit Zugriff auf den Ordner sehen dann auch diese Dateien."
                    .into(),
            );
            let mut s = ScriptBuilder::new(f, host_target.clone());
            s.acl = true;
            let total = rows.len();
            for r in rows.iter().take(MAX_OBJECTS) {
                let (path, protected, explicit): (String, bool, i64) =
                    (r.get(0), r.get(1), r.get(2));
                s.step(
                    &format!("{path}: auf Vererbung zurücksetzen"),
                    &format!("Backup-Acl {p}; Invoke-Icacls {p} /reset", p = q(&path)),
                );
                g.objects.push(Obj {
                    label: path,
                    info: match (protected, explicit) {
                        (true, n) => format!("Vererbung unterbrochen, {n} eigene Einträge"),
                        (false, n) => format!("{n} eigene Einträge"),
                    },
                });
            }
            g.objects_total = total;
            g.script = Some(s.build());
        }

        _ => {
            g.steps = steps(&["Für diesen Befund gibt es keine Schritt-für-Schritt-Anleitung."]);
        }
    }
    Ok(g)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_and_flags() {
        assert_eq!(q(r"D:\Daten\O'Brien"), r"'D:\Daten\O''Brien'");
        assert_eq!(inherit_flags(0x3), "(OI)(CI)");
        assert_eq!(inherit_flags(0x0b), "(OI)(CI)(IO)");
        assert_eq!(icacls_perm(Rights::Modify), Some("M"));
        assert_eq!(icacls_perm(Rights::Special), None);
    }

    #[test]
    fn script_layout() {
        let f = FindingRef {
            system_id: Some(1),
            hostname: Some("FS01".into()),
            rule: "ORPHANED_SID".into(),
            title: "Test".into(),
            path: None,
            sid: None,
        };
        let mut s = ScriptBuilder::new(&f, "FS01".into());
        s.acl = true;
        s.step("x", "Backup-Acl 'D:\\x'");
        let out = s.build();
        assert_eq!(out.file_name, "pc-fix-orphaned-sid.ps1");
        assert!(out.body.contains("param(\r\n    [switch] $Apply\r\n)"));
        assert!(out.body.contains("Invoke-Step 'x' { Backup-Acl 'D:\\x' }"));
        assert!(out.body.contains("ORPHANED_SID.txt"));
        assert!(!out.body.contains("{RULE}"));
    }
}
