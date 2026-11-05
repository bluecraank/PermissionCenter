//! Typische Schwachstellen: wertet den Katalog aus `pc_common::weakness` gegen die
//! Registry-Werte der Clients, die GPO-Einstellungen und die AD-Daten aus.
//!
//! Eine GPO belegt nur, was sie setzt: Fehlt eine Einstellung, sagt das nichts über den
//! tatsächlichen Wert. Verlässlich sind die Werte, die der Client je System meldet.

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

use anyhow::Result;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use tokio_postgres::GenericClient;

use crate::analysis::{Rule, Severity};
use crate::api::{ApiResult, AppState};
use crate::db;
use crate::directory::Directory;
use pc_common::sid::rid;
use pc_common::weakness::{
    default_value, for_rule, value_label, AdCheck, GpoCheck, RegCheck, Weakness, CATALOG,
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/weaknesses", get(overview))
        .with_state(state)
}

const KRBTGT_MAX_AGE_DAYS: i64 = 180;

/// Regeln für alle Einträge, die eigene Befunde erzeugen.
static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    CATALOG
        .iter()
        .filter(|w| w.rules.is_empty() && !w.manual)
        .map(|w| Rule {
            id: w.id,
            severity: Severity::parse(w.severity),
            scope: "system",
            title: w.title,
            description: w.why,
            recommendation: w.fix,
        })
        .collect()
});

pub fn rule(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

pub fn rules() -> &'static [Rule] {
    &RULES
}

/// Ein Treffer je Eintrag und System (oder je Eintrag für GPO und AD).
pub struct Hit {
    pub rule: &'static str,
    pub system_id: Option<i64>,
    pub title: String,
    /// Belege, je Zeile eine Quelle.
    pub evidence: Vec<String>,
    pub affected: i64,
}

fn hklm(key: &str, value: &str) -> String {
    format!(r"HKLM\{key}\{value}")
}

fn describe(c: &RegCheck, value: &str) -> String {
    match value_label(c, value) {
        Some(l) => format!("{value} ({l})"),
        None => value.to_string(),
    }
}

/// Wertet die gemeldeten Registry-Werte eines Systems aus.
pub fn eval_registry(
    w: &Weakness,
    values: &HashMap<(String, String), String>,
    is_dc: bool,
    os_build: Option<u32>,
) -> Vec<String> {
    let get = |k: &str, v: &str| values.get(&(k.to_lowercase(), v.to_lowercase()));
    let mut out = Vec::new();
    for c in w.reg {
        if c.dc_only && !is_dc {
            continue;
        }
        let policy = c.policy_key.and_then(|p| get(p, c.value).map(|x| (p, x)));
        let (shown, value, source) = if let Some((p, x)) = policy {
            (hklm(p, c.value), x.clone(), "per Richtlinie gesetzt")
        } else if let Some(x) = get(c.key, c.value) {
            (hklm(c.key, c.value), x.clone(), "gesetzt")
        } else if let Some(d) = default_value(c, os_build) {
            (
                hklm(c.key, c.value),
                d.to_string(),
                "nicht gesetzt, Standardwert von Windows",
            )
        } else {
            continue;
        };
        if c.test.matches(&value) {
            out.push(format!("{shown} = {} ({source})", describe(c, &value)));
        }
    }
    out
}

/// `KeyName`, Wert usw. aus der Detailzeile einer GPO-Einstellung.
fn detail_field<'a>(detail: &'a str, field: &str) -> Option<&'a str> {
    detail.split(" | ").find_map(|p| {
        let (k, v) = p.split_once(": ")?;
        (k == field).then_some(v.trim())
    })
}

fn setting_value(detail: &str) -> Option<String> {
    if let Some(v) = detail_field(detail, "SettingNumber") {
        return Some(v.to_string());
    }
    if let Some(v) = detail_field(detail, "SettingBoolean") {
        return Some(
            if v.eq_ignore_ascii_case("true") {
                "1"
            } else {
                "0"
            }
            .to_string(),
        );
    }
    detail_field(detail, "SettingString").map(str::to_string)
}

/// Registry-Pfad ohne Struktur-Präfix, in Kleinbuchstaben.
fn norm_key(k: &str) -> String {
    let k = k.trim().to_lowercase();
    for p in ["hkey_local_machine\\", "hklm\\", "machine\\"] {
        if let Some(r) = k.strip_prefix(p) {
            return r.to_string();
        }
    }
    k
}

/// Passt eine GPO-Einstellung zu einem Muster? Liefert Eintrag und lesbaren Beleg.
pub fn match_gpo_setting(name: &str, detail: &str) -> Option<(&'static Weakness, String)> {
    let key = detail_field(detail, "KeyName").map(norm_key);
    let value = setting_value(detail);
    let own = detail_field(detail, "Name").unwrap_or("");
    for w in CATALOG {
        if let (Some(k), Some(v)) = (&key, &value) {
            for c in w.reg {
                let full = format!("{}\\{}", c.key, c.value).to_lowercase();
                let policy = c
                    .policy_key
                    .map(|p| format!("{p}\\{}", c.value).to_lowercase());
                if (*k == full || Some(k) == policy.as_ref()) && c.test.matches(v) {
                    return Some((w, format!("{} = {}", c.value, describe(c, v))));
                }
            }
        }
        for g in w.gpo {
            match g {
                GpoCheck::Account(n, test) => {
                    if own.eq_ignore_ascii_case(n) {
                        if let Some(v) = value.as_deref().filter(|v| test.matches(v)) {
                            return Some((w, format!("{n} = {v}")));
                        }
                    }
                }
                GpoCheck::Policy(names, state) => {
                    let last = name.rsplit(" › ").next().unwrap_or(name);
                    let hit = names
                        .iter()
                        .any(|x| x.eq_ignore_ascii_case(own) || x.eq_ignore_ascii_case(last));
                    if hit
                        && detail_field(detail, "State")
                            .is_some_and(|s| s.eq_ignore_ascii_case(state))
                    {
                        return Some((w, format!("{last} = {state}")));
                    }
                }
                GpoCheck::Marker(m) => {
                    if name.starts_with(m) {
                        return Some((w, name.to_string()));
                    }
                }
            }
        }
    }
    None
}

/// Hinweis für eine GPO-Einstellung in der Oberfläche.
pub fn gpo_hint(name: &str, detail: &str) -> Value {
    match match_gpo_setting(name, detail) {
        Some((w, evidence)) => json!({
            "id": w.id, "title": w.title, "severity": w.severity,
            "why": w.why, "fix": w.fix, "evidence": evidence,
        }),
        None => Value::Null,
    }
}

fn ad_hits(w: &Weakness, check: AdCheck, dir: &Directory, quota: Option<i64>) -> Option<Hit> {
    let name = |sid: &String| dir.view(sid).name;
    let accounts: Vec<String> = match check {
        AdCheck::UacUsers(bit) => dir
            .users
            .iter()
            .filter(|(_, u)| {
                u.enabled && !u.is_computer && u.uac.is_some_and(|x| x & i64::from(bit) != 0)
            })
            .map(|(s, _)| name(s))
            .collect(),
        AdCheck::UacNonDc(bit) => dir
            .users
            .iter()
            .filter(|(s, u)| {
                let dc = dir
                    .member_of
                    .get(*s)
                    .is_some_and(|g| g.iter().any(|x| matches!(rid(x), Some(516 | 521))));
                u.enabled && !dc && u.uac.is_some_and(|x| x & i64::from(bit) != 0)
            })
            .map(|(s, _)| name(s))
            .collect(),
        AdCheck::GuestEnabled => dir
            .users
            .iter()
            .filter(|(s, u)| u.enabled && rid(s) == Some(501))
            .map(|(s, _)| name(s))
            .collect(),
        AdCheck::KrbtgtPasswordOld => {
            let limit = Utc::now() - Duration::days(KRBTGT_MAX_AGE_DAYS);
            dir.users
                .iter()
                .filter(|(s, u)| rid(s) == Some(502) && u.pwd_last_set.is_some_and(|t| t < limit))
                .map(|(s, u)| {
                    format!(
                        "{}: zuletzt geändert {}",
                        name(s),
                        u.pwd_last_set
                            .map(|t| t.format("%d.%m.%Y").to_string())
                            .unwrap_or_default()
                    )
                })
                .collect()
        }
        AdCheck::MachineAccountQuota => {
            let q = quota.filter(|q| *q > 0)?;
            return Some(Hit {
                rule: w.id,
                system_id: None,
                title: w.title.to_string(),
                evidence: vec![format!("ms-DS-MachineAccountQuota = {q}")],
                affected: 1,
            });
        }
    };
    if accounts.is_empty() {
        return None;
    }
    let mut sorted = accounts;
    sorted.sort();
    let affected = sorted.len() as i64;
    let mut evidence: Vec<String> = sorted.iter().take(20).cloned().collect();
    if sorted.len() > 20 {
        evidence.push(format!("… und {} weitere", sorted.len() - 20));
    }
    Some(Hit {
        rule: w.id,
        system_id: None,
        title: format!("{} ({affected})", w.title),
        evidence,
        affected,
    })
}

type RegValues = HashMap<i64, HashMap<(String, String), String>>;

async fn load_registry(c: &impl GenericClient) -> Result<RegValues> {
    let mut out: RegValues = HashMap::new();
    for r in c
        .query(
            "SELECT system_id, key, name, value FROM system_security_settings",
            &[],
        )
        .await?
    {
        out.entry(r.get(0)).or_default().insert(
            (
                r.get::<_, String>(1).to_lowercase(),
                r.get::<_, String>(2).to_lowercase(),
            ),
            r.get(3),
        );
    }
    Ok(out)
}

/// Berechnet alle Treffer.
pub async fn evaluate(c: &impl GenericClient, dir: &Directory) -> Result<Vec<Hit>> {
    let mut hits = Vec::new();

    // Registry-Werte der Systeme
    let values = load_registry(c).await?;
    let systems = c
        .query("SELECT id, hostname, is_dc, os_build FROM systems", &[])
        .await?;
    for s in &systems {
        let id: i64 = s.get(0);
        let Some(v) = values.get(&id) else { continue };
        let is_dc: bool = s.get(2);
        let build = s.get::<_, Option<i64>>(3).map(|b| b as u32);
        for w in CATALOG.iter().filter(|w| !w.reg.is_empty()) {
            let evidence = eval_registry(w, v, is_dc, build);
            if !evidence.is_empty() {
                hits.push(Hit {
                    rule: w.id,
                    system_id: Some(id),
                    title: w.title.to_string(),
                    affected: evidence.len() as i64,
                    evidence,
                });
            }
        }
    }

    // GPO-Einstellungen (nur verknüpfte GPOs mit aktivem Bereich)
    let mut per_rule: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for r in c
        .query(
            "SELECT name, data, settings FROM gpos ORDER BY lower(name)",
            &[],
        )
        .await?
    {
        let gpo: String = r.get(0);
        let data: Value = r.get(1);
        let settings: Value = r.get(2);
        let linked = data["links"]
            .as_array()
            .is_some_and(|l| l.iter().any(|x| x["enabled"].as_bool().unwrap_or(false)));
        if !linked {
            continue;
        }
        for s in settings.as_array().into_iter().flatten() {
            let scope = s["scope"].as_str().unwrap_or("");
            let on = match scope {
                "Computer" => data["computer_enabled"].as_bool().unwrap_or(true),
                "Benutzer" => data["user_enabled"].as_bool().unwrap_or(true),
                _ => true,
            };
            if !on {
                continue;
            }
            let (name, detail) = (
                s["name"].as_str().unwrap_or(""),
                s["detail"].as_str().unwrap_or(""),
            );
            if let Some((w, evidence)) = match_gpo_setting(name, detail) {
                per_rule
                    .entry(w.id)
                    .or_default()
                    .push(format!("GPO {gpo}: {evidence}"));
            }
        }
    }
    for (rule, mut evidence) in per_rule {
        evidence.sort();
        evidence.dedup();
        let w = pc_common::weakness::find(rule).expect("Eintrag aus dem Katalog");
        hits.push(Hit {
            rule,
            system_id: None,
            title: format!("{} (per GPO gesetzt)", w.title),
            affected: evidence.len() as i64,
            evidence,
        });
    }

    // Active Directory
    if dir.ad_loaded {
        let quota = db::get_meta(c, "ad_machine_account_quota")
            .await?
            .and_then(|v| v.parse().ok());
        for w in CATALOG {
            if let Some(check) = w.ad {
                hits.extend(ad_hits(w, check, dir, quota));
            }
        }
    }
    Ok(hits)
}

/// Stand je Katalogeintrag für die Oberfläche.
async fn overview(State(st): State<AppState>) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let reported: i64 = c
        .query_one(
            "SELECT COUNT(DISTINCT system_id) FROM system_security_settings",
            &[],
        )
        .await?
        .get(0);
    let dcs: i64 = c
        .query_one(
            "SELECT COUNT(DISTINCT s.system_id) FROM system_security_settings s
             JOIN systems y ON y.id = s.system_id WHERE y.is_dc",
            &[],
        )
        .await?
        .get(0);
    let gpos: i64 = c.query_one("SELECT COUNT(*) FROM gpos", &[]).await?.get(0);
    let systems: i64 = c
        .query_one("SELECT COUNT(*) FROM systems", &[])
        .await?
        .get(0);
    let ad_users: i64 = c
        .query_one("SELECT COUNT(*) FROM ad_users", &[])
        .await?
        .get(0);
    let uac_known: i64 = c
        .query_one("SELECT COUNT(*) FROM ad_users WHERE uac IS NOT NULL", &[])
        .await?
        .get(0);
    let quota_known = db::get_meta(c, "ad_machine_account_quota").await?.is_some();

    let mut findings: HashMap<&'static str, Vec<Value>> = HashMap::new();
    for r in c
        .query(
            "SELECT f.rule, f.title, f.detail, y.hostname, f.fingerprint, f.system_id, fs.status
             FROM findings f LEFT JOIN systems y ON y.id = f.system_id
             LEFT JOIN finding_states fs ON fs.fingerprint = f.fingerprint
             ORDER BY y.hostname NULLS FIRST, f.title",
            &[],
        )
        .await?
    {
        let rule: String = r.get(0);
        if let Some(w) = for_rule(&rule) {
            findings.entry(w.id).or_default().push(json!({
                "title": r.get::<_, String>(1),
                "detail": r.get::<_, Option<String>>(2),
                "hostname": r.get::<_, Option<String>>(3),
                "fingerprint": r.get::<_, Option<String>>(4),
                "system_id": r.get::<_, Option<i64>>(5),
                "assist_status": r.get::<_, Option<String>>(6),
            }));
        }
    }

    let items: Vec<Value> = CATALOG
        .iter()
        .map(|w| {
            let mut sources = Vec::new();
            if !w.reg.is_empty() {
                sources.push("Registry");
            }
            if !w.reg.is_empty() || !w.gpo.is_empty() {
                sources.push("GPO");
            }
            if w.ad.is_some() || !w.rules.is_empty() {
                sources.push("Active Directory");
            }
            // Ohne Daten darf nichts als unauffällig gelten
            let checked = if w.manual {
                false
            } else if !w.reg.is_empty() {
                if w.reg.iter().all(|r| r.dc_only) {
                    dcs > 0
                } else {
                    reported > 0
                }
            } else if !w.gpo.is_empty() {
                gpos > 0
            } else if let Some(a) = w.ad {
                match a {
                    AdCheck::UacUsers(_) | AdCheck::UacNonDc(_) => uac_known > 0,
                    AdCheck::MachineAccountQuota => quota_known,
                    _ => ad_users > 0,
                }
            } else {
                ad_users > 0 || systems > 0
            };
            let list = findings.get(w.id).cloned().unwrap_or_default();
            let status = if !list.is_empty() {
                "found"
            } else if w.manual {
                "manual"
            } else if checked {
                "ok"
            } else {
                "unchecked"
            };
            json!({
                "id": w.id, "category": w.category, "severity": w.severity, "title": w.title,
                "why": w.why, "fix": w.fix, "status": status, "sources": sources, "findings": list,
            })
        })
        .collect();
    Ok(Json(json!({
        "systems_total": systems,
        "systems_reported": reported,
        "gpos": gpos,
        "ad_loaded": ad_users > 0,
        "items": items,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_common::weakness::find;

    fn vals(items: &[(&str, &str, &str)]) -> HashMap<(String, String), String> {
        items
            .iter()
            .map(|(k, n, v)| ((k.to_lowercase(), n.to_lowercase()), v.to_string()))
            .collect()
    }

    const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";

    #[test]
    fn lm_compat_from_registry() {
        let w = find("WK_LM_COMPAT").unwrap();
        let e = eval_registry(
            w,
            &vals(&[(LSA, "LmCompatibilityLevel", "0")]),
            false,
            Some(14393),
        );
        assert_eq!(e.len(), 1);
        assert!(e[0].contains("= 0 (LM und NTLM senden)"), "{}", e[0]);
        assert!(
            eval_registry(w, &vals(&[(LSA, "LmCompatibilityLevel", "5")]), false, None).is_empty()
        );
        // Fehlt der Wert, gilt der sichere Standard
        assert!(eval_registry(w, &vals(&[]), false, None).is_empty());
    }

    #[test]
    fn default_counts_and_is_labelled() {
        let w = find("WK_SMB_SIGN_SERVER").unwrap();
        let e = eval_registry(w, &vals(&[]), false, Some(14393));
        assert!(e[0].contains("Standardwert"), "{}", e[0]);
        assert!(eval_registry(w, &vals(&[]), false, Some(26100)).is_empty());
    }

    #[test]
    fn dc_only_is_skipped_elsewhere() {
        let w = find("WK_LDAP_SIGN").unwrap();
        assert!(eval_registry(w, &vals(&[]), false, None).is_empty());
        assert_eq!(eval_registry(w, &vals(&[]), true, None).len(), 1);
    }

    #[test]
    fn policy_value_wins() {
        let w = find("WK_RDP_NLA").unwrap();
        let rdp = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
        let pol = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
        let weak = vals(&[(rdp, "UserAuthentication", "0")]);
        assert_eq!(eval_registry(w, &weak, false, None).len(), 1);
        let fixed = vals(&[
            (rdp, "UserAuthentication", "0"),
            (pol, "UserAuthentication", "1"),
        ]);
        assert!(eval_registry(w, &fixed, false, None).is_empty());
    }

    #[test]
    fn gpo_security_option_matches_language_independent() {
        let (w, e) = match_gpo_setting(
            r"MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel",
            r"KeyName: MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel | SettingNumber: 0",
        )
        .unwrap();
        assert_eq!(w.id, "WK_LM_COMPAT");
        assert!(e.contains("LM und NTLM senden"));
        assert!(match_gpo_setting(
            "x",
            r"KeyName: MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel | SettingNumber: 5",
        )
        .is_none());
    }

    #[test]
    fn gpo_account_policy_and_marker() {
        let (w, _) = match_gpo_setting(
            "MinimumPasswordLength",
            "Name: MinimumPasswordLength | SettingNumber: 7 | Type: Password",
        )
        .unwrap();
        assert_eq!(w.id, "WK_PW_LENGTH");
        assert!(match_gpo_setting(
            "MinimumPasswordLength",
            "Name: MinimumPasswordLength | SettingNumber: 14"
        )
        .is_none());
        let (w, _) = match_gpo_setting(
            "PasswordComplexity",
            "Name: PasswordComplexity | SettingBoolean: false",
        )
        .unwrap();
        assert_eq!(w.id, "WK_PW_COMPLEXITY");
        let (w, _) = match_gpo_setting(
            "Turn off multicast name resolution",
            "Name: Turn off multicast name resolution | State: Disabled",
        )
        .unwrap();
        assert_eq!(w.id, "WK_LLMNR");
        assert!(match_gpo_setting(
            "Multicastnamensauflösung deaktivieren",
            "Name: Multicastnamensauflösung deaktivieren | State: Enabled",
        )
        .is_none());
        let (w, _) =
            match_gpo_setting("GPP-Kennwort: Administrator", "Marker: cpassword gesetzt").unwrap();
        assert_eq!(w.id, "WK_GPP_PASSWORD");
        assert!(match_gpo_setting("Irgendwas", "Name: Irgendwas | State: Enabled").is_none());
    }

    #[test]
    fn rules_only_for_own_findings() {
        assert!(rule("WK_LM_COMPAT").is_some());
        assert!(rule("WK_KERBEROAST").is_none(), "nutzt vorhandene Regel");
        assert!(rule("WK_NBTNS").is_none(), "nicht automatisch prüfbar");
    }
}
