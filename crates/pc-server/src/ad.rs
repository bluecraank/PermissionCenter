//! Active-Directory-Anbindung: LDAP-Synchronisation und JSON-Import.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use futures_util::pin_mut;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use tokio_postgres::binary_copy::BinaryCopyInWriter;
use tokio_postgres::types::Type;
use tokio_postgres::Transaction;
use tracing::info;

use crate::config::LdapConfig;
use crate::db;
use pc_common::sid::{domain_prefix, sid_to_string};
use pc_common::{AdGroup, AdSnapshot, AdUser};

const UAC_ACCOUNTDISABLE: u32 = 0x2;

/// Speichert einen AD-Stand (ersetzt den bisherigen vollständig).
pub async fn store_snapshot(
    tx: &Transaction<'_>,
    snap: &AdSnapshot,
    source: &str,
) -> Result<(usize, usize)> {
    tx.batch_execute("DELETE FROM ad_members; DELETE FROM ad_users; DELETE FROM ad_groups;")
        .await?;
    let ust = tx
        .prepare(
            "INSERT INTO ad_users (sid, sam, upn, display_name, dn, enabled, last_logon, pwd_last_set, created, is_computer)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (sid) DO NOTHING",
        )
        .await?;
    let gst = tx
        .prepare(
            "INSERT INTO ad_groups (sid, sam, dn, description, scope, is_security, created)
             VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (sid) DO NOTHING",
        )
        .await?;
    let mut members: HashSet<(String, String)> = HashSet::new();
    for u in &snap.users {
        tx.execute(
            &ust,
            &[
                &u.sid,
                &u.sam_account_name,
                &u.user_principal_name,
                &u.display_name,
                &u.distinguished_name,
                &u.enabled,
                &u.last_logon,
                &u.password_last_set,
                &u.created,
                &u.is_computer,
            ],
        )
        .await?;
        for g in &u.member_of {
            members.insert((g.clone(), u.sid.clone()));
        }
    }
    for g in &snap.groups {
        tx.execute(
            &gst,
            &[
                &g.sid,
                &g.sam_account_name,
                &g.distinguished_name,
                &g.description,
                &g.scope,
                &g.is_security,
                &g.created,
            ],
        )
        .await?;
        for m in &g.members {
            members.insert((g.sid.clone(), m.clone()));
        }
    }
    // Mitgliedschaften in einem Rutsch per COPY
    let sink = tx
        .copy_in("COPY ad_members (group_sid, member_sid) FROM STDIN BINARY")
        .await?;
    let writer = BinaryCopyInWriter::new(sink, &[Type::TEXT, Type::TEXT]);
    pin_mut!(writer);
    for (g, m) in &members {
        writer.as_mut().write(&[g, m]).await?;
    }
    writer.finish().await?;

    let domain_sid = snap.domain_sid.clone().or_else(|| {
        snap.users
            .iter()
            .find_map(|u| domain_prefix(&u.sid).map(str::to_string))
    });
    db::set_meta(tx, "ad_domain", snap.domain.as_deref()).await?;
    db::set_meta(tx, "ad_domain_sid", domain_sid.as_deref()).await?;
    db::set_meta(tx, "ad_synced_at", Some(&Utc::now().to_rfc3339())).await?;
    db::set_meta(tx, "ad_source", Some(source)).await?;
    Ok((snap.users.len(), snap.groups.len()))
}

fn first<'a>(e: &'a SearchEntry, attr: &str) -> Option<&'a str> {
    e.attrs
        .get(attr)
        .and_then(|v| v.first())
        .map(String::as_str)
}

fn filetime(v: Option<&str>) -> Option<DateTime<Utc>> {
    let ft: i64 = v?.parse().ok()?;
    if ft <= 0 || ft == i64::MAX {
        return None;
    }
    let secs = ft / 10_000_000 - 11_644_473_600;
    Utc.timestamp_opt(secs, 0).single()
}

fn generalized_time(v: Option<&str>) -> Option<DateTime<Utc>> {
    let s = v?;
    let s = s.split('.').next()?.trim_end_matches('Z');
    NaiveDateTime::parse_from_str(s, "%Y%m%d%H%M%S")
        .ok()
        .map(|n| Utc.from_utc_datetime(&n))
}

fn entry_sid(e: &SearchEntry) -> Option<String> {
    e.bin_attrs
        .get("objectSid")
        .and_then(|v| v.first())
        .and_then(|b| sid_to_string(b))
}

fn group_scope(group_type: i64) -> (Option<String>, bool) {
    let gt = group_type as u32;
    let scope = if gt & 0x1 != 0 {
        "builtin"
    } else if gt & 0x2 != 0 {
        "global"
    } else if gt & 0x4 != 0 {
        "domain_local"
    } else if gt & 0x8 != 0 {
        "universal"
    } else {
        "unknown"
    };
    (Some(scope.to_string()), gt & 0x8000_0000 != 0)
}

fn connect(cfg: &LdapConfig) -> Result<LdapConn> {
    let url = cfg
        .url
        .as_deref()
        .ok_or_else(|| anyhow!("LDAP-URL fehlt"))?;
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(15))
        .set_starttls(cfg.starttls)
        .set_no_tls_verify(cfg.no_tls_verify);
    let mut ldap = LdapConn::with_settings(settings, url)
        .with_context(|| format!("Verbindung zu {url} fehlgeschlagen"))?;
    match (&cfg.bind_dn, &cfg.bind_password) {
        (Some(dn), Some(pw)) => {
            ldap.simple_bind(dn, pw)?
                .success()
                .context("LDAP-Anmeldung fehlgeschlagen")?;
        }
        _ => return Err(anyhow!("bind_dn/bind_password fehlen")),
    }
    Ok(ldap)
}

fn paged_search(
    ldap: &mut LdapConn,
    base: &str,
    filter: &str,
    attrs: &[&str],
) -> Result<Vec<SearchEntry>> {
    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(500)),
    ];
    let mut search =
        ldap.streaming_search_with(adapters, base, Scope::Subtree, filter, attrs.to_vec())?;
    let mut out = Vec::new();
    while let Some(entry) = search.next()? {
        out.push(SearchEntry::construct(entry));
    }
    search.result().success()?;
    Ok(out)
}

/// Liest Benutzer, Computer und Gruppen per LDAP (blockierend).
pub fn fetch_snapshot(cfg: &LdapConfig) -> Result<AdSnapshot> {
    let base = cfg
        .base_dn
        .as_deref()
        .ok_or_else(|| anyhow!("base_dn fehlt"))?;
    let mut ldap = connect(cfg)?;

    let root = ldap
        .search(
            base,
            Scope::Base,
            "(objectClass=*)",
            vec!["objectSid", "name"],
        )?
        .success()?
        .0;
    let domain_sid = root
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .and_then(|e| entry_sid(&e));

    let user_attrs = [
        "objectSid",
        "sAMAccountName",
        "userPrincipalName",
        "displayName",
        "distinguishedName",
        "userAccountControl",
        "lastLogonTimestamp",
        "pwdLastSet",
        "whenCreated",
        "primaryGroupID",
        "objectClass",
    ];
    let accounts = paged_search(
        &mut ldap,
        base,
        "(|(&(objectCategory=person)(objectClass=user))(objectClass=computer))",
        &user_attrs,
    )?;
    let groups = paged_search(
        &mut ldap,
        base,
        "(objectClass=group)",
        &[
            "objectSid",
            "sAMAccountName",
            "distinguishedName",
            "description",
            "groupType",
            "member",
            "whenCreated",
        ],
    )?;
    let _ = ldap.unbind();

    // DN → SID für die Auflösung von `member`
    let mut dn_sid: HashMap<String, String> = HashMap::new();
    for e in accounts.iter().chain(groups.iter()) {
        if let (Some(sid), Some(dn)) = (entry_sid(e), first(e, "distinguishedName")) {
            dn_sid.insert(dn.to_lowercase(), sid);
        }
    }

    let mut snap = AdSnapshot {
        domain: Some(
            base.split(',')
                .filter_map(|p| {
                    p.trim()
                        .strip_prefix("DC=")
                        .or_else(|| p.trim().strip_prefix("dc="))
                })
                .collect::<Vec<_>>()
                .join("."),
        ),
        domain_sid: domain_sid.clone(),
        collected_at: Some(Utc::now()),
        ..Default::default()
    };
    for e in &accounts {
        let Some(sid) = entry_sid(e) else { continue };
        let uac: u32 = first(e, "userAccountControl")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let is_computer = e
            .attrs
            .get("objectClass")
            .is_some_and(|v| v.iter().any(|c| c.eq_ignore_ascii_case("computer")));
        let mut member_of = Vec::new();
        // Primäre Gruppe (meist Domänen-Benutzer) taucht nicht in `member` auf.
        if let (Some(ds), Some(pg)) = (&domain_sid, first(e, "primaryGroupID")) {
            member_of.push(format!("{ds}-{pg}"));
        }
        snap.users.push(AdUser {
            sid,
            sam_account_name: first(e, "sAMAccountName").unwrap_or_default().to_string(),
            user_principal_name: first(e, "userPrincipalName").map(str::to_string),
            display_name: first(e, "displayName").map(str::to_string),
            distinguished_name: first(e, "distinguishedName").map(str::to_string),
            enabled: uac & UAC_ACCOUNTDISABLE == 0,
            last_logon: filetime(first(e, "lastLogonTimestamp")),
            password_last_set: filetime(first(e, "pwdLastSet")),
            created: generalized_time(first(e, "whenCreated")),
            is_computer,
            member_of,
        });
    }
    for e in &groups {
        let Some(sid) = entry_sid(e) else { continue };
        let gt: i64 = first(e, "groupType")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let (scope, is_security) = group_scope(gt);
        let members = e
            .attrs
            .get("member")
            .map(|v| {
                v.iter()
                    .filter_map(|dn| dn_sid.get(&dn.to_lowercase()).cloned())
                    .collect()
            })
            .unwrap_or_default();
        snap.groups.push(AdGroup {
            sid,
            sam_account_name: first(e, "sAMAccountName").unwrap_or_default().to_string(),
            distinguished_name: first(e, "distinguishedName").map(str::to_string),
            description: first(e, "description").map(str::to_string),
            scope,
            is_security,
            members,
            created: generalized_time(first(e, "whenCreated")),
        });
    }
    info!(
        "LDAP: {} Konten, {} Gruppen gelesen",
        snap.users.len(),
        snap.groups.len()
    );
    Ok(snap)
}

/// Prüft Anmeldedaten per LDAP-Bind. Vorbereitet für `auth.mode = "ldap"`.
#[allow(dead_code)]
pub fn verify_credentials(cfg: &LdapConfig, user: &str, password: &str) -> Result<bool> {
    if password.is_empty() {
        return Ok(false);
    }
    let url = cfg
        .url
        .as_deref()
        .ok_or_else(|| anyhow!("LDAP-URL fehlt"))?;
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(10))
        .set_starttls(cfg.starttls)
        .set_no_tls_verify(cfg.no_tls_verify);
    let mut ldap = LdapConn::with_settings(settings, url)?;
    let ok = ldap.simple_bind(user, password)?.success().is_ok();
    let _ = ldap.unbind();
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_conversions() {
        assert_eq!(
            filetime(Some("133500000000000000"))
                .unwrap()
                .format("%Y")
                .to_string(),
            "2024"
        );
        assert!(filetime(Some("0")).is_none());
        assert!(filetime(Some("9223372036854775807")).is_none());
        assert_eq!(
            generalized_time(Some("20240115083000.0Z"))
                .unwrap()
                .to_rfc3339(),
            "2024-01-15T08:30:00+00:00"
        );
        assert_eq!(group_scope(-2147483646), (Some("global".into()), true));
        assert_eq!(group_scope(-2147483643), (Some("builtin".into()), true));
    }
}
