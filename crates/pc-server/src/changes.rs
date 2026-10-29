//! Änderungsverlauf: Unterschiede der expliziten Berechtigungen, Vererbung,
//! Besitzer und Freigabeberechtigungen zwischen zwei Scans eines Systems.
//!
//! Verglichen wird nur innerhalb der Scan-Wurzeln, die in beiden Scans
//! vorkommen. Ein Teil-Scan (`pc-client scan --path …`) erzeugt so keine
//! Scheinänderungen für die übrigen Laufwerke.

use std::collections::{BTreeMap, HashMap};

use anyhow::Result;
use chrono::{DateTime, Utc};
use pc_common::rights::{classify, Rights};
use tokio_postgres::Transaction;

/// Höchstzahl gespeicherter Änderungen je Scan (Schutz vor Massenänderungen).
const MAX_CHANGES: usize = 20_000;

/// (SID, Typ, Flags) → Maske
type AceSet = BTreeMap<(String, String, i32), i64>;

#[derive(Default)]
pub struct Snapshot {
    roots: Vec<String>,
    /// Pfad (klein) → (Pfad, geschützt, Besitzer, explizite ACEs)
    folders: HashMap<String, (String, bool, Option<String>, AceSet)>,
    /// Freigabename (klein) → (Name, Pfad, ACEs)
    shares: HashMap<String, (String, String, AceSet)>,
}

pub struct Change {
    pub object_kind: &'static str,
    pub path: String,
    pub change: &'static str,
    pub sid: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

fn norm(p: &str) -> String {
    p.trim_end_matches('\\').to_lowercase()
}

fn under(path: &str, root: &str) -> bool {
    path == root
        || path.starts_with(&format!("{root}\\"))
        || root.ends_with(':') && path.starts_with(root)
}

/// Lädt den aktuell gespeicherten Stand eines Systems.
pub async fn snapshot(tx: &Transaction<'_>, system_id: i64) -> Result<Snapshot> {
    let mut s = Snapshot::default();
    if let Some(r) = tx
        .query_opt(
            "SELECT s.roots FROM systems y JOIN scans s ON s.id = y.last_scan_id WHERE y.id = $1",
            &[&system_id],
        )
        .await?
    {
        let roots: serde_json::Value = r.get(0);
        s.roots = roots
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| x["path"].as_str())
            .map(norm)
            .collect();
    }
    for r in tx
        .query(
            "SELECT path, protected, owner_sid FROM folders WHERE system_id = $1",
            &[&system_id],
        )
        .await?
    {
        let path: String = r.get(0);
        s.folders
            .insert(norm(&path), (path, r.get(1), r.get(2), AceSet::new()));
    }
    for r in tx
        .query(
            "SELECT f.path, a.sid, a.ace_type, a.flags, a.mask FROM aces a
             JOIN folders f ON f.system_id = a.system_id AND f.local_id = a.folder_local_id
             WHERE a.system_id = $1 AND NOT a.inherited AND a.ace_type IN ('allow', 'deny')",
            &[&system_id],
        )
        .await?
    {
        let path: String = r.get(0);
        if let Some(f) = s.folders.get_mut(&norm(&path)) {
            f.3.insert((r.get(1), r.get(2), r.get(3)), r.get(4));
        }
    }
    for r in tx
        .query(
            "SELECT s.name, s.path, x.sid, x.ace_type, x.mask FROM shares s
             LEFT JOIN share_aces x ON x.share_id = s.id
             WHERE s.system_id = $1 AND NOT s.is_special",
            &[&system_id],
        )
        .await?
    {
        let name: String = r.get(0);
        let e = s
            .shares
            .entry(name.to_lowercase())
            .or_insert_with(|| (name.clone(), r.get(1), AceSet::new()));
        if let Some(sid) = r.get::<_, Option<String>>(2) {
            e.2.insert((sid, r.get(3), -1), r.get(4));
        }
    }
    Ok(s)
}

fn ace_label(ace_type: &str, flags: i32, mask: i64) -> String {
    let r: Rights = classify(mask as u32);
    let mut s = String::new();
    if ace_type == "deny" {
        s.push_str("Verweigern: ");
    }
    s.push_str(r.label_de());
    // Freigabe-ACEs haben keine Vererbung (flags = -1)
    if flags < 0 {
    } else if flags & 0x8 != 0 {
        s.push_str(" (nur Unterobjekte)");
    } else if flags & 0x3 == 0 {
        s.push_str(" (nur dieser Ordner)");
    }
    s
}

fn diff_aces(out: &mut Vec<Change>, kind: &'static str, path: &str, old: &AceSet, new: &AceSet) {
    for (k, m) in new {
        match old.get(k) {
            None => out.push(Change {
                object_kind: kind,
                path: path.to_string(),
                change: "ace_added",
                sid: Some(k.0.clone()),
                old_value: None,
                new_value: Some(ace_label(&k.1, k.2, *m)),
            }),
            Some(om) if om != m => out.push(Change {
                object_kind: kind,
                path: path.to_string(),
                change: "ace_changed",
                sid: Some(k.0.clone()),
                old_value: Some(ace_label(&k.1, k.2, *om)),
                new_value: Some(ace_label(&k.1, k.2, *m)),
            }),
            _ => {}
        }
    }
    for (k, m) in old {
        if !new.contains_key(k) {
            out.push(Change {
                object_kind: kind,
                path: path.to_string(),
                change: "ace_removed",
                sid: Some(k.0.clone()),
                old_value: Some(ace_label(&k.1, k.2, *m)),
                new_value: None,
            });
        }
    }
}

/// Vergleicht zwei Stände. Ohne gemeinsamen Scan-Bereich gibt es keine Änderungen.
pub fn diff(old: &Snapshot, new: &Snapshot, host: &str) -> Vec<Change> {
    let mut out = Vec::new();
    let common: Vec<&String> = new.roots.iter().filter(|r| old.roots.contains(r)).collect();
    if common.is_empty() {
        return out;
    }
    let in_scope = |p: &str| common.iter().any(|r| under(p, r));
    let empty = AceSet::new();

    let mut paths: Vec<&String> = new.folders.keys().chain(old.folders.keys()).collect();
    paths.sort();
    paths.dedup();
    for key in paths {
        if !in_scope(key) {
            continue;
        }
        match (old.folders.get(key), new.folders.get(key)) {
            (Some(o), Some(n)) => {
                diff_aces(&mut out, "folder", &n.0, &o.3, &n.3);
                if o.1 != n.1 {
                    out.push(Change {
                        object_kind: "folder",
                        path: n.0.clone(),
                        change: if n.1 {
                            "inheritance_disabled"
                        } else {
                            "inheritance_enabled"
                        },
                        sid: None,
                        old_value: None,
                        new_value: None,
                    });
                }
                if o.2.is_some() && n.2.is_some() && o.2 != n.2 {
                    out.push(Change {
                        object_kind: "folder",
                        path: n.0.clone(),
                        change: "owner_changed",
                        sid: n.2.clone(),
                        old_value: o.2.clone(),
                        new_value: n.2.clone(),
                    });
                }
            }
            // Neu gemeldeter Ordner: nur explizite Rechte sind eine Änderung
            (None, Some(n)) => {
                diff_aces(&mut out, "folder", &n.0, &empty, &n.3);
                if n.1 {
                    out.push(Change {
                        object_kind: "folder",
                        path: n.0.clone(),
                        change: "inheritance_disabled",
                        sid: None,
                        old_value: None,
                        new_value: None,
                    });
                }
            }
            // Nicht mehr gemeldet: relevant nur, wenn er eigene Rechte hatte
            (Some(o), None) if !o.3.is_empty() => out.push(Change {
                object_kind: "folder",
                path: o.0.clone(),
                change: "folder_removed",
                sid: None,
                old_value: Some(format!("{} explizite Einträge", o.3.len())),
                new_value: None,
            }),
            _ => {}
        }
        if out.len() > MAX_CHANGES {
            break;
        }
    }

    let mut names: Vec<&String> = new.shares.keys().chain(old.shares.keys()).collect();
    names.sort();
    names.dedup();
    for key in names {
        match (old.shares.get(key), new.shares.get(key)) {
            (Some(o), Some(n)) => diff_aces(
                &mut out,
                "share",
                &format!("\\\\{host}\\{}", n.0),
                &o.2,
                &n.2,
            ),
            (None, Some(n)) => out.push(Change {
                object_kind: "share",
                path: format!("\\\\{host}\\{}", n.0),
                change: "share_added",
                sid: None,
                old_value: None,
                new_value: Some(n.1.clone()),
            }),
            (Some(o), None) => out.push(Change {
                object_kind: "share",
                path: format!("\\\\{host}\\{}", o.0),
                change: "share_removed",
                sid: None,
                old_value: Some(o.1.clone()),
                new_value: None,
            }),
            _ => {}
        }
    }
    out.truncate(MAX_CHANGES);
    out
}

pub async fn store(
    tx: &Transaction<'_>,
    system_id: i64,
    scan_id: i64,
    at: DateTime<Utc>,
    changes: &[Change],
) -> Result<()> {
    let stmt = tx
        .prepare(
            "INSERT INTO changes (system_id, scan_id, detected_at, object_kind, path, change, sid, old_value, new_value)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .await?;
    for c in changes {
        tx.execute(
            &stmt,
            &[
                &system_id,
                &scan_id,
                &at,
                &c.object_kind,
                &c.path,
                &c.change,
                &c.sid,
                &c.old_value,
                &c.new_value,
            ],
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(roots: &[&str], folders: &[(&str, bool, &[(&str, i64)])]) -> Snapshot {
        let mut s = Snapshot {
            roots: roots.iter().map(|r| norm(r)).collect(),
            ..Default::default()
        };
        for (p, prot, aces) in folders {
            let set: AceSet = aces
                .iter()
                .map(|(sid, m)| ((sid.to_string(), "allow".to_string(), 3), *m))
                .collect();
            s.folders.insert(
                norm(p),
                (p.to_string(), *prot, Some("S-1-5-32-544".into()), set),
            );
        }
        s
    }

    #[test]
    fn detects_changes_in_common_roots_only() {
        let modify = 0x1301bf;
        let read = 0x1200a9;
        let old = snap(
            &["D:\\", "E:\\"],
            &[
                ("D:\\Daten", false, &[("S-1-5-21-1-1001", read)]),
                ("D:\\Alt", false, &[("S-1-5-21-1-1002", read)]),
                ("E:\\Archiv", false, &[("S-1-5-21-1-1003", read)]),
            ],
        );
        // Teil-Scan nur über D:\ – E:\ darf nicht als entfernt erscheinen
        let new = snap(
            &["D:\\"],
            &[(
                "D:\\Daten",
                true,
                &[("S-1-5-21-1-1001", modify), ("S-1-1-0", read)],
            )],
        );
        let c = diff(&old, &new, "FS01");
        let kinds: Vec<_> = c.iter().map(|x| x.change).collect();
        assert!(kinds.contains(&"ace_changed"));
        assert!(kinds.contains(&"ace_added"));
        assert!(kinds.contains(&"inheritance_disabled"));
        assert!(kinds.contains(&"folder_removed"));
        assert!(c.iter().all(|x| !x.path.starts_with("E:")));
        assert_eq!(c.len(), 4);
    }
}
