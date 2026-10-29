//! Rekursiver Berechtigungsscan über Laufwerke, Freigaben und UNC-Pfade.
//!
//! Im Modus `relevant` werden nur Ordner gemeldet, die vom Elternordner
//! abweichen (eigene ACEs, unterbrochene Vererbung, Fehler, verwaister Besitzer)
//! sowie deren Vorfahren und die oberen `skeleton_depth` Ebenen. Alle übrigen
//! Ordner erben exakt die Rechte ihres `acl_source_id`-Vorfahren.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use anyhow::Result;
use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::ScanConfig;
use crate::exclude::ExcludeSet;
use crate::win::{fs, resolver::SidResolver, shares, system};
use pc_common::{
    FolderRecord, ReportMode, RootKind, ScanError, ScanReport, ScanRoot, ScanStats, ShareInfo,
    REPORT_SCHEMA_VERSION,
};

struct Pending {
    rec: Option<FolderRecord>,
    idx: Option<usize>,
}

#[derive(Default, Clone, Copy)]
struct RootCounters {
    scanned: u64,
    excluded: u64,
    errors: u64,
}

struct Scanner<'a> {
    cfg: &'a ScanConfig,
    excludes: ExcludeSet,
    resolver: SidResolver,
    folders: Vec<FolderRecord>,
    next_id: u64,
    stats: ScanStats,
    errors: Vec<ScanError>,
    forced: HashSet<String>,
    path_ids: HashMap<String, u64>,
    root: RootCounters,
    last_progress: Instant,
    max_logged_errors: u64,
}

pub fn join(parent: &str, name: &str) -> String {
    if parent.ends_with('\\') {
        format!("{parent}{name}")
    } else {
        format!("{parent}\\{name}")
    }
}

fn norm(path: &str) -> String {
    let p = path.trim_end_matches('\\').to_lowercase();
    if p.len() == 2 && p.ends_with(':') {
        format!("{p}\\")
    } else {
        p
    }
}

impl<'a> Scanner<'a> {
    fn new(cfg: &'a ScanConfig) -> Self {
        let excludes = ExcludeSet::new(&cfg.exclude);
        info!("{} Ausschlussregeln aktiv", excludes.len());
        Self {
            cfg,
            excludes,
            resolver: SidResolver::new(),
            folders: Vec::new(),
            next_id: 1,
            stats: ScanStats::default(),
            errors: Vec::new(),
            forced: HashSet::new(),
            path_ids: HashMap::new(),
            root: RootCounters::default(),
            last_progress: Instant::now(),
            max_logged_errors: 200,
        }
    }

    fn scan_root(&mut self, path: &str, kind: RootKind) -> ScanRoot {
        info!("Scanne {} ({})", path, kind.as_str());
        self.root = RootCounters::default();
        // `\\?\`-Pfade akzeptieren keine Schrägstriche
        let path = path.replace('/', "\\");
        let display = if path.len() == 2 && path.ends_with(':') {
            format!("{path}\\")
        } else if path.len() > 3 {
            path.trim_end_matches('\\').to_string()
        } else {
            path
        };
        let first_id = self.next_id;
        let mut stack = Vec::new();
        self.visit(display.clone(), 0, None, None, &mut stack);
        ScanRoot {
            path: display,
            kind,
            folder_id: Some(first_id),
            folders_scanned: self.root.scanned,
            folders_excluded: self.root.excluded,
            errors: self.root.errors,
        }
    }

    fn error(&mut self, path: &str, e: &fs::WinError) {
        self.stats.errors += 1;
        self.root.errors += 1;
        if self.stats.errors <= self.max_logged_errors {
            warn!("Lesefehler {}: {} (Code {})", path, e.message, e.code);
            if self.stats.errors == self.max_logged_errors {
                warn!(
                    "Weitere Lesefehler werden nur noch gezählt (logging.max_logged_scan_errors)"
                );
            }
        } else {
            tracing::debug!("Lesefehler {}: {} (Code {})", path, e.message, e.code);
        }
        if self.errors.len() < 10_000 {
            self.errors.push(ScanError {
                path: path.to_string(),
                code: Some(e.code),
                message: e.message.clone(),
            });
        }
    }

    fn emit_stack(&mut self, stack: &mut [Pending]) {
        for p in stack.iter_mut() {
            if let Some(rec) = p.rec.take() {
                p.idx = Some(self.folders.len());
                self.folders.push(rec);
            }
        }
    }

    fn visit(
        &mut self,
        path: String,
        depth: u32,
        parent_id: Option<u64>,
        parent_source: Option<u64>,
        stack: &mut Vec<Pending>,
    ) -> u64 {
        self.stats.folders_scanned += 1;
        self.root.scanned += 1;
        if self.last_progress.elapsed().as_secs() >= 10 {
            self.last_progress = Instant::now();
            info!(
                "… {} Ordner gescannt, {} gemeldet – {}",
                self.stats.folders_scanned,
                self.folders.len(),
                path
            );
        }
        let id = self.next_id;
        self.next_id += 1;

        let (sec, entries) = match fs::open_dir(&path, true) {
            Ok(h) => (fs::read_security(&h), fs::list_dir(&h)),
            Err(list_err) => match fs::open_dir(&path, false) {
                Ok(h) => (fs::read_security(&h), Err(list_err)),
                Err(e) => (Err(e), Err(list_err)),
            },
        };

        let mut rec = FolderRecord {
            id,
            parent_id,
            path,
            depth,
            owner_sid: None,
            inheritance_protected: false,
            has_explicit_aces: false,
            acl_source_id: parent_source,
            aces: Vec::new(),
            file_count: 0,
            file_bytes: 0,
            subfolder_total: 0,
            is_reparse_point: false,
            error: None,
        };

        let mut owner_orphaned = false;
        match sec {
            Ok(sec) => {
                rec.has_explicit_aces = sec.aces.iter().any(|a| !a.inherited);
                rec.inheritance_protected = sec.protected;
                if let Some(o) = &sec.owner_sid {
                    owner_orphaned = self.resolver.is_orphaned(o);
                }
                rec.owner_sid = sec.owner_sid;
                for a in &sec.aces {
                    let orphan = self.resolver.is_orphaned(&a.sid);
                    if orphan && !a.inherited {
                        self.stats.orphaned_aces += 1;
                    }
                }
                rec.aces = sec.aces;
            }
            Err(e) => {
                rec.error = Some(format!("Sicherheit nicht lesbar: {e}"));
                self.error(&rec.path, &e);
            }
        }
        if rec.has_explicit_aces {
            self.stats.folders_with_explicit_aces += 1;
        }
        if rec.inheritance_protected {
            self.stats.folders_inheritance_protected += 1;
        }
        if rec.has_explicit_aces || rec.inheritance_protected || parent_source.is_none() {
            rec.acl_source_id = Some(id);
        }
        let source = rec.acl_source_id;

        let mut subdirs = Vec::new();
        match entries {
            Ok(list) => {
                for e in list {
                    if !e.is_dir() {
                        rec.file_count += 1;
                        rec.file_bytes += e.size;
                        continue;
                    }
                    if e.is_reparse() {
                        self.stats.reparse_points_skipped += 1;
                        continue;
                    }
                    subdirs.push(e);
                }
                self.stats.files_seen += rec.file_count;
            }
            Err(e) => {
                if rec.error.is_none() {
                    rec.error = Some(format!("Inhalt nicht lesbar: {e}"));
                    self.error(&rec.path, &e);
                }
            }
        }

        let key = norm(&rec.path);
        let forced = self.forced.contains(&key);
        if forced {
            self.path_ids.insert(key, id);
        }
        let relevant = self.cfg.report_mode == ReportMode::Full
            || depth <= self.cfg.skeleton_depth
            || rec.has_explicit_aces
            || rec.inheritance_protected
            || rec.error.is_some()
            || owner_orphaned
            || forced;
        let parent_path = rec.path.clone();
        stack.push(Pending {
            rec: Some(rec),
            idx: None,
        });
        if relevant {
            self.emit_stack(stack);
        }

        let mut sub_total = 0u64;
        let depth_ok = self.cfg.max_depth.is_none_or(|m| depth < m);
        for e in subdirs {
            let child = join(&parent_path, &e.name);
            if (self.cfg.skip_system_hidden && e.is_system_hidden())
                || self.excludes.is_excluded(&child)
            {
                self.stats.folders_excluded += 1;
                self.root.excluded += 1;
                continue;
            }
            if !depth_ok {
                sub_total += 1;
                continue;
            }
            sub_total += 1 + self.visit(child, depth + 1, Some(id), source, stack);
        }

        let p = stack.pop().expect("Stack");
        if let Some(idx) = p.idx {
            self.folders[idx].subfolder_total = sub_total;
        }
        sub_total
    }
}

/// Führt einen vollständigen Scan aus. `paths` überschreibt die konfigurierten Roots.
pub fn run(cfg: &ScanConfig, paths: &[String], max_logged_errors: u64) -> Result<ScanReport> {
    let cfg = cfg.clone();
    let paths = paths.to_vec();
    // Span des aufrufenden Threads (Lauf-ID) in den Scanner-Thread übernehmen
    let span = tracing::Span::current();
    // Tiefe Verzeichnisbäume: eigener Thread mit großem Stack.
    let handle = std::thread::Builder::new()
        .name("scanner".into())
        .stack_size(128 * 1024 * 1024)
        .spawn(move || span.in_scope(|| run_inner(&cfg, &paths, max_logged_errors)))?;
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("Scanner-Thread abgebrochen"))?
}

fn run_inner(cfg: &ScanConfig, paths: &[String], max_logged_errors: u64) -> Result<ScanReport> {
    let started_at = Utc::now();
    let t0 = Instant::now();
    if !system::is_elevated() {
        warn!("Prozess läuft ohne Administratorrechte – Ergebnisse sind unvollständig");
    }
    for p in [
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeSecurityPrivilege",
    ] {
        if !system::enable_privilege(p) {
            warn!("{p} konnte nicht aktiviert werden");
        }
    }
    let host = system::host_info();
    info!(
        "System: {} ({}, {})",
        host.hostname, host.os_name, host.os_version
    );

    let mut sc = Scanner::new(cfg);
    sc.max_logged_errors = max_logged_errors;
    let mut roots = Vec::new();
    let mut share_list: Vec<ShareInfo> = Vec::new();

    if paths.is_empty() && cfg.shares {
        match shares::enumerate() {
            Ok(s) => share_list = s,
            Err(e) => warn!("Freigaben nicht ermittelbar: {e}"),
        }
        for s in share_list
            .iter()
            .filter(|s| shares::is_disk_share(s) && !s.is_special)
        {
            sc.forced.insert(norm(&s.path));
        }
        info!("{} Freigaben gefunden", share_list.len());
    }

    if !paths.is_empty() {
        for p in paths {
            let kind = if p.starts_with("\\\\") {
                RootKind::Remote
            } else {
                RootKind::LocalDrive
            };
            roots.push(sc.scan_root(p, kind));
        }
    } else {
        if cfg.local_drives {
            let wanted: Vec<String> = cfg
                .drives
                .iter()
                .map(|d| d.trim_end_matches('\\').to_uppercase())
                .collect();
            for d in system::drives(system::DRIVE_FIXED) {
                if wanted.is_empty() || wanted.contains(&d) {
                    roots.push(sc.scan_root(&d, RootKind::LocalDrive));
                }
            }
        }
        // Freigaben, deren Pfad noch nicht erfasst wurde (z. B. unter ausgeschlossenen Ordnern wie SYSVOL)
        for s in share_list
            .iter()
            .filter(|s| shares::is_disk_share(s) && !s.is_special)
        {
            if s.path.is_empty() || sc.path_ids.contains_key(&norm(&s.path)) {
                continue;
            }
            roots.push(sc.scan_root(&s.path, RootKind::Share));
        }
        if cfg.mapped_drives {
            for d in system::drives(system::DRIVE_REMOTE) {
                roots.push(sc.scan_root(&d, RootKind::Remote));
            }
        }
        for p in &cfg.extra_paths {
            roots.push(sc.scan_root(p, RootKind::Remote));
        }
    }

    for s in share_list.iter_mut() {
        s.folder_id = sc.path_ids.get(&norm(&s.path)).copied();
        if let Some(perms) = &s.permissions {
            for a in perms {
                sc.resolver.resolve(&a.sid);
            }
        }
    }

    let mut stats = sc.stats;
    stats.folders_reported = sc.folders.len() as u64;
    stats.duration_ms = t0.elapsed().as_millis() as u64;
    info!(
        "Scan beendet: {} Ordner gescannt, {} gemeldet, {} ausgeschlossen, {} Fehler, {} verwaiste ACEs ({:.1}s)",
        stats.folders_scanned,
        stats.folders_reported,
        stats.folders_excluded,
        stats.errors,
        stats.orphaned_aces,
        stats.duration_ms as f64 / 1000.0
    );

    Ok(ScanReport {
        schema_version: REPORT_SCHEMA_VERSION,
        scan_id: Uuid::new_v4(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        host,
        started_at,
        finished_at: Utc::now(),
        report_mode: cfg.report_mode,
        roots,
        shares: share_list,
        folders: sc.folders,
        principals: sc.resolver.into_principals(),
        errors: sc.errors,
        stats,
    })
}
