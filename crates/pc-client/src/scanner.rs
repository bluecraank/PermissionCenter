//! Rekursiver Berechtigungsscan über Laufwerke, Freigaben und UNC-Pfade.
//!
//! Im Modus `relevant` werden nur Ordner gemeldet, die vom Elternordner
//! abweichen (eigene ACEs, unterbrochene Vererbung, Fehler, verwaister Besitzer)
//! sowie deren Vorfahren und die oberen `skeleton_depth` Ebenen. Alle übrigen
//! Ordner erben exakt die Rechte ihres `acl_source_id`-Vorfahren.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::Result;
use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::ScanConfig;
use crate::exclude::ExcludeSet;
use crate::win::{fs, groups, resolver::SidResolver, shares, system};
use pc_common::{
    wellknown, FileRecord, FolderRecord, PrincipalInfo, ReportMode, RootKind, ScanError,
    ScanReport, ScanRoot, ScanStats, ShareInfo, REPORT_SCHEMA_VERSION,
};

/// Stapelgröße der Scanner-Threads (tiefe Verzeichnisbäume, rekursiv).
const SCANNER_STACK: usize = 128 * 1024 * 1024;

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
    /// Dateien mit eigenen Berechtigungen (Dateiebene)
    files: Vec<FileRecord>,
    /// Normalisierte Pfade, unter denen Dateien geprüft werden
    file_paths: Vec<String>,
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
            files: Vec::new(),
            file_paths: cfg.file_acl_paths.iter().map(|p| norm(p)).collect(),
        }
    }

    /// Liegt der Ordner unter einem Pfad der Dateiebene?
    fn file_level(&self, path: &str) -> bool {
        let p = norm(path);
        self.file_paths.iter().any(|f| {
            p == *f
                || (f.ends_with('\\') && p.starts_with(f.as_str()))
                || p.starts_with(&format!("{f}\\"))
        })
    }

    /// Prüft die Dateien eines Ordners und merkt sich die mit eigenen Berechtigungen.
    fn scan_files(&mut self, folder: &str, folder_id: u64, names: &[String]) -> bool {
        let mut found = false;
        for name in names {
            let path = join(folder, name);
            let sec = match fs::open_dir(&path, false).and_then(|h| fs::read_security(&h)) {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("Datei {path}: {e}");
                    continue;
                }
            };
            if !sec.protected && sec.aces.iter().all(|a| a.inherited) {
                continue;
            }
            for a in sec.aces.iter().filter(|a| !a.inherited) {
                if self.resolver.is_orphaned(&a.sid) {
                    self.stats.orphaned_aces += 1;
                }
            }
            self.stats.files_with_explicit_aces += 1;
            self.files.push(FileRecord {
                folder_id,
                name: name.clone(),
                owner_sid: sec.owner_sid,
                inheritance_protected: sec.protected,
                aces: sec.aces,
            });
            found = true;
        }
        found
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
        let mut file_names = Vec::new();
        let check_files = !self.file_paths.is_empty() && self.file_level(&rec.path);
        match entries {
            Ok(list) => {
                for e in list {
                    if !e.is_dir() {
                        rec.file_count += 1;
                        rec.file_bytes += e.size;
                        if check_files && !e.is_reparse() {
                            file_names.push(e.name);
                        }
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

        let has_files = !file_names.is_empty() && self.scan_files(&rec.path, id, &file_names);
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
            || has_files
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

/// Ergebnis eines einzelnen Roots (eigener Scanner, eigene IDs ab 1).
struct Part {
    root: ScanRoot,
    folders: Vec<FolderRecord>,
    files: Vec<FileRecord>,
    stats: ScanStats,
    errors: Vec<ScanError>,
    path_ids: HashMap<String, u64>,
    principals: Vec<PrincipalInfo>,
    last_id: u64,
}

fn scan_part(
    cfg: &ScanConfig,
    path: &str,
    kind: RootKind,
    forced: &HashSet<String>,
    max_logged_errors: u64,
) -> Part {
    let mut sc = Scanner::new(cfg);
    sc.forced = forced.clone();
    sc.max_logged_errors = max_logged_errors;
    let root = sc.scan_root(path, kind);
    Part {
        root,
        folders: sc.folders,
        files: sc.files,
        stats: sc.stats,
        errors: sc.errors,
        path_ids: sc.path_ids,
        principals: sc.resolver.into_principals(),
        last_id: sc.next_id - 1,
    }
}

/// Scannt mehrere Roots, bis zu `scan.parallel_roots` gleichzeitig.
fn scan_parts(
    cfg: &ScanConfig,
    jobs: Vec<(String, RootKind)>,
    forced: &HashSet<String>,
    max_logged_errors: u64,
) -> Vec<Part> {
    let workers = cfg.parallel_roots.clamp(1, 16).min(jobs.len());
    if workers <= 1 {
        return jobs
            .iter()
            .map(|(p, k)| scan_part(cfg, p, *k, forced, max_logged_errors))
            .collect();
    }
    info!("{} Bereiche, bis zu {workers} gleichzeitig", jobs.len());
    let n = jobs.len();
    let queue: Mutex<VecDeque<(usize, String, RootKind)>> = Mutex::new(
        jobs.into_iter()
            .enumerate()
            .map(|(i, (p, k))| (i, p, k))
            .collect(),
    );
    let results: Mutex<Vec<Option<Part>>> = Mutex::new((0..n).map(|_| None).collect());
    let span = tracing::Span::current();
    std::thread::scope(|scope| {
        for w in 0..workers {
            let (queue, results, span) = (&queue, &results, span.clone());
            std::thread::Builder::new()
                .name(format!("scanner-{}", w + 1))
                .stack_size(SCANNER_STACK)
                .spawn_scoped(scope, move || {
                    span.in_scope(|| loop {
                        let next = queue.lock().expect("Warteschlange").pop_front();
                        let Some((i, p, k)) = next else {
                            break;
                        };
                        let part = scan_part(cfg, &p, k, forced, max_logged_errors);
                        results.lock().expect("Ergebnisse")[i] = Some(part);
                    })
                })
                .expect("Scanner-Thread");
        }
    });
    results
        .into_inner()
        .expect("Ergebnisse")
        .into_iter()
        .flatten()
        .collect()
}

fn add_stats(a: &mut ScanStats, b: &ScanStats) {
    a.folders_scanned += b.folders_scanned;
    a.folders_excluded += b.folders_excluded;
    a.folders_with_explicit_aces += b.folders_with_explicit_aces;
    a.folders_inheritance_protected += b.folders_inheritance_protected;
    a.reparse_points_skipped += b.reparse_points_skipped;
    a.files_seen += b.files_seen;
    a.errors += b.errors;
    a.orphaned_aces += b.orphaned_aces;
    a.files_with_explicit_aces += b.files_with_explicit_aces;
}

/// Gesamtergebnis: Teile mit fortlaufenden IDs zusammengeführt.
#[derive(Default)]
struct Merged {
    roots: Vec<ScanRoot>,
    folders: Vec<FolderRecord>,
    files: Vec<FileRecord>,
    stats: ScanStats,
    errors: Vec<ScanError>,
    path_ids: HashMap<String, u64>,
    principals: HashMap<String, PrincipalInfo>,
    next_id: u64,
}

impl Merged {
    fn add(&mut self, parts: Vec<Part>) {
        for mut p in parts {
            let off = self.next_id;
            for f in p.folders.iter_mut() {
                f.id += off;
                f.parent_id = f.parent_id.map(|v| v + off);
                f.acl_source_id = f.acl_source_id.map(|v| v + off);
            }
            for f in p.files.iter_mut() {
                f.folder_id += off;
            }
            p.root.folder_id = p.root.folder_id.map(|v| v + off);
            for (k, v) in p.path_ids {
                self.path_ids.entry(k).or_insert(v + off);
            }
            for x in p.principals {
                self.principals.entry(x.sid.clone()).or_insert(x);
            }
            add_stats(&mut self.stats, &p.stats);
            self.roots.push(p.root);
            self.folders.extend(p.folders);
            self.files.extend(p.files);
            self.errors.extend(p.errors);
            self.next_id += p.last_id;
        }
    }
}

/// Direkte Mitglieder der lokalen Administratorengruppe.
fn local_admins() -> Option<Vec<PrincipalInfo>> {
    let mut resolver = SidResolver::new();
    let group = resolver
        .resolve(wellknown::BUILTIN_ADMINISTRATORS)
        .name
        .clone()
        .unwrap_or_else(|| "Administratoren".into());
    match groups::members(&group) {
        Ok(list) => {
            let out: Vec<PrincipalInfo> =
                list.iter().map(|s| resolver.resolve(s).clone()).collect();
            info!("{} Mitglieder in der lokalen Gruppe {group}", out.len());
            Some(out)
        }
        Err(e) => {
            warn!("Lokale Administratoren nicht ermittelbar: {e}");
            None
        }
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
        .stack_size(SCANNER_STACK)
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
    info!(
        "{} Ausschlussregeln aktiv",
        ExcludeSet::new(&cfg.exclude).len()
    );
    if !cfg.file_acl_paths.is_empty() {
        info!("Dateiebene aktiv für: {}", cfg.file_acl_paths.join(", "));
    }

    let mut share_list: Vec<ShareInfo> = Vec::new();
    let mut forced = HashSet::new();
    if paths.is_empty() && cfg.shares {
        match shares::enumerate() {
            Ok(s) => share_list = s,
            Err(e) => warn!("Freigaben nicht ermittelbar: {e}"),
        }
        for s in share_list
            .iter()
            .filter(|s| shares::is_disk_share(s) && !s.is_special)
        {
            forced.insert(norm(&s.path));
        }
        info!("{} Freigaben gefunden", share_list.len());
    }

    let mut m = Merged::default();
    if !paths.is_empty() {
        let jobs = paths
            .iter()
            .map(|p| {
                let kind = if p.starts_with("\\\\") {
                    RootKind::Remote
                } else {
                    RootKind::LocalDrive
                };
                (p.clone(), kind)
            })
            .collect();
        m.add(scan_parts(cfg, jobs, &forced, max_logged_errors));
    } else {
        if cfg.local_drives {
            let wanted: Vec<String> = cfg
                .drives
                .iter()
                .map(|d| d.trim_end_matches('\\').to_uppercase())
                .collect();
            let jobs = system::drives(system::DRIVE_FIXED)
                .into_iter()
                .filter(|d| wanted.is_empty() || wanted.contains(d))
                .map(|d| (d, RootKind::LocalDrive))
                .collect();
            m.add(scan_parts(cfg, jobs, &forced, max_logged_errors));
        }
        // Freigaben, deren Pfad noch nicht erfasst wurde (z. B. unter ausgeschlossenen Ordnern wie SYSVOL)
        let jobs = share_list
            .iter()
            .filter(|s| shares::is_disk_share(s) && !s.is_special)
            .filter(|s| !s.path.is_empty() && !m.path_ids.contains_key(&norm(&s.path)))
            .map(|s| (s.path.clone(), RootKind::Share))
            .collect();
        m.add(scan_parts(cfg, jobs, &forced, max_logged_errors));
        let mut jobs: Vec<(String, RootKind)> = Vec::new();
        if cfg.mapped_drives {
            jobs.extend(
                system::drives(system::DRIVE_REMOTE)
                    .into_iter()
                    .map(|d| (d, RootKind::Remote)),
            );
        }
        jobs.extend(
            cfg.extra_paths
                .iter()
                .map(|p| (p.clone(), RootKind::Remote)),
        );
        m.add(scan_parts(cfg, jobs, &forced, max_logged_errors));
    }

    let mut resolver = SidResolver::new();
    for s in share_list.iter_mut() {
        s.folder_id = m.path_ids.get(&norm(&s.path)).copied();
        if let Some(perms) = &s.permissions {
            for a in perms {
                if !m.principals.contains_key(&a.sid) {
                    resolver.resolve(&a.sid);
                }
            }
        }
    }
    let local_admins = local_admins();
    for x in resolver
        .into_principals()
        .into_iter()
        .chain(local_admins.iter().flatten().cloned())
    {
        m.principals.entry(x.sid.clone()).or_insert(x);
    }

    let mut stats = m.stats;
    stats.folders_reported = m.folders.len() as u64;
    stats.duration_ms = t0.elapsed().as_millis() as u64;
    info!(
        "Scan beendet: {} Ordner gescannt, {} gemeldet, {} ausgeschlossen, {} Fehler, {} verwaiste ACEs, {} Dateien mit eigenen Rechten ({:.1}s)",
        stats.folders_scanned,
        stats.folders_reported,
        stats.folders_excluded,
        stats.errors,
        stats.orphaned_aces,
        stats.files_with_explicit_aces,
        stats.duration_ms as f64 / 1000.0
    );
    let mut principals: Vec<PrincipalInfo> = m.principals.into_values().collect();
    principals.sort_by(|a, b| a.sid.cmp(&b.sid));

    Ok(ScanReport {
        schema_version: REPORT_SCHEMA_VERSION,
        scan_id: Uuid::new_v4(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        host,
        started_at,
        finished_at: Utc::now(),
        report_mode: cfg.report_mode,
        roots: m.roots,
        shares: share_list,
        folders: m.folders,
        principals,
        errors: m.errors,
        stats,
        files: m.files,
        local_admins,
    })
}
