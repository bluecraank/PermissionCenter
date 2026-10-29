# Anforderungen ↔ Umsetzung

Stand: 2026-10-29 (Version 0.1.0). Bezug: [AUFGABENSTELLUNG.md](AUFGABENSTELLUNG.md) und Nachträge aus der Abstimmung.

## PermissionCenter-Client

| Anforderung | Umsetzung | Getestet |
|---|---|---|
| Rust-Client für Windows Server 2016–2025 | `crates/pc-client`, Win32 über `windows`-Crate, statische CRT; nur APIs ab Windows 8/Server 2012 | Build + Lauf auf Windows 11; Server-Versionen nicht verfügbar |
| Mit lokaler DB | SQLite (`localdb.rs`): Scans, Ordner, ACEs, Freigaben, Prinzipale, Outbox | ✔ Scan, Status, Orphans, Upload-Wiederholung |
| Scannt alle Ordner von Laufwerken auf Berechtigungen | `scanner.rs`, `win/fs.rs`: alle festen Laufwerke, DACL + Besitzer + Vererbung | ✔ Testbaum mit icacls/Set-Acl |
| … verwaiste Einträge | SID-Auflösung (`win/resolver.rs`), verwaiste ACEs und Besitzer; serverseitig AD-Abgleich | ✔ verwaiste SID erkannt |
| Generiert Verzeichnisstränge und Abhängigkeiten | `acl_source_id`, Eltern-Kette, `subfolder_total`; Server: Baum, Strang-Ursprung, Strukturgraph | ✔ API + UI |
| Schließt systembekannte Ordner aus | `exclude.rs` + Standardliste, System+Versteckt-Attribut | ✔ Unit-Tests |
| Scannt alle Netzlaufwerke (freigegebene Ordner) | `win/shares.rs` (NetShareEnum 502 inkl. Freigabe-ACL), optional verbundene Laufwerke und UNC-Pfade | ✔ Aufzählung; Freigabe-SD nur als Admin |
| Liefert Ergebnisse an zentrales Programm | `upload.rs`: gzip-JSON + Token an `/api/v1/reports` | ✔ inkl. 401 bei falschem Token |
| *Nachtrag:* OTA-Updates | `update.rs`, Server `releases.rs`: SHA-256 + Ed25519, Selbstaustausch, Neustart | ✔ Ablehnung unsigniert/falscher Schlüssel, Installation, Aufräumen, Auto-Update vor Scan |
| *Nachtrag:* als Windows-Dienst | `service.rs`: install/uninstall/start/stop/run, Zeitplan, Wiederherstellung | ⚠ Kompiliert; Installation hier nicht ausführbar (Adminrechte/Sandbox) |
| *Nachtrag:* sehr gutes Log | `logging.rs`: rotierende Tageslogs, Lauf-ID, Ursachenketten, Panic-Hook, `logs`-Befehl | ✔ |
| *Nachtrag:* menschenfreundliche Konfiguration | TOML mit kommentierter Vorlage (`init-config`) | ✔ Vorlage = Standardwerte (Test) |

## PermissionCenter-Server

| Anforderung | Umsetzung | Getestet |
|---|---|---|
| Webanwendung mit moderner UI (shadcn/ui, Radix, Tailwind 4) | `web/`, eingebettet in `pc-server` | ✔ Typprüfung + Build, Auslieferung/SPA-Routing; ⚠ nicht visuell geprüft |
| AD-Authentifizierung (erstmal kein Login) | `auth.mode` (`none`/`ldap`), `ad::verify_credentials`, `/api/v1/auth/status` | ✔ Status-Endpunkt; Login bewusst nicht aktiv |
| Sammelt vom Client alle Informationen | `ingest.rs` (PostgreSQL, COPY BINARY), Historie | ✔ echte Scans + Demodaten |
| Analysiert und bereitet Ergebnisse auf | `analysis.rs` (18 Regeln), Dashboard-/Systemauswertungen | ✔ alle Regeln mit Demodaten ausgelöst |
| Erkennt Zusammenhänge | `directory.rs` (transitive Gruppen), `/principals/{sid}`, Graph-Modi | ✔ |
| Kennt alle AD-User und AD-Gruppen | `ad.rs`: LDAP (paged) + JSON-Import, `Export-ADData.ps1` | ✔ Import; ⚠ LDAP ohne Test-AD nicht geprüft |
| Kann verwaiste User/Gruppen erkennen | `ORPHANED_SID`, `AD_ORPHANED_GROUP`, `AD_EMPTY_GROUP`, `AD_UNUSED_GROUP`, deaktiviert/inaktiv | ✔ |
| Auditing-Tool zur Bewertung | `/api/v1/audit`, Punktwert/Note, Checkliste, Druckansicht | ✔ |
| Kann Empfehlungen ausgeben | `/api/v1/recommendations`, priorisiert | ✔ |
| Visualisiert die IT-Landschaft | Cytoscape-Graphen: Landschaft, System, Prinzipal | ✔ API; ⚠ nicht visuell geprüft |
| Docker-Compose-fähig | `Dockerfile`, `docker-compose.yml`, `.env.example`, Healthcheck | ⚠ Docker hier nicht installiert – nicht gebaut |
| Eigene schnelle Datenbank | PostgreSQL 17 als eigener Dienst (Entscheidung Auftraggeber), COPY BINARY, Indizes | ✔ gegen PostgreSQL 17.7 getestet |

## Changelog

| Anforderung | Umsetzung |
|---|---|
| Keep a Changelog + SemVer | [CHANGELOG.md](../CHANGELOG.md), Version 0.1.0 in allen Paketen |
