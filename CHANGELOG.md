# Changelog

Alle nennenswerten Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/),
und dieses Projekt hält sich an [Semantic Versioning](https://semver.org/lang/de/).

## [Unreleased]

### Hinzugefügt
- **Audit-Assist** (Weboberfläche und API `/api/v1/assist`): arbeitet alle offenen Befunde Schritt für Schritt ab, mit Anleitung, betroffenen Objekten und einem PowerShell-Skript je Befund. Das Skript läuft standardmäßig als Probelauf, ändert erst mit `-Apply` und sichert vorher ACLs bzw. AD-Objekte
- Bearbeitungsstand je Befund (erledigt, Ausnahme mit Begründung), der Neuberechnungen überdauert. Der nächste Scan bzw. AD-Abgleich bestätigt Behebungen automatisch
- Einstieg in den Audit-Assist über Dashboard, Audit und Befundliste; Kennzeichnung von Ausnahmen in Befundliste und Audit
- `pc-server publish-client --server <url> --token <token>`: Client-Release lokal signieren und per API auf einen entfernten Server hochladen

### Behoben
- `Install-PcClient.ps1` brach unter Windows PowerShell 5.1 mit `NativeCommandError` ab, sobald der Client Logzeilen auf stderr schrieb

### Geändert
- Als Ausnahme akzeptierte Befunde zählen nicht mehr in Bewertung, Audit, Empfehlungen und Dashboard-Statistik
- Datenbankschema Version 2 (`findings.fingerprint`, Tabelle `finding_states`). Die Migration erfolgt beim Start automatisch
- Verwaltungszeilen eines Client-Laufs (Start, Konfiguration, Dauer) erscheinen nur noch in der Logdatei, nicht mehr auf der Konsole

## [0.1.0] - 2026-10-29

### Hinzugefügt

#### Client (`pc-client`)
- Berechtigungsscan aller festen Laufwerke, lokaler Freigaben (inkl. Freigabeberechtigungen), optional verbundener Netzlaufwerke und UNC-Pfade auf Windows Server 2016–2025
- Lesen über `SeBackupPrivilege` und Backup-Semantik, Long-Path-Unterstützung, Junctions/Reparse-Points werden nicht verfolgt
- Ausschluss systembekannter Ordner (Platzhalter `?:`/`*`, Umgebungsvariablen, Attribut System+Versteckt)
- Verzeichnisstränge: `acl_source_id` je Ordner, Report-Modus `relevant` (nur abweichende Ordner und Gerüst) oder `full`
- Erkennung verwaister SIDs und Besitzer (lokale SID-Auflösung)
- Lokale SQLite-Datenbank mit Scan-Historie, normalisierten Ergebnissen und Upload-Warteschlange (Outbox)
- gzip-komprimierter Upload mit API-Token
- Betrieb als Windows-Dienst (`service install|uninstall|start|stop`) mit Zeitplan und automatischem Neustart, alternativ als geplante Aufgabe (`tools/Install-PcClient.ps1`)
- OTA-Selbstaktualisierung mit SHA-256- und Ed25519-Signaturprüfung (`update`, automatisch vor Scans bzw. im Dienst)
- Rotierende Tageslogdateien mit Lauf-ID, Fehlerursachenketten, Lesefehlern und Absturzprotokoll; Befehl `logs`
- Kommentierte TOML-Konfigurationsvorlage (`init-config`), Diagnosebefehle `info`, `status`, `orphans`, `export`

#### Server (`pc-server`)
- REST-API zur Annahme der Client-Reports (gzip, Token, Duplikaterkennung, ältere Scans nur als Historie)
- PostgreSQL-Datenbank mit automatischem Schema, Massenimport per `COPY BINARY`
- Active Directory: LDAP-Synchronisation (auch periodisch, paged search, Primärgruppen) und JSON-Import (`tools/Export-ADData.ps1`)
- Analyse-Engine mit 18 Regeln für Dateisysteme, Freigaben und AD, inklusive verwaister Benutzer und Gruppen
- Audit mit Punktwert und Note je System, für das AD und gesamt; priorisierte Empfehlungen
- Zusammenhangsanalyse: direkte und über verschachtelte Gruppen vererbte Zugriffe je Prinzipal
- Graph-API für Landschaft, Systemstruktur und Prinzipal-Beziehungen
- Verwaltung von Client-Releases für OTA-Updates (`gen-signing-key`, `publish-client`, API)
- Vorbereitete AD-Authentifizierung (`auth.mode`), Login derzeit deaktiviert
- Konfiguration per TOML und Umgebungsvariablen `PC_*`, Unterbefehle `import-ad`, `import-report`, `sync-ad`, `analyze`, `healthcheck`

#### Web-Oberfläche
- React + Vite + Tailwind CSS 4 + shadcn/ui (Radix UI), hell/dunkel, eingebettet in das Server-Binary
- Dashboard, Systeme mit Verzeichnisbaum/ACL-Details/Freigaben/Strukturgraph/Scan-Historie, Befunde mit Filtern, Audit, Empfehlungen, Benutzer & Gruppen, Prinzipal-Details mit Zusammenhangsgraph, Active Directory, IT-Landschaft, Einstellungen mit Client-Update-Übersicht

#### Betrieb
- `Dockerfile` (Multi-Stage) und `docker-compose.yml` mit PostgreSQL 17, Healthchecks und Volumes
- Demodaten-Generator `tools/demo/generate_demo.py`
