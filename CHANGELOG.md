# Changelog

Alle nennenswerten Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/),
und dieses Projekt hält sich an [Semantic Versioning](https://semver.org/lang/de/).

## [Unreleased]

## [0.2.0] - 2026-10-29

### Hinzugefügt
- **Audit-Assist** (Weboberfläche und API `/api/v1/assist`): arbeitet alle offenen Befunde Schritt für Schritt ab, mit Anleitung, betroffenen Objekten und einem PowerShell-Skript je Befund. Das Skript läuft standardmäßig als Probelauf, ändert erst mit `-Apply` und sichert vorher ACLs bzw. AD-Objekte
- Bearbeitungsstand je Befund (erledigt, Ausnahme mit Begründung), der Neuberechnungen überdauert. Der nächste Scan bzw. AD-Abgleich bestätigt Behebungen automatisch
- Einstieg in den Audit-Assist über Dashboard, Audit und Befundliste; Kennzeichnung von Ausnahmen in Befundliste und Audit
- `pc-server publish-client --server <url> --token <token>`: Client-Release lokal signieren und per API auf einen entfernten Server hochladen
- `pc-server publish-client --signature <Base64>`: Release mit bereits vorhandener Signatur (z. B. aus CI) veröffentlichen
- **Änderungsverlauf**: Unterschiede zwischen zwei Scans (explizite Berechtigungen, Vererbung, Besitzer, Freigaben), nur innerhalb gemeinsamer Scan-Wurzeln; Seite „Änderungen“, Reiter je System, Filter je Prinzipal
- **Bewertungstrend**: Tageswerte je System, für Dateisysteme, AD und gesamt; Diagramme auf Dashboard und Systemseite
- **Benachrichtigungen** per E-Mail (SMTP) und Webhook (Teams, Slack, JSON): neue Befunde ab einstellbarer Schwere, Verschlechterung der Note, Systeme ohne aktuellen Scan, Wochenbericht; Testversand in den Einstellungen; stündliche Neubewertung
- **Exporte** als CSV (Excel-tauglich): Befunde, Audit, Berechtigungen je System, Änderungen, Zugriffe je Prinzipal, Zugriffsprüfung
- **Druckberichte** (bzw. PDF über den Browser): Audit-Bericht und Zugriffsbericht je Benutzer/Gruppe
- **Zugriffsprüfung**: wer hat Zugriff auf einen Pfad oder UNC-Pfad – Auflösung verschachtelter Gruppen und lokaler Administratoren bis zum Benutzer, Freigabeberechtigungen, Dateneigentümer
- **Dateneigentümer** je Ordner (gilt für Unterordner), Pflege im Verzeichnisbaum und auf eigener Seite
- AD-Prüfungen: privilegierte Konten deaktiviert/inaktiv, zu viele Mitglieder in privilegierten Gruppen, Kerberoasting (SPN an Benutzerkonto), „Kennwort läuft nie ab“, sehr alte Kennwörter, verwaiste Computerkonten – jeweils mit Audit-Assist-Anleitung
- Client erfasst die Mitglieder der lokalen Administratoren; Regeln für breite Gruppen, verwaiste SIDs und Benutzer direkt in den lokalen Administratoren
- Client-Dateiebene (`[scan] file_acl_paths`): Dateien mit eigenen Berechtigungen; Regel und Audit-Assist (Zurücksetzen auf Vererbung)
- Client scannt mehrere Laufwerke bzw. Freigaben parallel (`[scan] parallel_roots`, Standard 2)
- „Jetzt scannen“ in der Weboberfläche; der Client-Dienst fragt alle `[service] task_poll_minutes` nach Aufträgen
- GitHub Actions: CI (Formatierung, Tests, Web, Client, Docker) und Release bei Tag (signierter Client als ZIP, Server-Image in ghcr.io)
- Demodaten mit AD-Risikofällen (SPN, alte Kennwörter, verwaiste Computer, deaktivierter Domänen-Admin)

### Behoben
- Empfehlung der Regel „System nicht aktuell gescannt“ nannte ein nicht vorhandenes Skript
- `Install-PcClient.ps1` brach unter Windows PowerShell 5.1 mit `NativeCommandError` ab, sobald der Client Logzeilen auf stderr schrieb

### Geändert
- Als Ausnahme akzeptierte Befunde zählen nicht mehr in Bewertung, Audit, Empfehlungen und Dashboard-Statistik
- Datenbankschema Version 3 (u. a. `findings.fingerprint`, `finding_states`, `changes`, `score_history`, `data_owners`, `local_admins`, `files`, `scan_requests`). Die Migration erfolgt beim Start automatisch
- Report-Format um `files`, `local_admins` und `stats.files_with_explicit_aces` erweitert (abwärtskompatibel)
- AD-Export (`Export-ADData.ps1`) und LDAP-Abgleich liefern zusätzlich „Kennwort läuft nie ab“ und SPNs
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
