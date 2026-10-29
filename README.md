# PermissionCenter

Berechtigungsanalyse für Windows-Dateiserver und Active Directory.

- **PermissionCenter-Client** (`pc-client`, Rust): scannt auf Windows Server 2016–2025 alle Ordner der lokalen Laufwerke und Freigaben, erkennt verwaiste Einträge, bildet Berechtigungsstränge und überträgt die Ergebnisse an den Server.
- **PermissionCenter-Server** (`pc-server`, Rust + PostgreSQL): sammelt die Ergebnisse, gleicht sie mit dem AD ab, erkennt Zusammenhänge sowie verwaiste Benutzer und Gruppen. Er bewertet die Systeme (Audit), gibt Empfehlungen und visualisiert die IT-Landschaft in einer Weboberfläche (React, Tailwind CSS 4, shadcn/ui).

```
 Windows-Server (2016–2025)                       Docker-Host
┌──────────────────────────────┐   HTTPS/JSON   ┌───────────────────────────────┐
│ pc-client  (Dienst/Aufgabe)  │ ─────────────▶ │ pc-server  (axum, Web-UI)     │
│  • NTFS-/Freigabe-ACLs       │   gzip, Token  │  • Analyse, Audit, Empfehlung │
│  • lokale SQLite + Outbox    │ ◀───────────── │  • LDAP-Abgleich / AD-Import  │
│  • Logdateien                │   OTA-Updates  │  • Client-Releases (signiert) │
└──────────────────────────────┘                └──────────────┬────────────────┘
                                                               │
                                                       ┌───────▼────────┐
                                                       │ PostgreSQL 17  │
                                                       └────────────────┘
```

## Funktionen

| Bereich | Umfang |
|---|---|
| Scan | Alle festen Laufwerke, lokale Freigaben (inkl. Freigabeberechtigungen), optional Netzlaufwerke/UNC-Pfade. Pfade über 260 Zeichen, `SeBackupPrivilege` (liest auch Ordner ohne Admin-Zugriff), Junctions werden nicht verfolgt |
| Ausschlüsse | Systemordner (`C:\Windows`, `Program Files`, `ProgramData`, `$Recycle.Bin`, `System Volume Information`, `AppData` …), Platzhalter, `%VAR%`, Ordner mit Attribut System+Versteckt |
| Verzeichnisstränge | Jeder Ordner kennt seinen `acl_source` (nächster Vorfahr mit eigenen Rechten). Übertragen werden nur Ordner mit abweichenden Rechten, ihre Vorfahren und die obersten Ebenen; alle anderen erben exakt |
| Verwaiste Einträge | Nicht auflösbare SIDs (Client) und Domänen-SIDs, die im AD nicht mehr existieren (Server); auch verwaiste Besitzer |
| Active Directory | LDAP-Synchronisation (auch periodisch) oder JSON-Import (`tools/Export-ADData.ps1`): Benutzer, Computer, Gruppen, verschachtelte Mitgliedschaften |
| Analyse | 18 Prüfregeln, z. B. verwaiste SIDs, Schreibrechte für „Jeder“, offene Freigaben, deaktivierte/inaktive Benutzer mit Rechten, Direktberechtigungen statt AGDLP, leere/verwaiste/ungenutzte Gruppen |
| Audit | Punktwert 0–100 und Note A–F je System, für das AD und gesamt; Checkliste bestanden/nicht bestanden |
| Empfehlungen | Priorisierte Maßnahmen je Regel mit Aufwandsschätzung und betroffenen Systemen |
| Zusammenhänge | Für jeden Benutzer und jede Gruppe: direkte Zugriffe, Zugriffe über (verschachtelte) Gruppen, Mitglieder, Befunde |
| Visualisierung | Interaktive Graphen: IT-Landschaft (Domäne → Systeme → Freigaben ↔ Gruppen), Berechtigungsstränge je System, Beziehungen je Prinzipal |
| Betrieb | Docker Compose mit PostgreSQL, Client als Windows-Dienst oder geplante Aufgabe, signierte OTA-Updates, rotierende Logdateien |

## Schnellstart Server (Docker Compose)

```bash
cp .env.example .env          # POSTGRES_PASSWORD und PC_API_TOKENS setzen
docker compose up -d --build
# Web-Oberfläche: http://<docker-host>:8080
```

Die Datenbank liegt im Volume `pgdata`, die Client-Releases liegen in `releases`. Das Schema legt der Server beim Start selbst an.

AD anbinden, Variante 1 (LDAP): in `.env` die Werte `PC_LDAP_URL`, `PC_LDAP_BIND_DN`, `PC_LDAP_BIND_PASSWORD`, `PC_LDAP_BASE_DN` und optional `PC_LDAP_SYNC_INTERVAL_MINUTES` setzen, dann in der Oberfläche unter *Active Directory → LDAP synchronisieren* abgleichen.
Variante 2 (Export auf einem DC):

```powershell
.\tools\Export-ADData.ps1 -Server http://<docker-host>:8080
```

## Client installieren

Voraussetzung: `pc-client.exe` (Build siehe unten) und das Skript `tools\Install-PcClient.ps1` im selben Ordner. Als Administrator ausführen:

```powershell
# Als Windows-Dienst (empfohlen): täglicher Scan um 02:00, stündliche Update-Prüfung
.\Install-PcClient.ps1 -ServerUrl http://permcenter:8080 -ApiToken <token> -PublicKey <öffentlicher-schlüssel>

# Alternativ als geplante Aufgabe
.\Install-PcClient.ps1 -ServerUrl http://permcenter:8080 -ApiToken <token> -Mode Task -At 02:30

# Entfernen
.\Install-PcClient.ps1 -Uninstall
```

Dabei passiert Folgendes: Die EXE kommt nach `%ProgramFiles%\PermissionCenter`. Konfiguration, lokale Datenbank und Logs liegen unter `%ProgramData%\PermissionCenter`; dieser Ordner ist nur für SYSTEM und Administratoren zugänglich.

### Befehle

| Befehl | Zweck |
|---|---|
| `pc-client scan [--path D:\Daten] [--no-upload] [--mode full]` | Scan, lokal speichern, hochladen |
| `pc-client upload` | Ausstehende Scans erneut senden (Outbox) |
| `pc-client status` / `orphans` | Lokale Scan-Historie / verwaiste SIDs des letzten Scans |
| `pc-client update [--check]` | OTA-Update prüfen/installieren |
| `pc-client logs [-n 100] [--errors]` | Letzte Logzeilen |
| `pc-client service install\|uninstall\|start\|stop` | Windows-Dienst verwalten |
| `pc-client info` | Diagnose: System, Laufwerke, Freigaben, Rechte |
| `pc-client init-config [--out datei]` | Kommentierte Konfigurationsvorlage |
| `pc-client export --scan latest --out report.json` | Report als JSON |

## Konfiguration

Beide Programme nutzen TOML-Dateien: `schlüssel = wert`, Abschnitte und Kommentare. Kommentierte Vorlagen liegen unter [config/](config/):

- [config/pc-client.example.toml](config/pc-client.example.toml), wird mit `pc-client init-config` erzeugt. Abschnitte: `[server]`, `[scan]`, `[storage]`, `[update]`, `[logging]`, `[service]`
- [config/pc-server.example.toml](config/pc-server.example.toml). Beim Server kann zusätzlich jeder wichtige Wert per Umgebungsvariable `PC_*` überschrieben werden; das ist der Standardweg unter Docker, siehe [.env.example](.env.example).

## OTA-Updates des Clients

1. Einmalig ein Schlüsselpaar erzeugen und den privaten Schlüssel sicher verwahren (nicht auf dem Server):
   ```bash
   pc-server gen-signing-key --out permcenter-signing.key
   ```
2. Den öffentlichen Schlüssel beim Server (`PC_CLIENT_UPDATE_PUBLIC_KEY`) und in den Clients (`[update] public_key`, Installationsparameter `-PublicKey`) eintragen.
3. Eine neue Version bauen, lokal signieren und auf den Server hochladen (der private Schlüssel verlässt deinen Rechner nicht):
   ```powershell
   # Version in Cargo.toml ([workspace.package] version) erhöhen, CHANGELOG pflegen
   cargo build --release -p pc-client -p pc-server
   .\target\release\pc-server.exe publish-client `
       --file .\target\release\pc-client.exe --version 0.2.0 `
       --signing-key C:\Sicher\permcenter-signing.key `
       --server http://permcenter:8080 --token <ein Wert aus PC_API_TOKENS> --notes "…"
   ```
   Ohne `--server` legt `publish-client` das Release im lokalen `client_releases_dir` ab (z. B. direkt auf dem Server).
   Rohe API: `POST /api/v1/client/releases?version=0.2.0&signature=…` mit `X-Api-Key` und der EXE als Body.

Die Clients prüfen vor jedem Scan bzw. im Dienst in festen Abständen. Bevor ein Update installiert wird, müssen **Größe, SHA-256 und Ed25519-Signatur** stimmen; die Signatur deckt Version und Inhalt gemeinsam ab, ein Downgrade mit einer alten Signatur ist also nicht möglich. Danach tauscht der Client seine EXE aus und startet neu. Der Dienst beendet sich dazu mit Code 10, die Dienst-Wiederherstellung startet ihn wieder. Ohne `public_key` verweigert der Client Updates, solange `require_signature = true` gilt (Standard).

## Logging (Client)

- Tägliche Logdatei `%ProgramData%\PermissionCenter\logs\pc-client.JJJJ-MM-TT.log`, Aufbewahrung 30 Tage (`[logging]`)
- Jede Zeile enthält lokale Zeit, Level, Thread, eine **Lauf-ID** und den Befehl, z. B.
  `2026-10-29 15:36:35.716  WARN ThreadId(04) run{id=e2a818da cmd=scan}: pc_client::scanner: Lesefehler D:\Daten\X: Zugriff verweigert (Code 5)`
- Protokolliert werden Startzeile (Version, PID, Konto, Adminrechte), Konfiguration, Privilegien, jede Scan-Wurzel, Lesefehler (bis `max_logged_scan_errors`), Fortschritt, Zusammenfassung, Upload (mit HTTP-Status), alle Update-Schritte, die Fehlerursachenkette und Abstürze (Panic mit Ort und Backtrace)
- Schnell ansehen mit `pc-client logs --errors`

## Entwicklung

Voraussetzungen: Rust ≥ 1.85, Node.js ≥ 20, PostgreSQL ≥ 15 (für den Server).

```bash
cargo test --workspace                       # Unit-Tests
cd web && npm ci && npm run build && cd ..   # Web-UI bauen (wird ins Server-Binary eingebettet)
cargo build --release                        # target/release/pc-server(.exe), pc-client.exe

# Server lokal
PC_DATABASE_URL=postgres://user:pw@localhost:5432/permcenter cargo run -p pc-server
# UI mit Hot-Reload (Proxy auf :8080)
cd web && npm run dev
```

Den Client unter Windows mit dem MSVC-Toolchain bauen. Die CRT wird statisch gelinkt (`.cargo/config.toml`), deshalb ist auf den Servern kein VC++-Redistributable nötig.

### Demodaten

```bash
python tools/demo/generate_demo.py demo/
pc-server import-ad demo/ad-demo.json
pc-server import-report demo/report-fs01.json
pc-server import-report demo/report-fs02.json
```

## Projektstruktur

```
crates/pc-common   Gemeinsames Datenmodell (Report, ACE, AD), Rechte, SIDs, Release-Signaturen
crates/pc-client   Windows-Client: Scanner, Win32-Zugriff, lokale DB, Upload, Dienst, OTA, Logging
crates/pc-server   Server: REST-API, PostgreSQL, Analyse, AD/LDAP, Releases, eingebettete UI
web/               Web-Oberfläche (React, Vite, Tailwind CSS 4, shadcn/ui, Cytoscape.js)
tools/             Install-PcClient.ps1, Export-ADData.ps1, Demodaten-Generator
config/            Kommentierte Beispielkonfigurationen
docs/              Aufgabenstellung, Architektur, Anforderungs-Mapping, Arbeitsprotokoll
```

Weitere Dokumentation: [Architektur](docs/ARCHITEKTUR.md) · [Anforderungen ↔ Umsetzung](docs/ANFORDERUNGEN.md) · [Arbeitsprotokoll](docs/PROTOKOLL.md) · [Changelog](CHANGELOG.md)

## Sicherheitshinweise

- Die Weboberfläche hat **noch keinen Login** (so in der Aufgabenstellung vorgesehen; die AD-Authentifizierung ist vorbereitet). Den Server deshalb nur im internen Netz betreiben bzw. hinter einen Reverse-Proxy mit Zugriffsschutz stellen.
- Für die Clients immer `api_tokens` setzen und den Server per TLS bereitstellen (Reverse-Proxy).
- Den privaten Signaturschlüssel nicht auf dem Server ablegen.
