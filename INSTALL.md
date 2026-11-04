# PermissionCenter installieren

Diese Anleitung bringt PermissionCenter in etwa 30 Minuten zum Laufen. Eine Erklärung aller Funktionen steht in der [README.md](README.md).

## Das Prinzip in drei Sätzen

1. Ein **Server** (Docker auf einem Linux- oder Windows-Rechner) sammelt alle Daten und zeigt sie im Browser an.
2. Auf jedem **Dateiserver** läuft der **pc-client** und meldet Ordnerberechtigungen an den Server.
3. Auf einem **Domänencontroller** läuft einmal täglich der **gpo-client** und meldet die Gruppenrichtlinien.

```
Dateiserver (pc-client) ──┐
Dateiserver (pc-client) ──┼──►  PermissionCenter-Server  ◄── Browser
Domänencontroller         │     (Docker + Datenbank)
  (gpo-client) ───────────┘
```

Reihenfolge: **Server → Active Directory → Clients → GPOs**. Jeden Schritt kann man einzeln testen.

---

## Was du brauchst

| Wofür | Was |
|---|---|
| Server | Ein Rechner mit **Docker** und **Docker Compose** (ca. 2 GB RAM, Platz je nach Menge der Ordner), von den Clients per Netzwerk erreichbar |
| Dateiserver | Windows Server 2016 bis 2025, Administratorrechte |
| Domänencontroller | Windows Server mit GPMC/RSAT (auf jedem DC vorhanden), Domänen-Administrator |
| Zum Bauen der Programme | **Rust** (https://rustup.rs) und **Node.js 20+** – nur einmal auf einem Entwicklungsrechner, nicht auf den Servern |

Offener Port: **8080** (TCP) vom Dateiserver und vom DC zum PermissionCenter-Server. Er lässt sich in der `.env` ändern.

---

## Schritt 1: Server starten

Auf dem Docker-Rechner, im Ordner mit dem PermissionCenter-Quellcode:

**1. Einstellungsdatei anlegen**

```bash
cp .env.example .env
```

**2. Die `.env` mit einem Texteditor öffnen und zwei Werte setzen:**

- `POSTGRES_PASSWORD=` – ein langes, zufälliges Passwort für die Datenbank.
- `PC_API_TOKENS=` – ein geheimes „Passwort“ für die Clients. Eines erzeugen (PowerShell):

  ```powershell
  -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 32 | % {[char]$_})
  ```

  Das Ergebnis in `PC_API_TOKENS=` eintragen und **aufschreiben** – es wird in den Schritten 3 und 4 gebraucht.

Alles andere kann zunächst so bleiben.

**3. Starten**

```bash
docker compose up -d --build
```

Der erste Start dauert einige Minuten (es wird alles gebaut). Das Datenbankschema legt der Server selbst an.

**4. Prüfen**

Im Browser `http://<server>:8080` öffnen. Es erscheint das PermissionCenter-Dashboard (noch leer). Alternativ:

```bash
docker compose ps          # beide Container "running"/"healthy"
docker compose logs server # Meldungen des Servers
```

> **Hinweis zu HTTPS:** Der Server spricht nur HTTP. Wenn der Verkehr verschlüsselt sein soll (empfohlen, denn das Token wird übertragen), schalte einen Reverse Proxy (z. B. Caddy, nginx, Traefik) mit Zertifikat davor und verwende dann `https://…` in den Clients.

---

## Schritt 2: Active Directory anbinden

Ohne AD-Daten kennt der Server nur SIDs. Mit AD-Daten sieht er Namen, deaktivierte Konten, verschachtelte Gruppen usw. Es gibt zwei Wege – einer genügt.

### Variante A: Export-Skript (am einfachsten)

Auf einem Domänencontroller oder Rechner mit RSAT-Modul `ActiveDirectory`, PowerShell als Administrator:

```powershell
.\tools\Export-ADData.ps1 -Server http://<server>:8080
```

Das Skript liest Benutzer, Computer und Gruppen und lädt sie direkt hoch. Beliebig oft wiederholbar, jeder Lauf ersetzt den alten Stand.

### Variante B: Automatischer LDAP-Abgleich

In der `.env` eintragen (Konto mit Leserechten im AD, ein normales Domänenkonto reicht):

```
PC_LDAP_URL=ldaps://dc01.firma.local:636
PC_LDAP_BIND_DN=svc-permcenter@firma.local
PC_LDAP_BIND_PASSWORD=geheim
PC_LDAP_BASE_DN=DC=firma,DC=local
PC_LDAP_SYNC_INTERVAL_MINUTES=60
```

Danach `docker compose up -d` und in der Weboberfläche unter **Active Directory → LDAP synchronisieren** klicken.

**Prüfen:** Die Seite *Active Directory* zeigt Anzahl Benutzer und Gruppen.

---

## Schritt 3: Dateiserver anbinden (pc-client)

### 3.1 Programme bauen (einmalig, auf dem Entwicklungsrechner)

```powershell
cd web
npm ci
npm run build
cd ..
cargo build --release
```

Ergebnis in `target\release\`:

- `pc-client.exe` – für die Dateiserver
- `gpo-client.exe` – für den Domänencontroller
- `pc-server.exe` – wird nur für OTA-Updates gebraucht (siehe unten)

### 3.2 Auf dem Dateiserver installieren

Diese zwei Dateien auf den Dateiserver kopieren, in **denselben Ordner**:

- `pc-client.exe`
- `tools\Install-PcClient.ps1`

Dann PowerShell **als Administrator** öffnen:

```powershell
.\Install-PcClient.ps1 -ServerUrl http://<server>:8080 -ApiToken <dein-token>
```

Das Skript kopiert das Programm nach `C:\Program Files\PermissionCenter`, legt die Konfiguration unter `C:\ProgramData\PermissionCenter\pc-client.toml` an und richtet einen **Windows-Dienst** ein, der jede Nacht um 02:00 Uhr scannt.

Varianten:

```powershell
# Sofort einmal scannen
.\Install-PcClient.ps1 -ServerUrl http://<server>:8080 -ApiToken <token> -RunNow

# Statt Dienst als geplante Aufgabe um 03:30 Uhr
.\Install-PcClient.ps1 -ServerUrl http://<server>:8080 -ApiToken <token> -Mode Task -At 03:30

# Wieder entfernen
.\Install-PcClient.ps1 -Uninstall
```

### 3.3 Prüfen

Einen Scan von Hand starten und zusehen:

```powershell
& "C:\Program Files\PermissionCenter\pc-client.exe" scan
```

Nach Ende erscheint der Dateiserver in der Weboberfläche unter **Systeme**. Bei großen Servern kann der erste Scan länger dauern. Bei Problemen:

```powershell
& "C:\Program Files\PermissionCenter\pc-client.exe" logs --errors
```

Systemordner wie `C:\Windows` und `Program Files` werden absichtlich übersprungen. Was gescannt oder ausgeschlossen wird, steht in der Konfigurationsdatei `pc-client.toml` (alles kommentiert).

---

## Schritt 4: Gruppenrichtlinien anbinden (gpo-client)

Auf einem **Domänencontroller** (oder einem Rechner mit RSAT-GPMC), als Domänen-Administrator.

**1.** `gpo-client.exe` auf den DC kopieren, z. B. nach `C:\PermissionCenter\`.

**2.** Einmal von Hand ausführen:

```powershell
C:\PermissionCenter\gpo-client.exe --server http://<server>:8080 --token <dein-token>
```

Das dauert je nach Anzahl der GPOs ein paar Sekunden bis Minuten. Am Ende steht z. B. `Übertragen: 42 GPOs übernommen …`.

**3.** In der Weboberfläche den Menüpunkt **Gruppenrichtlinien** öffnen.

**4. Täglich automatisch** (geplante Aufgabe, PowerShell als Administrator):

```powershell
$action  = New-ScheduledTaskAction -Execute 'C:\PermissionCenter\gpo-client.exe' `
           -Argument '--server http://<server>:8080 --token <dein-token>'
$trigger = New-ScheduledTaskTrigger -Daily -At 03:00
Register-ScheduledTask -TaskName 'PermissionCenter-GPO' -Action $action -Trigger $trigger `
           -User 'SYSTEM' -RunLevel Highest
```

Nur anschauen, ohne etwas zu übertragen: `gpo-client.exe --dry-run --out C:\Temp\gpos.json`.

---

## Schritt 5: Loslegen

In der Weboberfläche (`http://<server>:8080`):

| Menüpunkt | Was du dort findest |
|---|---|
| **Dashboard** | Gesamtnote A–F und die wichtigsten Probleme |
| **Befunde** / **Audit** | Alle gefundenen Probleme, nach Schwere sortiert |
| **Audit-Assist** | Führt Schritt für Schritt durchs Beheben, mit fertigen PowerShell-Skripten |
| **Zugriffsprüfung** | „Wer darf auf `\\FS01\Daten\Vertrieb`?“ |
| **Gruppenrichtlinien** | GPO-Liste, Einstellungssuche, gezielt zugewiesene GPOs, Berechtigungsmatrix |

---

## Optional

### Benachrichtigungen (E-Mail, Teams, Slack)

In der `.env` die gewünschten Zeilen ausfüllen (`PC_SMTP_*`, `PC_WEBHOOK_TEAMS`, `PC_WEBHOOK_SLACK`, `PC_PUBLIC_URL`), dann `docker compose up -d`. Unter **Einstellungen → Benachrichtigungen** gibt es einen Testversand. Details stehen in der README.

### Automatische Updates der Clients

Damit sich `pc-client` selbst aktualisiert, braucht es ein Schlüsselpaar (Schutz gegen untergeschobene Programme). Eine Kurzfassung:

```powershell
# 1. Einmalig Schlüssel erzeugen – die Datei GUT aufbewahren, nicht auf dem Server ablegen
.\target\release\pc-server.exe gen-signing-key --out C:\Sicher\permcenter-signing.key
```

Der ausgegebene **öffentliche** Schlüssel kommt in die `.env` (`PC_CLIENT_UPDATE_PUBLIC_KEY=`) und beim Installieren der Clients als `-PublicKey "<schlüssel>"`. Neue Versionen veröffentlichen:

```powershell
.\target\release\pc-server.exe publish-client --file .\target\release\pc-client.exe `
    --version <neue-version> --signing-key C:\Sicher\permcenter-signing.key `
    --server http://<server>:8080 --token <dein-token>
```

Der Client prüft Signatur und Prüfsumme und tauscht sich dann selbst aus. Der `gpo-client` aktualisiert sich nicht automatisch – dort die EXE einfach ersetzen.

---

## Server aktualisieren und sichern

**Neue Version einspielen** (Daten bleiben erhalten):

```bash
git pull            # bzw. neuen Quellcode einspielen
docker compose up -d --build
```

**Datenbank sichern:**

```bash
docker compose exec db pg_dump -U permcenter permcenter > backup.sql
```

**Zurückspielen:**

```bash
docker compose exec -T db psql -U permcenter permcenter < backup.sql
```

Die Daten liegen im Docker-Volume `pgdata`. `docker compose down` behält sie, `docker compose down -v` **löscht sie**.

---

## Wenn etwas nicht klappt

| Problem | Lösung |
|---|---|
| Browser erreicht `http://<server>:8080` nicht | `docker compose ps` prüfen; Firewall auf dem Server: Port 8080 freigeben |
| Client meldet „Server nicht erreichbar“ | URL und Port prüfen; vom Dateiserver aus testen: `Invoke-WebRequest http://<server>:8080/api/v1/health` |
| Client meldet `401` / „Ungültiges API-Token“ | Das Token muss **genau** einem Eintrag aus `PC_API_TOKENS` entsprechen. Nach Änderung der `.env`: `docker compose up -d` |
| `docker compose up` bricht mit „POSTGRES_PASSWORD … setzen“ ab | `.env` fehlt oder `POSTGRES_PASSWORD` ist leer |
| Dateiserver erscheint nicht unter *Systeme* | `pc-client logs --errors` auf dem Dateiserver; `pc-client scan` von Hand starten |
| Viele „Zugriff verweigert“ im Scan | Client muss als Dienst (SYSTEM) oder als Administrator laufen |
| `gpo-client`: „powershell.exe konnte nicht gestartet werden“ oder „Get-GPOReport … nicht erkannt“ | Auf einem DC ausführen oder auf dem Rechner das Feature „Gruppenrichtlinienverwaltung“ installieren: `Install-WindowsFeature GPMC` |
| `gpo-client`: Gruppenmitglieder fehlen | Das AD-PowerShell-Modul (RSAT) fehlt: `Install-WindowsFeature RSAT-AD-PowerShell` |
| Gruppenrichtlinien-Seite bleibt leer | `gpo-client` noch nicht gelaufen oder mit Fehler beendet (Meldung in der Konsole beachten) |
| Selbstsigniertes Zertifikat (nur Test) | Beim `gpo-client` `--accept-invalid-certs`, beim `pc-client` `accept_invalid_certs = true` in der Konfiguration |

Logs des Servers: `docker compose logs -f server`.

---

## Deinstallieren

- **Dateiserver:** `.\Install-PcClient.ps1 -Uninstall`
- **Domänencontroller:** `Unregister-ScheduledTask -TaskName 'PermissionCenter-GPO' -Confirm:$false` und die EXE löschen
- **Server:** `docker compose down -v` (löscht auch alle Daten!)
