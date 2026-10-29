# Arbeitsprotokoll

Laufendes Protokoll zur Umsetzung von [AUFGABENSTELLUNG.md](AUFGABENSTELLUNG.md).
Mapping Anforderung → Umsetzung → Test: [ANFORDERUNGEN.md](ANFORDERUNGEN.md).

## 2026-10-29 – Version 0.1.0

### Ausgangslage
- Leeres Verzeichnis, nur `docs/AUFGABENSTELLUNG.md`.
- Toolchain: Rust 1.99.1 (MSVC + GNU), Node 24, Python 3.13, Git.
- Entwicklungsrechner: Windows 11 Pro, kein AD, kein Docker, kein PostgreSQL.

### Grundsatzentscheidungen
| Thema | Entscheidung | Begründung |
|---|---|---|
| Sprache Server | Rust (axum + tokio) | Ein Workspace, gemeinsames Datenmodell mit dem Client |
| Gemeinsames Modell | Crate `pc-common` | Report-Format ist der Vertrag zwischen Client und Server |
| Lokale DB Client | SQLite (rusqlite, bundled) | Keine Installation nötig, Outbox für Offline-Betrieb |
| DB Server | **PostgreSQL 17** als eigener Compose-Dienst | Entscheidung Auftraggeber („eigene schnelle Datenbank“); vorher SQLite |
| Windows-API | `windows`-Crate | Offizielle Bindings, kein C-Code |
| CRT | statisch gelinkt | Läuft auf Server 2016 ohne VC++-Redistributable |
| Transport | HTTP(S) POST, JSON gzip, API-Token | Firewall-freundlich, einfach |
| Web-UI | React + Vite + Tailwind CSS 4 + shadcn/ui (Radix), Cytoscape.js; eingebettet ins Server-Binary | Vorgabe Auftraggeber; ein Binary, offline lauffähig |
| AD | LDAP (ldap3, rustls/ring) + JSON-Import (PowerShell) | Testbar ohne Domäne |
| Login | vorbereitet (`auth.mode`), aktuell `none` | Laut Aufgabe „erstmal kein Login“ |
| Konfiguration | TOML mit kommentierter Vorlage; Server zusätzlich `PC_*`-Umgebungsvariablen | Entscheidung Auftraggeber (TOML statt .env) |
| OTA | Server hält Releases, Client prüft SHA-256 + Ed25519-Signatur | Nachtrag Auftraggeber; Integrität auch bei kompromittiertem Server |
| Client-Betrieb | Windows-Dienst (empfohlen) oder geplante Aufgabe | Nachtrag Auftraggeber |

### Verlauf
1. Workspace, `pc-common` (Modell, Rechte, SIDs, bekannte SIDs) mit Unit-Tests.
2. Client: ACL-Parser, Ausschlüsse, Win32-Schicht (Ordner, Security, Freigaben, SID-Auflösung, Privilegien), Scanner, lokale DB, Upload, CLI.
   Praxistest mit Testbaum (icacls/Set-Acl): verwaiste SID, unterbrochene Vererbung, Verweigern-ACE, „Jeder: Vollzugriff“.
3. Server zunächst mit SQLite; nach neuer Anforderung („Docker Compose“, „eigene schnelle Datenbank“) und Rückfrage auf **PostgreSQL** umgestellt (tokio-postgres + deadpool, COPY BINARY).
4. Web-UI mit shadcn-CLI-Komponenten. Korrektur: Die CLI hatte den Utils-Import falsch aufgelöst (`from "cn"`).
5. Docker: Multi-Stage-Dockerfile, Compose mit PostgreSQL, Healthcheck-Unterbefehl (Laufzeit-Image ohne curl).
6. End-to-End-Test gegen portables PostgreSQL 17.7 (Scratchpad, localhost:55432):
   Client-Scan → Upload (401 bei falschem Token, Outbox-Wiederholung) → Analyse → alle API-Endpunkte 200.
   Gefundene und behobene Fehler: Pfade mit `/` funktionierten nicht mit `\\?\`; doppelt kodierte Windows-Fehlermeldungen; Arbeitsgruppen-Systeme im Landschaftsgraph unter der AD-Domäne; Lücken in System-IDs durch Upsert.
7. Demodaten-Generator (Domäne DEMO.LOCAL, FS01/FS02): alle 18 Regeln werden ausgelöst.
8. OTA-Updates (Nachtrag): Release-Ablage, Signaturen, Client-Selbstaustausch. Getestet: unsignierte und falsch signierte Releases werden abgelehnt (Server und Client), Installation, Aufräumen der Altversion, automatisches Update vor einem Scan.
9. Windows-Dienst (Nachtrag): `service install|uninstall|start|stop|run`, Zeitplan, Neustart nach Update über die Dienst-Wiederherstellung.
10. Logging (Nachtrag): rotierende Tageslogs mit Lauf-ID; Korrektur: ANSI-Codes gelangten über den gemeinsamen Span-Cache in die Datei.
11. Kommentierte Konfigurationsvorlagen, Installationsskript mit `-Mode Service|Task`, Dokumentation, Changelog, Git-Repository.

### Rückfragen an den Auftraggeber
| Frage | Antwort |
|---|---|
| Was bedeutet „eigene schnelle Datenbank“? | PostgreSQL-Container |
| Wie gegen PostgreSQL testen (kein Docker/PG lokal)? | Portables PostgreSQL im Scratchpad starten |
| Format der Client-Konfiguration? | TOML behalten |

### Nicht verifiziert / offen
- **Docker-Image** wurde nicht gebaut (Docker auf dem Entwicklungsrechner nicht vorhanden). → `docker compose up -d --build` auf einem Docker-Host ausführen.
- **Dienstinstallation** nicht ausgeführt (Adminrechte/Sandbox); Code kompiliert, `service run` außerhalb des SCM bricht korrekt mit Log-Eintrag ab.
- **LDAP-Synchronisation** ohne Test-AD nicht geprüft; der JSON-Import desselben Datenmodells ist getestet.
- **Freigabeberechtigungen** und `SeBackupPrivilege` nur ohne Adminrechte getestet (Code-Pfad für Admin ungeprüft).
- **Windows Server 2016–2025**: nur auf Windows 11 getestet.
- **UI** typgeprüft, gebaut und ausgeliefert, aber nicht im Browser visuell geprüft.

## 2026-10-29 – Audit-Assist (Unreleased)

**Anforderung:** Ein Assistent, der einfach und Schritt für Schritt hilft, alle offenen Probleme zu beheben.

**Entscheidungen**
- Der Server ändert **nichts selbst**. Er hat keinen Zugriff auf die Dateiserver, und der AD-Zugang ist nur lesend. Stattdessen erzeugt er je Befund ein geprüftes PowerShell-Skript mit Probelauf, `-Apply` und Sicherung.
- Ein Befund ist erst behoben, wenn neue Daten ihn bestätigen. Das Klicken auf „Erledigt“ allein reicht nicht.
- Ausnahmen brauchen eine Begründung und fließen nicht in die Bewertung ein (audit-tauglich nachvollziehbar).

**Tests**
- Alle 17 Skripttypen aus den Demodaten mit dem Parser von Windows PowerShell 5.1 geprüft: keine Syntaxfehler.
- Realer Durchlauf auf NTFS:
  - Testordner mit verwaister SID (Erlauben und Verweigern) angelegt und gescannt.
  - Skript ausgeführt, erst als Probelauf, dann mit `-Apply`.
  - Erneut gescannt: Status `resolved`.
  - Die Sicherung wurde erfolgreich zurückgespielt.
  - Dabei gefunden und behoben: `icacls /remove` scheitert an verwaisten SIDs. Das Skript entfernt diese Einträge jetzt über .NET.
- „Nicht bestätigt“ geprüft: als erledigt markiert, Scan ohne Änderung, Status `failed`.
- Ausnahme ohne Begründung wird abgelehnt (400). Die Ausnahme überdauert eine Neuanalyse und wird im Audit gezählt.
- Seite im Browser (Edge headless) geprüft.

**Nicht verifiziert:** AD-Skripte (`Remove-ADGroup` usw.), Freigabe-Skripte (`*-SmbShareAccess`) und die Übertragung auf Gruppen (`-Group`) nur per Parser geprüft, nicht ausgeführt. Grund: kein AD bzw. keine Adminrechte auf dem Testrechner.

### Ideen für nächste Versionen
- Login über AD aktivieren (vorbereitet), Rollen (Leser/Admin).
- Veränderungsverlauf zwischen Scans (Diff der Berechtigungen).
- Export der Audits als PDF/CSV.
- LDAP-Range-Retrieval für sehr große Gruppen.
- Parallele Wurzel-Scans im Client.
