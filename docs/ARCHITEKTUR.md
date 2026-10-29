# Architektur

## Komponenten

| Komponente | Technik | Aufgabe |
|---|---|---|
| `pc-common` | Rust-Bibliothek | Report-Format (Vertrag Client ↔ Server), Rechte-Klassifizierung, SID-Parser, bekannte SIDs, Release-Signaturen |
| `pc-client` | Rust, `windows`-Crate, SQLite | Scan, lokale Ablage, Upload, Dienst, OTA-Update, Logging |
| `pc-server` | Rust, axum/tokio, tokio-postgres, ldap3 | API, Ingest, Analyse, AD-Abgleich, Release-Verwaltung, Auslieferung der UI |
| `web` | React 19, Vite, Tailwind CSS 4, shadcn/ui (Radix), TanStack Query, Cytoscape.js, Recharts | Weboberfläche; das Build-Ergebnis wird per `rust-embed` in `pc-server` eingebettet |
| PostgreSQL 17 | Docker-Container | Datenhaltung des Servers |

## Datenfluss

1. **Scan** (Client, eigener Thread mit 128-MB-Stack für tiefe Bäume): Rekursion je Wurzel. Jeder Ordner wird einmal mit `READ_CONTROL | FILE_LIST_DIRECTORY` und `FILE_FLAG_BACKUP_SEMANTICS` geöffnet. Aus diesem Handle liest der Client Security-Descriptor (`GetSecurityInfo`) und Inhalt (`GetFileInformationByHandleEx`, `FILE_FULL_DIR_INFO`).
2. **Reduktion** („relevant“): Ein Ordner wird gemeldet, wenn er eigene ACEs hat, die Vererbung unterbrochen ist, ein Fehler auftrat, der Besitzer verwaist ist, er eine Freigabe ist oder in den obersten `skeleton_depth` Ebenen liegt. Seine Vorfahren werden mitgemeldet (Stack-basiert, ohne den ganzen Baum im Speicher zu halten). `subfolder_total` zählt alle Unterordner, auch die nicht gemeldeten.
3. **Stränge**: `acl_source_id` verweist auf den nächsten Vorfahren (bzw. den Ordner selbst), dessen ACL die Rechte bestimmt. Jeder nicht gemeldete Ordner erbt die Rechte seines nächsten gemeldeten Vorfahren.
4. **SID-Auflösung** mit Cache (`LookupAccountSidW`). `ERROR_NONE_MAPPED` gilt als verwaist, außer bei bekannten SIDs; andere Fehler (z. B. DC nicht erreichbar) ergeben `unknown`.
5. **Lokale DB** (`%ProgramData%\PermissionCenter\pc-client.db`): Scan + gzip-Nutzlast + normalisierte Tabellen. Nicht übertragene Scans bleiben in der Outbox.
6. **Upload**: `POST /api/v1/reports`, JSON gzip-komprimiert, Header `X-Api-Key`.
7. **Ingest** (eine Transaktion, Advisory-Lock je System): System anlegen/aktualisieren, Scan-Historie speichern. Ist der Scan der neueste, werden die Detaildaten des Systems ersetzt (`COPY BINARY` für Ordner und ACEs).
8. **Analyse** (gleiche Transaktion, globaler Advisory-Lock): komplette Neuberechnung aller Befunde. Sie läuft auch nach jedem AD-Abgleich und auf Anforderung.

## Datenmodell (Server)

```
systems ─┬─< scans                 (Historie je Upload, Kennzahlen, Wurzeln, Fehlerliste)
         ├─< folders (system_id, local_id)  ─< aces (system_id, folder_local_id)
         ├─< shares ─< share_aces
         └─< findings              (system_id NULL = AD-Befund, fingerprint = stabile Kennung)
finding_states                      (Audit-Assist: fixed | accepted | resolved je fingerprint)
principals                          (Auflösung der Clients: Name, Domäne, Art)
ad_users, ad_groups, ad_members     (AD-Stand, wird je Abgleich ersetzt)
meta                                (Schema-Version, AD-Domäne/SID, Zeitstempel)
```

Je System werden nur die Detaildaten des neuesten Scans gehalten. Das hält die Datenbank kompakt; der Verlauf bleibt als Kennzahlen erhalten.

## Prinzipal-Status (Server)

| Status | Bedingung |
|---|---|
| `orphaned` | Client meldet `unresolved`/`deleted`, **oder** das AD ist geladen und die SID gehört zur Domäne, existiert dort aber nicht |
| `disabled` | AD-Benutzer deaktiviert |
| `inactive` | AD-Benutzer aktiv, letzte Anmeldung (bzw. Erstellung bei „nie angemeldet“) älter als `inactive_days` |
| `system` | Bekannte SID (Jeder, SYSTEM, VORDEFINIERT\…, NT SERVICE\…) |
| `active` / `unknown` | sonst |

## Prüfregeln

| Regel | Schwere | Prüft |
|---|---|---|
| `ORPHANED_SID` | Hoch | Explizite ACEs für nicht existierende Konten |
| `BROAD_WRITE` | Hoch | Schreiben/Ändern/Vollzugriff für Jeder, Authentifizierte Benutzer, Benutzer, Domänen-Benutzer/-Gäste, Anonym |
| `SHARE_OPEN` | Mittel | Freigabe ohne Security-Descriptor oder mit Vollzugriff für breite Gruppen |
| `DISABLED_USER_ACE` | Mittel | Deaktivierte AD-Benutzer mit expliziten Rechten |
| `PERMISSION_DELEGATION` | Mittel | `WRITE_DAC`/`WRITE_OWNER` für Nicht-Administratoren |
| `STALE_SYSTEM` | Mittel | Letzter Scan älter als `stale_scan_days` |
| `DIRECT_USER_ACE` | Niedrig | Rechte direkt für Benutzerkonten (statt AGDLP) |
| `INACTIVE_USER_ACE` | Niedrig | Inaktive Benutzer mit expliziten Rechten |
| `DENY_ACE` | Niedrig | Explizite Verweigern-Einträge |
| `DEEP_EXPLICIT` | Niedrig | Explizite Rechte ab Tiefe `deep_explicit_depth` |
| `ORPHANED_OWNER` | Niedrig | Ordner mit verwaistem Besitzer |
| `INHERITANCE_BROKEN` | Info | Unterbrochene Vererbung |
| `SCAN_ERRORS` | Info | Nicht lesbare Ordner |
| `AD_EMPTY_GROUP` | Niedrig | Sicherheitsgruppe ohne Mitglieder |
| `AD_ORPHANED_GROUP` | Niedrig | Alle (transitiven) Benutzer der Gruppe deaktiviert |
| `AD_UNUSED_GROUP` | Info | Gruppe weder direkt noch über Verschachtelung in einer Berechtigung |
| `AD_INACTIVE_USER` | Niedrig | Aktiviertes, aber inaktives Konto |
| `AD_DISABLED_IN_GROUPS` | Info | Deaktivierte Konten sind noch Gruppenmitglied |

**Bewertung**: Strafpunkte = Σ Gewicht(Schwere) × min(3, 1 + log₁₀(betroffene Objekte)); Gewichte: Kritisch 25, Hoch 12, Mittel 5, Niedrig 1,5, Info 0. Punktwert = 100 · e^(−Strafpunkte/80). Noten: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 45, E ≥ 30, sonst F.

## Audit-Assist

- Die Befunde werden bei jeder Analyse neu erzeugt. Damit ein Bearbeitungsstand erhalten bleibt, bekommt jeder Befund einen `fingerprint`: SHA-256 aus Regel, System, SID und, nur bei `BROAD_WRITE`/`SHARE_OPEN`, Pfad.
- `finding_states` speichert dazu den Status: `fixed` (als erledigt markiert), `accepted` (Ausnahme mit Begründung) oder `resolved`.
  - Am Ende jeder Analyse wird ein `fixed`/`accepted`-Eintrag, dessen Befund verschwunden ist, zu `resolved`.
  - Taucht ein Befund wieder auf, wird sein `resolved`-Eintrag gelöscht; der Befund ist dann wieder offen.
- „Nicht bestätigt“ (`failed`) wird nicht gespeichert, sondern berechnet: Der Befund ist `fixed`, aber der letzte Scan des Systems bzw. der letzte AD-Abgleich ist neuer als die Markierung.
- `assist.rs` erzeugt je Regel die Anleitung und ein PowerShell-Skript (PS 5.1-kompatibel).
  - Einträge werden über .NET (`RemoveAccessRuleSpecific`) entfernt, weil icacls verwaiste SIDs nicht entfernen kann.
  - Rechte werden mit `icacls /grant` gesetzt, Besitzer mit `/setowner`, Vererbung mit `/inheritance:e`.
  - Freigaben werden mit `Grant/Revoke-SmbShareAccess` geändert, AD-Objekte mit `Remove-ADGroup`, `Disable-ADAccount` und `Remove-ADGroupMember`.

## OTA-Updates

```
Entwickler/CI                 Server                              Client
pc-server publish-client ──▶  client-releases/<ver>/              GET /api/v1/client/latest  (Token)
  (signiert mit privatem      pc-client.exe + release.json        ├─ Version > eigene?
   Ed25519-Schlüssel)         prüft Signatur, falls Public Key    ├─ Download, Größe + SHA-256 prüfen
                              gesetzt                             ├─ Signatur über "version + sha256" prüfen
                                                                  ├─ exe → exe.old, exe.new → exe
                                                                  └─ Neustart (CLI: Re-Exec, Dienst: Exit 10 → SCM-Wiederherstellung)
```

## Sicherheit

- Client → Server: API-Token, TLS über Reverse-Proxy. Der Client prüft Zertifikate (`accept_invalid_certs` nur für Tests).
- Release-Integrität: Ed25519-Signatur; der öffentliche Schlüssel ist im Client fest konfiguriert.
- Daten auf dem Client: `%ProgramData%\PermissionCenter` ist nur für SYSTEM und Administratoren zugänglich.
- Weboberfläche: noch ohne Login (Vorgabe). Vorbereitet sind `auth.mode = "ldap"` und `ad::verify_credentials` (LDAP-Bind).

## Grenzen / bekannte Einschränkungen

- Sehr große Gruppen (> 1500 Mitglieder) liefert LDAP ohne Range-Retrieval unvollständig; zusätzlich werden `primaryGroupID` und `memberOf` der Benutzer genutzt. Der PowerShell-Export (`Get-ADGroup -Properties Members`) hat diese Einschränkung nicht.
- Nicht gemeldete Ordner erben in der Auswertung exakt die ACL ihres Strang-Ursprungs. Sonderfälle der Vererbung (z. B. „nur Dateien“) bilden sich bei Unterordnern deshalb nur näherungsweise ab.
- Der Scan läuft je System sequentiell (ein Thread). Parallele Wurzel-Scans sind eine mögliche Optimierung.
