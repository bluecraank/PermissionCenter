# PermissionCenter-Client

- Rust-Client für Windows Server 2016 - 2025 mit lokaler DB
- Scannt alle Ordner von Laufwerken auf Berechtigungen, verwaiste Einträge
- Generiert daraus Verzeichnisstränge und Abhängigkeiten
- Schließt System-bekannte Ordner wie z.B C:\Windows aus
- Scannt alle Netzlaufwerke (Freigegebene Ordner)
- Liefert seine Ergebnisse an ein zentrales Auswertungs-Programm

# PermissionCenter-Server
- AD Authentifizierung (aber erstmal kein Login)
- Sammelt vom Client alle Informationen
- Analyisiert und bereitet Ergebnisse auf
- Erkennt zusammenhänge
- Kennt alle AD-User und AD-Gruppen
- Kann verwaiste User/Gruppen erkennen
- Beinhaltet ein Auditing Tool zur Bewertung der Systeme
- Kann Empfehlungen ausgeben
- Visualisiert die IT-Landschaft
- Docker Compose fähig
- eigene schnelle Datenbank

# Umgang mit Hindernissen, besseren Ideen
- Frag mich

# Changelog
- Führen nach https://keepachangelog.com/de/1.0.0/ und https://semver.org/lang/de/
