//! Katalog typischer Schwachstellen in Windows- und AD-Umgebungen.
//!
//! Der Client liest die hier genannten Registry-Werte, der Server bewertet sie zusammen
//! mit GPO-Einstellungen und AD-Daten. Es sind ausschließlich Konfigurationswerte, keine
//! Geheimnisse wie gespeicherte Kennwörter.

/// Bedingung, unter der ein Wert als Schwachstelle gilt.
#[derive(Debug, Clone, Copy)]
pub enum Test {
    Eq(i64),
    Ne(i64),
    Lt(i64),
    Gt(i64),
    StrPrefix(&'static str),
}

impl Test {
    /// Prüft einen Wert (Zahl dezimal oder als Text).
    pub fn matches(&self, value: &str) -> bool {
        let num = value.trim().parse::<i64>().ok();
        match self {
            Test::Eq(x) => num == Some(*x),
            Test::Ne(x) => num.is_some_and(|n| n != *x),
            Test::Lt(x) => num.is_some_and(|n| n < *x),
            Test::Gt(x) => num.is_some_and(|n| n > *x),
            Test::StrPrefix(p) => value
                .trim()
                .to_ascii_lowercase()
                .starts_with(&p.to_ascii_lowercase()),
        }
    }
}

/// Wert, den Windows verwendet, wenn der Registry-Eintrag fehlt.
#[derive(Debug, Clone, Copy)]
pub enum RegDefault {
    /// Unbekannt oder unkritisch: nur ein ausdrücklich gesetzter Wert zählt.
    None,
    Always(i64),
    /// Bis zu dieser Build-Nummer (ausschließlich) gilt der Wert, danach der zweite.
    BeforeBuild(u32, i64, i64),
}

/// Ein Registry-Wert unter HKLM.
#[derive(Debug, Clone, Copy)]
pub struct RegCheck {
    pub key: &'static str,
    pub value: &'static str,
    pub test: Test,
    pub default: RegDefault,
    /// Gilt nur auf Domänencontrollern.
    pub dc_only: bool,
    /// Richtlinienschlüssel, dessen gleichnamiger Wert Vorrang hat.
    pub policy_key: Option<&'static str>,
    /// Empfohlener Wert für das Skript im Audit-Assist.
    pub fix: Option<i64>,
    /// Der Wert ist vom Typ REG_SZ.
    pub string: bool,
    /// Bedeutung einzelner Werte.
    pub labels: &'static [(i64, &'static str)],
}

const REG: RegCheck = RegCheck {
    key: "",
    value: "",
    test: Test::Eq(0),
    default: RegDefault::None,
    dc_only: false,
    policy_key: None,
    fix: None,
    string: false,
    labels: &[],
};

/// Einstellung, die nur in einer GPO erkennbar ist.
#[derive(Debug, Clone, Copy)]
pub enum GpoCheck {
    /// Kontorichtlinie, z. B. `MinimumPasswordLength`.
    Account(&'static str, Test),
    /// Administrative Vorlage: Name (Deutsch und Englisch) und bedenklicher Zustand.
    Policy(&'static [&'static str], &'static str),
    /// Name der Einstellung beginnt mit diesem Text.
    Marker(&'static str),
}

/// Prüfung an AD-Daten.
#[derive(Debug, Clone, Copy)]
pub enum AdCheck {
    /// Aktive Benutzerkonten mit diesem Bit in `userAccountControl`.
    UacUsers(u32),
    /// Aktive Konten außer Domänencontrollern mit diesem Bit.
    UacNonDc(u32),
    MachineAccountQuota,
    KrbtgtPasswordOld,
    GuestEnabled,
}

/// Ein Eintrag im Katalog.
#[derive(Debug, Clone, Copy)]
pub struct Weakness {
    pub id: &'static str,
    pub category: &'static str,
    /// critical, high, medium, low
    pub severity: &'static str,
    pub title: &'static str,
    /// Warum das ein Problem ist.
    pub why: &'static str,
    /// Was zu tun ist.
    pub fix: &'static str,
    pub reg: &'static [RegCheck],
    pub gpo: &'static [GpoCheck],
    pub ad: Option<AdCheck>,
    /// Vorhandene Prüfregeln, deren Befunde dieses Muster belegen.
    pub rules: &'static [&'static str],
    /// Lässt sich aus den erfassten Daten nicht zuverlässig prüfen.
    pub manual: bool,
}

const W: Weakness = Weakness {
    id: "",
    category: "",
    severity: "medium",
    title: "",
    why: "",
    fix: "",
    reg: &[],
    gpo: &[],
    ad: None,
    rules: &[],
    manual: false,
};

const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
const SMB_SERVER: &str = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
const SMB_CLIENT: &str = r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
const NTDS: &str = r"SYSTEM\CurrentControlSet\Services\NTDS\Parameters";
const RDP: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
const RDP_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
const UAC: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
const POINT_PRINT: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint";
const WINRM: &str = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service";

/// Server 2025 (Build 26100) hat strengere Standardwerte.
const BUILD_2025: u32 = 26100;

const LM_LABELS: &[(i64, &str)] = &[
    (0, "LM und NTLM senden"),
    (
        1,
        "LM und NTLM senden, NTLMv2-Sitzungssicherheit falls ausgehandelt",
    ),
    (2, "Nur NTLM senden"),
    (3, "Nur NTLMv2 senden"),
    (4, "Nur NTLMv2 senden, LM ablehnen"),
    (5, "Nur NTLMv2 senden, LM und NTLM ablehnen"),
];

/// Der Katalog (genau 50 Einträge).
pub const CATALOG: &[Weakness] = &[
    // --- Anmeldung und Anmeldedaten ---
    Weakness {
        id: "WK_LM_COMPAT",
        category: "Anmeldung",
        severity: "high",
        title: "Veraltete NTLM-Authentifizierung (LmCompatibilityLevel unter 3)",
        why: "Stufen 0 bis 2 erlauben LM oder NTLMv1. Diese Antworten lassen sich mitschneiden und in kurzer Zeit knacken oder weiterleiten.",
        fix: "LmCompatibilityLevel auf 5 setzen (Netzwerksicherheit: LAN Manager-Authentifizierungsebene). Vorher im Ereignisprotokoll prüfen, ob Altgeräte noch NTLMv1 nutzen.",
        reg: &[RegCheck {
            key: LSA,
            value: "LmCompatibilityLevel",
            test: Test::Lt(3),
            default: RegDefault::Always(3),
            fix: Some(5),
            labels: LM_LABELS,
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_LM_HASH",
        category: "Anmeldung",
        severity: "high",
        title: "LM-Hashes werden gespeichert",
        why: "LM-Hashes sind extrem schwach und lassen sich fast sofort in Klartext zurückrechnen.",
        fix: "NoLMHash auf 1 setzen und danach die betroffenen Kennwörter ändern, damit alte Hashes verschwinden.",
        reg: &[RegCheck {
            key: LSA,
            value: "NoLMHash",
            test: Test::Eq(0),
            default: RegDefault::Always(1),
            fix: Some(1),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_WDIGEST",
        category: "Anmeldung",
        severity: "high",
        title: "WDigest hält Kennwörter im Klartext im Speicher",
        why: "Mit UseLogonCredential=1 liegen Kennwörter angemeldeter Benutzer lesbar im LSASS-Speicher.",
        fix: "UseLogonCredential auf 0 setzen und das System neu starten.",
        reg: &[RegCheck {
            key: r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
            value: "UseLogonCredential",
            test: Test::Eq(1),
            fix: Some(0),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_LSA_PPL",
        category: "Anmeldung",
        severity: "low",
        title: "LSA-Schutz ist nicht aktiv",
        why: "Ohne RunAsPPL können Programme mit Administratorrechten leichter Anmeldedaten aus dem LSASS-Prozess auslesen.",
        fix: "RunAsPPL auf 1 setzen, zuerst auf einem Testsystem: Sicherheitssoftware und Smartcard-Treiber müssen damit zurechtkommen.",
        reg: &[RegCheck {
            key: LSA,
            value: "RunAsPPL",
            test: Test::Eq(0),
            default: RegDefault::Always(0),
            fix: Some(1),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_CACHED_LOGONS",
        category: "Anmeldung",
        severity: "low",
        title: "Viele zwischengespeicherte Anmeldungen",
        why: "Auf Servern liegen dadurch Hashes früherer Anmeldungen vor, auch von Administratoren, und lassen sich offline angreifen.",
        fix: "CachedLogonsCount auf Servern auf 4 oder weniger senken.",
        reg: &[RegCheck {
            key: WINLOGON,
            value: "CachedLogonsCount",
            test: Test::Gt(4),
            default: RegDefault::Always(10),
            fix: Some(4),
            string: true,
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_BLANK_PW",
        category: "Anmeldung",
        severity: "high",
        title: "Netzwerkanmeldung mit leerem Kennwort erlaubt",
        why: "Lokale Konten ohne Kennwort sind dann auch über das Netzwerk nutzbar.",
        fix: "LimitBlankPasswordUse auf 1 setzen und Konten ohne Kennwort beseitigen.",
        reg: &[RegCheck {
            key: LSA,
            value: "LimitBlankPasswordUse",
            test: Test::Eq(0),
            default: RegDefault::Always(1),
            fix: Some(1),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_AUTO_LOGON",
        category: "Anmeldung",
        severity: "high",
        title: "Automatische Anmeldung aktiv",
        why: "Bei AutoAdminLogon liegt das Kennwort meist im Klartext in der Registry und jeder Neustart meldet das Konto an.",
        fix: "AutoAdminLogon auf 0 setzen, den Wert DefaultPassword löschen und das Kennwort des Kontos ändern.",
        reg: &[RegCheck {
            key: WINLOGON,
            value: "AutoAdminLogon",
            test: Test::Eq(1),
            fix: Some(0),
            string: true,
            ..REG
        }],
        ..W
    },
    // --- Anonymer Zugriff ---
    Weakness {
        id: "WK_ANON_SAM",
        category: "Anonymer Zugriff",
        severity: "medium",
        title: "Anonyme Auflistung von Konten erlaubt",
        why: "Ohne Anmeldung lassen sich Kontonamen abfragen, die Grundlage für Kennwortangriffe.",
        fix: "RestrictAnonymousSAM auf 1 setzen.",
        reg: &[RegCheck {
            key: LSA,
            value: "RestrictAnonymousSAM",
            test: Test::Eq(0),
            default: RegDefault::Always(1),
            fix: Some(1),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_ANON_SHARES",
        category: "Anonymer Zugriff",
        severity: "low",
        title: "Anonyme Auflistung von Konten und Freigaben nicht gesperrt",
        why: "Windows sperrt diese Auflistung standardmäßig nicht. Angreifer sehen so ohne Anmeldung Freigaben und Konten.",
        fix: "RestrictAnonymous auf 1 setzen. Sehr alte Clients und Vertrauensstellungen vorher prüfen.",
        reg: &[RegCheck {
            key: LSA,
            value: "RestrictAnonymous",
            test: Test::Eq(0),
            default: RegDefault::Always(0),
            fix: Some(1),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_NULL_SESSION",
        category: "Anonymer Zugriff",
        severity: "medium",
        title: "Null-Sessions auf Freigaben und Pipes erlaubt",
        why: "Anonyme Verbindungen können Freigaben und benannte Pipes erreichen.",
        fix: "RestrictNullSessAccess auf 1 setzen.",
        reg: &[RegCheck {
            key: SMB_SERVER,
            value: "RestrictNullSessAccess",
            test: Test::Eq(0),
            default: RegDefault::Always(1),
            fix: Some(1),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_EVERYONE_ANON",
        category: "Anonymer Zugriff",
        severity: "medium",
        title: "Rechte für „Jeder“ gelten auch für anonyme Benutzer",
        why: "Alles, was für „Jeder“ freigegeben ist, ist dann auch ohne Anmeldung erreichbar.",
        fix: "EveryoneIncludesAnonymous auf 0 setzen.",
        reg: &[RegCheck {
            key: LSA,
            value: "EveryoneIncludesAnonymous",
            test: Test::Eq(1),
            fix: Some(0),
            ..REG
        }],
        ..W
    },
    // --- SMB ---
    Weakness {
        id: "WK_SMB1_SERVER",
        category: "SMB",
        severity: "high",
        title: "SMBv1-Server aktiviert",
        why: "SMBv1 ist seit Jahren abgekündigt und war Einfallstor für WannaCry und NotPetya.",
        fix: "SMB1 auf 0 setzen und das Feature entfernen (Remove-WindowsFeature FS-SMB1).",
        reg: &[RegCheck {
            key: SMB_SERVER,
            value: "SMB1",
            test: Test::Eq(1),
            fix: Some(0),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_SMB1_CLIENT",
        category: "SMB",
        severity: "medium",
        title: "SMBv1-Client aktiviert",
        why: "Der Client kann zu SMBv1 herabgestuft werden und so angreifbar sein.",
        fix: "Dienst mrxsmb10 auf Starttyp 4 (deaktiviert) setzen und das Feature entfernen.",
        reg: &[RegCheck {
            key: r"SYSTEM\CurrentControlSet\Services\mrxsmb10",
            value: "Start",
            test: Test::Ne(4),
            fix: Some(4),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_SMB_SIGN_SERVER",
        category: "SMB",
        severity: "medium",
        title: "SMB-Signierung auf dem Server nicht erzwungen",
        why: "Ohne Signierung lassen sich Anmeldungen per NTLM-Relay auf diesen Server weiterleiten.",
        fix: "RequireSecuritySignature auf 1 setzen. Sehr alte Geräte wie Scanner oder NAS vorher prüfen.",
        reg: &[RegCheck {
            key: SMB_SERVER,
            value: "RequireSecuritySignature",
            test: Test::Eq(0),
            default: RegDefault::BeforeBuild(BUILD_2025, 0, 1),
            fix: Some(1),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_SMB_SIGN_CLIENT",
        category: "SMB",
        severity: "low",
        title: "SMB-Signierung auf dem Client nicht erzwungen",
        why: "Verbindungen zu fremden Servern können manipuliert oder umgeleitet werden.",
        fix: "RequireSecuritySignature im Abschnitt LanmanWorkstation auf 1 setzen.",
        reg: &[RegCheck {
            key: SMB_CLIENT,
            value: "RequireSecuritySignature",
            test: Test::Eq(0),
            default: RegDefault::BeforeBuild(BUILD_2025, 0, 1),
            fix: Some(1),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_SMB_PLAINTEXT",
        category: "SMB",
        severity: "high",
        title: "Kennwörter dürfen unverschlüsselt an SMB-Server gehen",
        why: "Ein Angreifer im Netz kann so das Kennwort im Klartext erhalten.",
        fix: "EnablePlainTextPassword auf 0 setzen.",
        reg: &[RegCheck {
            key: SMB_CLIENT,
            value: "EnablePlainTextPassword",
            test: Test::Eq(1),
            fix: Some(0),
            ..REG
        }],
        ..W
    },
    // --- LDAP ---
    Weakness {
        id: "WK_LDAP_SIGN",
        category: "LDAP",
        severity: "high",
        title: "LDAP-Signierung auf dem Domänencontroller nicht erzwungen",
        why: "Unsignierte LDAP-Anmeldungen lassen sich weiterleiten. So können Angreifer im Namen des Opfers Änderungen im AD vornehmen.",
        fix: "LDAPServerIntegrity auf 2 setzen. Vorher Ereignis 2889 auswerten, um unsignierte Clients zu finden.",
        reg: &[RegCheck {
            key: NTDS,
            value: "LDAPServerIntegrity",
            test: Test::Lt(2),
            default: RegDefault::Always(1),
            dc_only: true,
            fix: Some(2),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_LDAP_CBT",
        category: "LDAP",
        severity: "medium",
        title: "LDAP-Kanalbindung nicht aktiv",
        why: "Auch über LDAPS sind Relay-Angriffe möglich, solange die Kanalbindung fehlt.",
        fix: "LdapEnforceChannelBinding zunächst auf 1 setzen, später auf 2.",
        reg: &[RegCheck {
            key: NTDS,
            value: "LdapEnforceChannelBinding",
            test: Test::Lt(1),
            default: RegDefault::Always(0),
            dc_only: true,
            fix: Some(1),
            ..REG
        }],
        ..W
    },
    // --- Namensauflösung ---
    Weakness {
        id: "WK_LLMNR",
        category: "Namensauflösung",
        severity: "medium",
        title: "LLMNR ist aktiv",
        why: "Antwortet ein Angreifer auf LLMNR-Anfragen, schicken Rechner ihm ihre Anmeldedaten.",
        fix: "Richtlinie „Multicastnamensauflösung deaktivieren“ aktivieren (EnableMulticast=0).",
        reg: &[RegCheck {
            key: r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            value: "EnableMulticast",
            test: Test::Ne(0),
            default: RegDefault::Always(1),
            fix: Some(0),
            ..REG
        }],
        gpo: &[GpoCheck::Policy(
            &["Turn off multicast name resolution", "Multicastnamensauflösung deaktivieren"],
            "Disabled",
        )],
        ..W
    },
    Weakness {
        id: "WK_NBTNS",
        category: "Namensauflösung",
        severity: "medium",
        title: "NetBIOS-Namensauflösung (NBT-NS) aktiv",
        why: "Wie bei LLMNR kann ein Angreifer auf Namensanfragen antworten und Anmeldedaten abgreifen.",
        fix: "NetBIOS über TCP/IP je Netzwerkkarte oder über DHCP abschalten. Das wird je Schnittstelle gesetzt und hier nicht automatisch geprüft.",
        manual: true,
        ..W
    },
    // --- Remotedesktop ---
    Weakness {
        id: "WK_RDP_NLA",
        category: "Remotedesktop",
        severity: "medium",
        title: "RDP ohne Authentifizierung auf Netzwerkebene (NLA)",
        why: "Ohne NLA erreicht jeder den Anmeldebildschirm, auch ohne gültiges Konto. Das vergrößert die Angriffsfläche deutlich.",
        fix: "UserAuthentication auf 1 setzen.",
        reg: &[RegCheck {
            key: RDP,
            value: "UserAuthentication",
            test: Test::Eq(0),
            default: RegDefault::Always(1),
            policy_key: Some(RDP_POLICY),
            fix: Some(1),
            ..REG
        }],
        gpo: &[GpoCheck::Policy(
            &[
                "Require user authentication for remote connections by using Network Level Authentication",
                "Benutzerauthentifizierung für Remoteverbindungen mithilfe der Authentifizierung auf Netzwerkebene erforderlich machen",
            ],
            "Disabled",
        )],
        ..W
    },
    Weakness {
        id: "WK_RDP_SEC_LAYER",
        category: "Remotedesktop",
        severity: "medium",
        title: "RDP nutzt die alte RDP-Sicherheitsschicht",
        why: "SecurityLayer=0 verzichtet auf TLS. Der Server lässt sich dann nicht verlässlich prüfen.",
        fix: "SecurityLayer auf 2 setzen (TLS).",
        reg: &[RegCheck {
            key: RDP,
            value: "SecurityLayer",
            test: Test::Eq(0),
            policy_key: Some(RDP_POLICY),
            fix: Some(2),
            ..REG
        }],
        ..W
    },
    // --- Verschlüsselung ---
    Weakness {
        id: "WK_SSL3",
        category: "Verschlüsselung",
        severity: "high",
        title: "SSL 3.0 ausdrücklich aktiviert",
        why: "SSL 3.0 ist seit POODLE gebrochen und darf nicht mehr verwendet werden.",
        fix: "Enabled auf 0 setzen und das System neu starten.",
        reg: &[RegCheck {
            key: r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server",
            value: "Enabled",
            test: Test::Ne(0),
            fix: Some(0),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_TLS10",
        category: "Verschlüsselung",
        severity: "low",
        title: "TLS 1.0 ist aktiv",
        why: "TLS 1.0 gilt als veraltet und ist nach aktuellen Vorgaben nicht mehr zulässig.",
        fix: "Enabled auf 0 setzen. Vorher Anwendungen und .NET-Dienste auf TLS 1.2 prüfen.",
        reg: &[RegCheck {
            key: r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
            value: "Enabled",
            test: Test::Ne(0),
            default: RegDefault::BeforeBuild(BUILD_2025, 1, 0),
            fix: Some(0),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_TLS11",
        category: "Verschlüsselung",
        severity: "low",
        title: "TLS 1.1 ist aktiv",
        why: "TLS 1.1 gilt als veraltet und ist nach aktuellen Vorgaben nicht mehr zulässig.",
        fix: "Enabled auf 0 setzen. Vorher Anwendungen und .NET-Dienste auf TLS 1.2 prüfen.",
        reg: &[RegCheck {
            key: r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
            value: "Enabled",
            test: Test::Ne(0),
            default: RegDefault::BeforeBuild(BUILD_2025, 1, 0),
            fix: Some(0),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_RC4",
        category: "Verschlüsselung",
        severity: "medium",
        title: "RC4 ausdrücklich aktiviert",
        why: "RC4 ist gebrochen und sollte für TLS nicht mehr erlaubt sein.",
        fix: "Enabled auf 0 setzen.",
        reg: &[RegCheck {
            key: r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128",
            value: "Enabled",
            test: Test::Ne(0),
            fix: Some(0),
            ..REG
        }],
        ..W
    },
    // --- Systemhärtung ---
    Weakness {
        id: "WK_UAC_OFF",
        category: "Systemhärtung",
        severity: "high",
        title: "Benutzerkontensteuerung (UAC) ausgeschaltet",
        why: "Programme laufen dann ohne Nachfrage mit vollen Rechten eines Administrators.",
        fix: "EnableLUA auf 1 setzen und das System neu starten.",
        reg: &[RegCheck {
            key: UAC,
            value: "EnableLUA",
            test: Test::Eq(0),
            default: RegDefault::Always(1),
            fix: Some(1),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_UAC_REMOTE",
        category: "Systemhärtung",
        severity: "high",
        title: "Lokale Administratoren haben aus der Ferne volle Rechte",
        why: "LocalAccountTokenFilterPolicy=1 ermöglicht Pass-the-Hash mit lokalen Konten über das ganze Netz.",
        fix: "LocalAccountTokenFilterPolicy auf 0 setzen oder den Wert löschen.",
        reg: &[RegCheck {
            key: UAC,
            value: "LocalAccountTokenFilterPolicy",
            test: Test::Eq(1),
            fix: Some(0),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_WINRM_INSECURE",
        category: "Systemhärtung",
        severity: "high",
        title: "WinRM erlaubt Basic-Anmeldung oder unverschlüsselten Verkehr",
        why: "Anmeldedaten und Befehle können im Netz mitgelesen werden.",
        fix: "AllowBasic und AllowUnencryptedTraffic auf 0 setzen.",
        reg: &[
            RegCheck {
                key: WINRM,
                value: "AllowBasic",
                test: Test::Eq(1),
                fix: Some(0),
                ..REG
            },
            RegCheck {
                key: WINRM,
                value: "AllowUnencryptedTraffic",
                test: Test::Eq(1),
                fix: Some(0),
                ..REG
            },
        ],
        ..W
    },
    Weakness {
        id: "WK_SPOOLER_DC",
        category: "Systemhärtung",
        severity: "high",
        title: "Druckwarteschlange läuft auf dem Domänencontroller",
        why: "Der Dienst lässt sich missbrauchen, um den Domänencontroller zu einer Anmeldung zu zwingen, und hatte schwere Lücken wie PrintNightmare.",
        fix: "Dienst Spooler stoppen und deaktivieren (Starttyp 4), sofern der DC nicht wirklich drucken muss.",
        reg: &[RegCheck {
            key: r"SYSTEM\CurrentControlSet\Services\Spooler",
            value: "Start",
            test: Test::Ne(4),
            dc_only: true,
            fix: Some(4),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_POINT_PRINT",
        category: "Systemhärtung",
        severity: "high",
        title: "Unsichere Point-and-Print-Einstellung",
        why: "Benutzer können Druckertreiber ohne Administratorrechte installieren. Darüber lässt sich Code als SYSTEM ausführen.",
        fix: "RestrictDriverInstallationToAdministrators auf 1 und NoWarningNoElevationOnInstall auf 0 setzen.",
        reg: &[
            RegCheck {
                key: POINT_PRINT,
                value: "RestrictDriverInstallationToAdministrators",
                test: Test::Eq(0),
                fix: Some(1),
                ..REG
            },
            RegCheck {
                key: POINT_PRINT,
                value: "NoWarningNoElevationOnInstall",
                test: Test::Eq(1),
                fix: Some(0),
                ..REG
            },
        ],
        ..W
    },
    Weakness {
        id: "WK_DEFENDER_OFF",
        category: "Systemhärtung",
        severity: "medium",
        title: "Microsoft Defender per Richtlinie abgeschaltet",
        why: "Das ist nur sinnvoll, wenn eine andere Schutzlösung aktiv ist. Sonst läuft das System ohne Schutz vor Schadsoftware.",
        fix: "Richtlinie entfernen oder eine aktive Ersatzlösung als Ausnahme dokumentieren.",
        reg: &[RegCheck {
            key: r"SOFTWARE\Policies\Microsoft\Windows Defender",
            value: "DisableAntiSpyware",
            test: Test::Eq(1),
            fix: Some(0),
            ..REG
        }],
        ..W
    },
    Weakness {
        id: "WK_FIREWALL_OFF",
        category: "Systemhärtung",
        severity: "medium",
        title: "Windows-Firewall im Domänen- oder Standardprofil aus",
        why: "Alle Dienste des Systems sind dann im Netz erreichbar, was die seitliche Ausbreitung erleichtert.",
        fix: "EnableFirewall auf 1 setzen und benötigte Regeln gezielt freigeben.",
        reg: &[
            RegCheck {
                key: r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
                value: "EnableFirewall",
                test: Test::Eq(0),
                policy_key: Some(r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"),
                fix: Some(1),
                ..REG
            },
            RegCheck {
                key: r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
                value: "EnableFirewall",
                test: Test::Eq(0),
                policy_key: Some(r"SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"),
                fix: Some(1),
                ..REG
            },
        ],
        ..W
    },
    Weakness {
        id: "WK_WSUS_HTTP",
        category: "Systemhärtung",
        severity: "high",
        title: "WSUS-Updates über unverschlüsseltes HTTP",
        why: "Ein Angreifer im Netz kann Updates manipulieren und so Code als SYSTEM ausführen.",
        fix: "WSUS auf HTTPS umstellen und die Adresse in der Richtlinie anpassen.",
        reg: &[RegCheck {
            key: r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
            value: "WUServer",
            test: Test::StrPrefix("http://"),
            string: true,
            ..REG
        }],
        ..W
    },
    // --- Protokollierung ---
    Weakness {
        id: "WK_PS_LOGGING",
        category: "Protokollierung",
        severity: "low",
        title: "PowerShell-Skriptblockprotokollierung aus",
        why: "Viele Angriffe laufen über PowerShell. Ohne dieses Protokoll bleiben sie schwer nachvollziehbar.",
        fix: "Richtlinie „PowerShell-Skriptblockprotokollierung aktivieren“ einschalten und das Protokoll zentral sammeln.",
        reg: &[RegCheck {
            key: r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            value: "EnableScriptBlockLogging",
            test: Test::Ne(1),
            default: RegDefault::Always(0),
            fix: Some(1),
            ..REG
        }],
        gpo: &[GpoCheck::Policy(
            &["Turn on PowerShell Script Block Logging", "PowerShell-Skriptblockprotokollierung aktivieren"],
            "Disabled",
        )],
        ..W
    },
    Weakness {
        id: "WK_EVENTLOG_SMALL",
        category: "Protokollierung",
        severity: "low",
        title: "Sicherheitsprotokoll ist klein",
        why: "Bei unter 100 MB werden Ereignisse schnell überschrieben. Bei einem Vorfall fehlen dann die Spuren.",
        fix: "MaxSize auf mindestens 196 MB setzen und Ereignisse zentral sammeln.",
        reg: &[RegCheck {
            key: r"SYSTEM\CurrentControlSet\Services\EventLog\Security",
            value: "MaxSize",
            test: Test::Lt(104_857_600),
            default: RegDefault::Always(20_971_520),
            fix: Some(205_520_896),
            ..REG
        }],
        ..W
    },
    // --- Active Directory ---
    Weakness {
        id: "WK_ASREP",
        category: "Active Directory",
        severity: "high",
        title: "Konten ohne Kerberos-Vorauthentifizierung (AS-REP-Roasting)",
        why: "Für diese Konten kann jeder ein Ticket anfordern und das Kennwort offline knacken, auch ohne eigene Anmeldung.",
        fix: "Option „Keine Kerberos-Vorauthentifizierung erforderlich“ entfernen.",
        ad: Some(AdCheck::UacUsers(0x40_0000)),
        ..W
    },
    Weakness {
        id: "WK_PASSWD_NOTREQD",
        category: "Active Directory",
        severity: "high",
        title: "Konten dürfen ein leeres Kennwort haben",
        why: "Das Attribut PASSWD_NOTREQD erlaubt leere Kennwörter trotz Kennwortrichtlinie.",
        fix: "Flag entfernen (Set-ADUser -PasswordNotRequired $false) und ein Kennwort setzen.",
        ad: Some(AdCheck::UacUsers(0x20)),
        ..W
    },
    Weakness {
        id: "WK_REVERSIBLE",
        category: "Active Directory",
        severity: "high",
        title: "Kennwörter mit umkehrbarer Verschlüsselung",
        why: "Das Kennwort dieser Konten lässt sich aus der AD-Datenbank im Klartext gewinnen.",
        fix: "Option entfernen und das Kennwort ändern, erst dann verschwindet der alte Wert.",
        ad: Some(AdCheck::UacUsers(0x80)),
        ..W
    },
    Weakness {
        id: "WK_UNCONSTRAINED",
        category: "Active Directory",
        severity: "high",
        title: "Unbeschränkte Delegierung außerhalb der Domänencontroller",
        why: "Wer so ein Konto oder System übernimmt, erhält die Tickets aller Benutzer, die sich dort anmelden, auch von Domänen-Admins.",
        fix: "Auf beschränkte Delegierung umstellen. Admin-Konten als „kann nicht delegiert werden“ markieren.",
        ad: Some(AdCheck::UacNonDc(0x8_0000)),
        ..W
    },
    Weakness {
        id: "WK_MAQ",
        category: "Active Directory",
        severity: "medium",
        title: "Jeder Benutzer darf Computer in die Domäne aufnehmen",
        why: "ms-DS-MachineAccountQuota über 0 ist Baustein vieler Angriffe, zum Beispiel über ressourcenbasierte Delegierung.",
        fix: "ms-DS-MachineAccountQuota auf 0 setzen und das Aufnehmen gezielt delegieren.",
        ad: Some(AdCheck::MachineAccountQuota),
        ..W
    },
    Weakness {
        id: "WK_KRBTGT_OLD",
        category: "Active Directory",
        severity: "high",
        title: "krbtgt-Kennwort seit über 180 Tagen unverändert",
        why: "Wurde der Schlüssel je erbeutet, gelten gefälschte Tickets (Golden Ticket) bis zur Änderung weiter.",
        fix: "Kennwort zweimal ändern, mit ausreichend Abstand für die Replikation dazwischen.",
        ad: Some(AdCheck::KrbtgtPasswordOld),
        ..W
    },
    Weakness {
        id: "WK_GUEST_ENABLED",
        category: "Active Directory",
        severity: "medium",
        title: "Gastkonto der Domäne aktiv",
        why: "Das Gastkonto erlaubt einen Zugriff, der keinem Menschen zuzuordnen ist.",
        fix: "Gastkonto deaktivieren.",
        ad: Some(AdCheck::GuestEnabled),
        ..W
    },
    Weakness {
        id: "WK_KERBEROAST",
        category: "Active Directory",
        severity: "high",
        title: "Kerberoasting über Dienstkonten",
        why: "Jeder Domänenbenutzer kann für Konten mit SPN Tickets anfordern und deren Kennwörter offline knacken.",
        fix: "Auf gMSA umstellen oder sehr lange Kennwörter und nur AES verwenden.",
        rules: &["AD_KERBEROASTABLE"],
        ..W
    },
    Weakness {
        id: "WK_DCSYNC",
        category: "Active Directory",
        severity: "critical",
        title: "Gefährliche AD-Rechte außerhalb der Administration",
        why: "DCSync oder Rechte auf privilegierte Objekte führen direkt zur Übernahme der Domäne.",
        fix: "Rechte unter „Angriffspfade“ prüfen und entfernen.",
        rules: &["AD_DCSYNC_RIGHT", "AD_ATTACK_PATH_BROAD", "AD_ATTACK_PATH"],
        ..W
    },
    Weakness {
        id: "WK_ADMINS",
        category: "Active Directory",
        severity: "medium",
        title: "Zu viele oder ungenutzte privilegierte Konten",
        why: "Jedes zusätzliche Admin-Konto vergrößert die Angriffsfläche, verwaiste bleiben oft lange unbemerkt.",
        fix: "Admin-Gruppen auf das Nötigste reduzieren und getrennte Admin-Konten verwenden.",
        rules: &["AD_PRIVILEGED_MANY", "AD_PRIVILEGED_STALE"],
        ..W
    },
    // --- Gruppenrichtlinien ---
    Weakness {
        id: "WK_GPP_PASSWORD",
        category: "Gruppenrichtlinien",
        severity: "critical",
        title: "Kennwort in Gruppenrichtlinien-Einstellungen (cpassword)",
        why: "Der Schlüssel für cpassword ist öffentlich. Jeder Domänenbenutzer kann das Kennwort aus SYSVOL lesen und entschlüsseln (MS14-025).",
        fix: "Eintrag aus der GPO löschen und das betroffene Kennwort sofort ändern. Für lokale Admins LAPS verwenden.",
        gpo: &[GpoCheck::Marker(GPP_PASSWORD_MARKER)],
        ..W
    },
    Weakness {
        id: "WK_PW_LENGTH",
        category: "Gruppenrichtlinien",
        severity: "medium",
        title: "Kennwortrichtlinie erlaubt kurze Kennwörter",
        why: "Unter 12 Zeichen sind Kennwörter durch Wörterbuch- und Brute-Force-Angriffe deutlich leichter zu erraten.",
        fix: "Minimale Kennwortlänge auf mindestens 12, besser 14 Zeichen setzen.",
        gpo: &[GpoCheck::Account("MinimumPasswordLength", Test::Lt(12))],
        ..W
    },
    Weakness {
        id: "WK_LOCKOUT",
        category: "Gruppenrichtlinien",
        severity: "medium",
        title: "Keine Kontosperrung bei falschen Kennwörtern",
        why: "Ohne Sperre lassen sich Kennwörter unbegrenzt durchprobieren.",
        fix: "Kontosperrungsschwelle auf höchstens 10 setzen.",
        gpo: &[GpoCheck::Account("LockoutBadCount", Test::Eq(0))],
        ..W
    },
    Weakness {
        id: "WK_PW_COMPLEXITY",
        category: "Gruppenrichtlinien",
        severity: "medium",
        title: "Kennwortkomplexität per GPO abgeschaltet",
        why: "Benutzer können dann sehr einfache Kennwörter wählen.",
        fix: "Komplexität einschalten oder eine lange Mindestlänge plus Sperrliste verwenden.",
        gpo: &[GpoCheck::Account("PasswordComplexity", Test::Eq(0))],
        ..W
    },
];

/// Name der vom `gpo-client` erzeugten Zeile bei gespeichertem cpassword.
pub const GPP_PASSWORD_MARKER: &str = "GPP-Kennwort";

pub fn find(id: &str) -> Option<&'static Weakness> {
    CATALOG.iter().find(|w| w.id == id)
}

/// Eintrag, zu dem eine vorhandene Prüfregel gehört.
pub fn for_rule(rule: &str) -> Option<&'static Weakness> {
    CATALOG
        .iter()
        .find(|w| w.id == rule || w.rules.contains(&rule))
}

/// Alle Registry-Werte, die der Client lesen soll: Schlüssel, Wert, REG_SZ.
pub fn registry_values() -> Vec<(&'static str, &'static str)> {
    let mut out = Vec::new();
    for w in CATALOG {
        for c in w.reg {
            out.push((c.key, c.value));
            if let Some(p) = c.policy_key {
                out.push((p, c.value));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Wert eines fehlenden Registry-Eintrags auf dieser Windows-Version.
pub fn default_value(c: &RegCheck, os_build: Option<u32>) -> Option<i64> {
    match c.default {
        RegDefault::None => None,
        RegDefault::Always(v) => Some(v),
        RegDefault::BeforeBuild(build, old, new) => match os_build {
            Some(b) if b >= build => Some(new),
            _ => Some(old),
        },
    }
}

/// Bedeutung eines Werts, falls bekannt.
pub fn value_label(c: &RegCheck, value: &str) -> Option<&'static str> {
    let n = value.trim().parse::<i64>().ok()?;
    c.labels.iter().find(|(v, _)| *v == n).map(|(_, l)| *l)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn catalog_has_fifty_unique_entries() {
        assert_eq!(CATALOG.len(), 50);
        let ids: HashSet<_> = CATALOG.iter().map(|w| w.id).collect();
        assert_eq!(ids.len(), 50);
    }

    #[test]
    fn every_entry_is_checkable_or_marked_manual() {
        for w in CATALOG {
            let checks =
                !w.reg.is_empty() || !w.gpo.is_empty() || w.ad.is_some() || !w.rules.is_empty();
            assert!(checks != w.manual, "{}", w.id);
            assert!(!w.why.is_empty() && !w.fix.is_empty(), "{}", w.id);
            assert!(w.id.starts_with("WK_"), "{}", w.id);
        }
    }

    #[test]
    fn suggested_fix_is_not_a_weak_value() {
        for w in CATALOG {
            for c in w.reg {
                if let Some(f) = c.fix {
                    assert!(!c.test.matches(&f.to_string()), "{} {}", w.id, c.value);
                }
            }
        }
    }

    #[test]
    fn lm_level() {
        let c = &find("WK_LM_COMPAT").unwrap().reg[0];
        for (v, weak) in [
            ("0", true),
            ("1", true),
            ("2", true),
            ("3", false),
            ("5", false),
        ] {
            assert_eq!(c.test.matches(v), weak, "{v}");
        }
        assert_eq!(value_label(c, "0"), Some("LM und NTLM senden"));
        assert!(!c.test.matches(&default_value(c, None).unwrap().to_string()));
    }

    #[test]
    fn defaults_depend_on_build() {
        let c = &find("WK_SMB_SIGN_SERVER").unwrap().reg[0];
        assert_eq!(default_value(c, Some(14393)), Some(0));
        assert_eq!(default_value(c, Some(26100)), Some(1));
        assert_eq!(default_value(c, None), Some(0));
        let c = &find("WK_SMB1_SERVER").unwrap().reg[0];
        assert_eq!(default_value(c, Some(14393)), None);
    }

    #[test]
    fn tests_handle_text() {
        assert!(Test::StrPrefix("http://").matches("HTTP://wsus:8530"));
        assert!(!Test::StrPrefix("http://").matches("https://wsus:8531"));
        assert!(!Test::Lt(3).matches("kein Wert"));
    }

    #[test]
    fn rules_map_to_entries() {
        assert_eq!(for_rule("AD_KERBEROASTABLE").unwrap().id, "WK_KERBEROAST");
        assert_eq!(for_rule("WK_LM_COMPAT").unwrap().id, "WK_LM_COMPAT");
        assert!(for_rule("DENY_ACE").is_none());
    }

    #[test]
    fn client_reads_policy_keys_too() {
        let v = registry_values();
        assert!(v.contains(&(RDP_POLICY, "UserAuthentication")));
        assert!(v.contains(&(RDP, "UserAuthentication")));
        assert!(v.contains(&(LSA, "LmCompatibilityLevel")));
    }
}
