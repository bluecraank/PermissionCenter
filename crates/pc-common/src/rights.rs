//! Abbildung roher NTFS-Zugriffsmasken auf verständliche Rechtestufen.

use serde::{Deserialize, Serialize};

pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;

pub const FILE_FULL_CONTROL: u32 = 0x001F_01FF;
pub const FILE_MODIFY: u32 = 0x0013_01BF;
pub const FILE_READ_EXECUTE: u32 = 0x0012_00A9;
pub const FILE_READ: u32 = 0x0012_0089;
pub const FILE_WRITE: u32 = 0x0010_0116;

pub const DELETE: u32 = 0x0001_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;

/// Freigabe-Berechtigungen (Share-Level) verwenden dieselben Bits.
pub const SHARE_FULL: u32 = FILE_FULL_CONTROL;
pub const SHARE_CHANGE: u32 = FILE_MODIFY;
pub const SHARE_READ: u32 = FILE_READ_EXECUTE;

/// Vereinfachte Rechtestufe, absteigend nach Mächtigkeit sortiert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rights {
    FullControl,
    Modify,
    Write,
    ReadExecute,
    Read,
    /// Kombination, die keiner Standardstufe entspricht.
    Special,
    None,
}

impl Rights {
    pub fn as_str(&self) -> &'static str {
        match self {
            Rights::FullControl => "full_control",
            Rights::Modify => "modify",
            Rights::Write => "write",
            Rights::ReadExecute => "read_execute",
            Rights::Read => "read",
            Rights::Special => "special",
            Rights::None => "none",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "full_control" => Rights::FullControl,
            "modify" => Rights::Modify,
            "write" => Rights::Write,
            "read_execute" => Rights::ReadExecute,
            "read" => Rights::Read,
            "none" => Rights::None,
            _ => Rights::Special,
        }
    }

    pub fn label_de(&self) -> &'static str {
        match self {
            Rights::FullControl => "Vollzugriff",
            Rights::Modify => "Ändern",
            Rights::Write => "Schreiben",
            Rights::ReadExecute => "Lesen, Ausführen",
            Rights::Read => "Lesen",
            Rights::Special => "Spezial",
            Rights::None => "Keine",
        }
    }

    /// Recht erlaubt das Anlegen/Ändern von Inhalten.
    pub fn can_write(&self) -> bool {
        matches!(self, Rights::FullControl | Rights::Modify | Rights::Write)
    }
}

/// Wandelt generische Rechte in dateispezifische um.
pub fn map_generic(mask: u32) -> u32 {
    let mut m = mask & !(GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ);
    if mask & GENERIC_ALL != 0 {
        m |= FILE_FULL_CONTROL;
    }
    if mask & GENERIC_READ != 0 {
        m |= FILE_READ;
    }
    if mask & GENERIC_WRITE != 0 {
        m |= FILE_WRITE;
    }
    if mask & GENERIC_EXECUTE != 0 {
        m |= 0x0012_00A0;
    }
    m
}

/// Ordnet eine Zugriffsmaske der stärksten vollständig enthaltenen Stufe zu.
pub fn classify(mask: u32) -> Rights {
    let m = map_generic(mask);
    let has = |bits: u32| m & bits == bits;
    if m == 0 {
        Rights::None
    } else if has(FILE_FULL_CONTROL) {
        Rights::FullControl
    } else if has(FILE_MODIFY) {
        Rights::Modify
    } else if has(FILE_WRITE) && !has(FILE_READ) {
        Rights::Write
    } else if has(FILE_READ_EXECUTE) {
        if m & (WRITE_DAC | WRITE_OWNER | DELETE) != 0 || has(FILE_WRITE) {
            Rights::Special
        } else {
            Rights::ReadExecute
        }
    } else if has(FILE_READ) {
        Rights::Read
    } else {
        Rights::Special
    }
}

/// Maske erlaubt das Ändern der Berechtigungen bzw. des Besitzers.
pub fn can_change_permissions(mask: u32) -> bool {
    map_generic(mask) & (WRITE_DAC | WRITE_OWNER) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_masks() {
        assert_eq!(classify(FILE_FULL_CONTROL), Rights::FullControl);
        assert_eq!(classify(FILE_MODIFY), Rights::Modify);
        assert_eq!(classify(FILE_READ_EXECUTE), Rights::ReadExecute);
        assert_eq!(classify(FILE_READ), Rights::Read);
        assert_eq!(classify(FILE_WRITE), Rights::Write);
        assert_eq!(classify(0), Rights::None);
    }

    #[test]
    fn generic_masks() {
        assert_eq!(classify(GENERIC_ALL), Rights::FullControl);
        assert_eq!(
            classify(GENERIC_READ | GENERIC_EXECUTE),
            Rights::ReadExecute
        );
        assert_eq!(classify(GENERIC_READ), Rights::Read);
    }

    #[test]
    fn special_masks() {
        assert_eq!(classify(FILE_READ_EXECUTE | WRITE_DAC), Rights::Special);
        assert_eq!(classify(0x0000_0001), Rights::Special);
        assert!(can_change_permissions(FILE_FULL_CONTROL));
        assert!(!can_change_permissions(FILE_MODIFY));
    }
}
