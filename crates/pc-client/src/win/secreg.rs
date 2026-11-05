//! Liest die Registry-Werte aus dem Schwachstellen-Katalog (nur HKLM, nur diese Liste).

use pc_common::weakness::registry_values;
use pc_common::SecuritySetting;
use windows::core::HSTRING;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    RegGetValueW, HKEY_LOCAL_MACHINE, REG_DWORD, REG_SZ, REG_VALUE_TYPE, RRF_RT_REG_DWORD,
    RRF_RT_REG_SZ,
};

fn read(key: &str, name: &str) -> Option<String> {
    let (k, n) = (HSTRING::from(key), HSTRING::from(name));
    let mut ty = REG_VALUE_TYPE::default();
    let mut buf = [0u16; 512];
    let mut len = std::mem::size_of_val(&buf) as u32;
    // SAFETY: Puffer und Länge passen zusammen, Schlüsselnamen sind nullterminiert.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            &k,
            &n,
            RRF_RT_REG_DWORD | RRF_RT_REG_SZ,
            Some(&mut ty),
            Some(buf.as_mut_ptr().cast()),
            Some(&mut len),
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    if ty == REG_DWORD {
        Some((buf[0] as u32 | ((buf[1] as u32) << 16)).to_string())
    } else if ty == REG_SZ {
        Some(super::from_wide(&buf).trim().to_string())
    } else {
        None
    }
}

/// Alle vorhandenen Werte. Fehlende Einträge werden nicht gemeldet.
pub fn read_settings() -> Vec<SecuritySetting> {
    registry_values()
        .into_iter()
        .filter_map(|(key, name)| {
            read(key, name).map(|value| SecuritySetting {
                key: key.to_string(),
                name: name.to_string(),
                value,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Auf jedem Windows vorhanden: DWORD und REG_SZ.
    #[test]
    fn reads_both_types() {
        let start = read(r"SYSTEM\CurrentControlSet\Services\EventLog", "Start").unwrap();
        assert!(start.parse::<u32>().is_ok(), "{start}");
        let product = read(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName",
        )
        .unwrap();
        assert!(product.contains("Windows"), "{product}");
        assert!(read(r"SOFTWARE\GibtEsNicht", "Nichts").is_none());
    }
}
