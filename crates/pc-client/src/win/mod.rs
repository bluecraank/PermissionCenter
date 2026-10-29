//! Windows-spezifische Systemaufrufe.

pub mod fs;
pub mod groups;
pub mod resolver;
pub mod shares;
pub mod system;

use windows::core::HSTRING;

/// Wandelt einen Anzeigepfad in die Long-Path-Form `\\?\…` um.
pub fn long_path(path: &str) -> HSTRING {
    let p = path.trim_end_matches('\\');
    let s = if p.starts_with("\\\\?\\") {
        p.to_string()
    } else if let Some(unc) = p.strip_prefix("\\\\") {
        format!("\\\\?\\UNC\\{unc}")
    } else if p.len() == 2 && p.ends_with(':') {
        format!("\\\\?\\{p}\\")
    } else {
        format!("\\\\?\\{p}")
    };
    HSTRING::from(s)
}

pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Liest einen nullterminierten UTF-16-String an einem Zeiger.
///
/// # Safety
/// `p` muss null sein oder auf einen gültigen, nullterminierten String zeigen.
pub unsafe fn pwstr_to_string(p: windows::core::PWSTR) -> Option<String> {
    if p.is_null() {
        None
    } else {
        p.to_string().ok()
    }
}
