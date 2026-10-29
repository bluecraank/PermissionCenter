//! Ordner öffnen, Inhalt auflisten und Security-Descriptor lesen.
//!
//! Ordner werden mit `FILE_FLAG_BACKUP_SEMANTICS` geöffnet. Ist das
//! `SeBackupPrivilege` aktiv, umgeht das die NTFS-Zugriffsprüfung – der Scan
//! sieht so auch Ordner, auf die Administratoren selbst keinen Zugriff haben.

use windows::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_NO_MORE_FILES, HANDLE, HLOCAL, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::{
    GetSecurityDescriptorControl, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FileFullDirectoryInfo, FileFullDirectoryRestartInfo, GetFileInformationByHandleEx,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_SYSTEM, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_LIST_DIRECTORY, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    READ_CONTROL,
};

use super::long_path;
use crate::acl;
use pc_common::sid::{sid_length, sid_to_string};
use pc_common::Ace;

const SE_DACL_PROTECTED: u16 = 0x1000;

#[derive(Debug)]
pub struct WinError {
    pub code: u32,
    pub message: String,
}

impl WinError {
    fn from_win(e: windows::core::Error) -> Self {
        let code = (e.code().0 as u32) & 0xFFFF;
        // std liest die Meldung per FormatMessageW (Unicode) – Umlaute bleiben korrekt.
        let text = std::io::Error::from_raw_os_error(code as i32).to_string();
        let message = match text.rfind(" (os error") {
            Some(i) => text[..i].trim().to_string(),
            None => text.trim().to_string(),
        };
        Self { code, message }
    }
    fn from_code(code: WIN32_ERROR) -> Self {
        Self::from_win(windows::core::Error::from(code.to_hresult()))
    }
}

impl std::fmt::Display for WinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (Code {})", self.message, self.code)
    }
}

pub struct DirHandle(HANDLE);

impl Drop for DirHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Öffnet einen Ordner. `list` = Auflisten erlaubt, sonst nur Sicherheit lesen.
pub fn open_dir(path: &str, list: bool) -> Result<DirHandle, WinError> {
    let access = if list {
        READ_CONTROL.0 | FILE_LIST_DIRECTORY.0
    } else {
        READ_CONTROL.0
    };
    let h = unsafe {
        CreateFileW(
            &long_path(path),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(WinError::from_win)?;
    Ok(DirHandle(h))
}

#[derive(Debug, Default)]
pub struct Security {
    pub owner_sid: Option<String>,
    pub protected: bool,
    pub aces: Vec<Ace>,
}

/// Liest Besitzer und DACL eines geöffneten Ordners.
pub fn read_security(h: &DirHandle) -> Result<Security, WinError> {
    unsafe {
        let mut owner = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let rc = GetSecurityInfo(
            h.0,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            Some(&mut sd),
        );
        if rc.is_err() {
            return Err(WinError::from_code(rc));
        }
        let result = parse_sd(sd, owner, dacl);
        LocalFree(Some(HLOCAL(sd.0)));
        Ok(result)
    }
}

/// # Safety
/// Zeiger müssen aus einem gültigen Security-Descriptor stammen.
pub unsafe fn parse_sd(sd: PSECURITY_DESCRIPTOR, owner: PSID, dacl: *mut ACL) -> Security {
    let mut sec = Security::default();
    let mut control: u16 = 0;
    let mut rev: u32 = 0;
    if !sd.0.is_null() && GetSecurityDescriptorControl(sd, &mut control, &mut rev).is_ok() {
        sec.protected = control & SE_DACL_PROTECTED != 0;
    }
    sec.owner_sid = psid_to_string(owner);
    sec.aces = if dacl.is_null() {
        acl::null_dacl()
    } else {
        acl_to_aces(dacl)
    };
    sec
}

/// # Safety
/// `dacl` muss auf eine gültige ACL zeigen.
pub unsafe fn acl_to_aces(dacl: *const ACL) -> Vec<Ace> {
    let size = (*dacl).AclSize as usize;
    let bytes = std::slice::from_raw_parts(dacl as *const u8, size);
    acl::parse_acl(bytes)
}

/// # Safety
/// `sid` muss null sein oder auf eine gültige SID zeigen.
pub unsafe fn psid_to_string(sid: PSID) -> Option<String> {
    if sid.0.is_null() {
        return None;
    }
    let head = std::slice::from_raw_parts(sid.0 as *const u8, 8);
    let len = 8 + head[1] as usize * 4;
    let bytes = std::slice::from_raw_parts(sid.0 as *const u8, len);
    sid_length(bytes)?;
    sid_to_string(bytes)
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub attributes: u32,
    pub size: u64,
}

impl DirEntry {
    pub fn is_dir(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
    }
    pub fn is_reparse(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    }
    pub fn is_system_hidden(&self) -> bool {
        let sh = FILE_ATTRIBUTE_SYSTEM.0 | FILE_ATTRIBUTE_HIDDEN.0;
        self.attributes & sh == sh
    }
}

/// Listet alle Einträge eines geöffneten Ordners (FILE_FULL_DIR_INFO).
pub fn list_dir(h: &DirHandle) -> Result<Vec<DirEntry>, WinError> {
    // 64 KiB, 8-Byte-ausgerichtet
    let mut buf = vec![0u64; 8192];
    let byte_len = (buf.len() * 8) as u32;
    let mut out = Vec::new();
    let mut first = true;
    loop {
        let class = if first {
            FileFullDirectoryRestartInfo
        } else {
            FileFullDirectoryInfo
        };
        first = false;
        let r = unsafe {
            GetFileInformationByHandleEx(h.0, class, buf.as_mut_ptr() as *mut _, byte_len)
        };
        if let Err(e) = r {
            if e.code() == ERROR_NO_MORE_FILES.to_hresult() {
                break;
            }
            return Err(WinError::from_win(e));
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, byte_len as usize) };
        let mut off = 0usize;
        loop {
            let rd = |o: usize| u32::from_le_bytes(bytes[off + o..off + o + 4].try_into().unwrap());
            let next = rd(0) as usize;
            let size = u64::from_le_bytes(bytes[off + 40..off + 48].try_into().unwrap());
            let attributes = rd(56);
            let name_len = rd(60) as usize;
            let name_bytes = &bytes[off + 68..off + 68 + name_len];
            let wide: Vec<u16> = name_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let name = String::from_utf16_lossy(&wide);
            if name != "." && name != ".." {
                out.push(DirEntry {
                    name,
                    attributes,
                    size,
                });
            }
            if next == 0 {
                break;
            }
            off += next;
        }
    }
    Ok(out)
}
