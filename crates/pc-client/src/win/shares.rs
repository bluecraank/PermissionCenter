//! Lokale Freigaben inkl. Freigabeberechtigungen (NetShareEnum, Level 502).

use windows::core::BOOL;
use windows::core::PCWSTR;
use windows::Win32::NetworkManagement::NetManagement::{NetApiBufferFree, MAX_PREFERRED_LENGTH};
use windows::Win32::Security::{GetSecurityDescriptorDacl, ACL};
use windows::Win32::Storage::FileSystem::{NetShareEnum, SHARE_INFO_502};

use super::fs::acl_to_aces;
use super::pwstr_to_string;
use pc_common::ShareInfo;

const STYPE_MASK: u32 = 0xFF;
const STYPE_DISKTREE: u32 = 0;
const STYPE_SPECIAL: u32 = 0x8000_0000;
const ERROR_MORE_DATA: u32 = 234;

pub fn is_disk_share(s: &ShareInfo) -> bool {
    s.share_type & STYPE_MASK == STYPE_DISKTREE
}

pub fn enumerate() -> Result<Vec<ShareInfo>, String> {
    let mut out = Vec::new();
    let mut resume: u32 = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut read: u32 = 0;
        let mut total: u32 = 0;
        let rc = unsafe {
            NetShareEnum(
                PCWSTR::null(),
                502,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                Some(&mut resume),
            )
        };
        if rc != 0 && rc != ERROR_MORE_DATA {
            return Err(format!("NetShareEnum fehlgeschlagen (Code {})", rc));
        }
        if !buf.is_null() {
            let items =
                unsafe { std::slice::from_raw_parts(buf as *const SHARE_INFO_502, read as usize) };
            for it in items {
                out.push(unsafe { convert(it) });
            }
            unsafe {
                NetApiBufferFree(Some(buf as *const _));
            }
        }
        if rc != ERROR_MORE_DATA {
            break;
        }
    }
    Ok(out)
}

unsafe fn convert(it: &SHARE_INFO_502) -> ShareInfo {
    let name = pwstr_to_string(it.shi502_netname).unwrap_or_default();
    let share_type = it.shi502_type.0;
    let mut permissions = None;
    if !it.shi502_security_descriptor.0.is_null() {
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        if GetSecurityDescriptorDacl(
            it.shi502_security_descriptor,
            &mut present,
            &mut dacl,
            &mut defaulted,
        )
        .is_ok()
            && present.as_bool()
            && !dacl.is_null()
        {
            permissions = Some(acl_to_aces(dacl));
        }
    }
    ShareInfo {
        is_special: share_type & STYPE_SPECIAL != 0 || name.eq_ignore_ascii_case("IPC$"),
        name,
        path: pwstr_to_string(it.shi502_path).unwrap_or_default(),
        remark: pwstr_to_string(it.shi502_remark).filter(|s| !s.is_empty()),
        share_type,
        permissions,
        folder_id: None,
    }
}
