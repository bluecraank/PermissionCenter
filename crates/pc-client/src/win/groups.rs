//! Mitglieder lokaler Gruppen (NetLocalGroupGetMembers).

use windows::core::HSTRING;
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetLocalGroupGetMembers, LOCALGROUP_MEMBERS_INFO_0, MAX_PREFERRED_LENGTH,
};

use pc_common::sid::sid_to_string;

const ERROR_MORE_DATA: u32 = 234;

/// SIDs der direkten Mitglieder einer lokalen Gruppe (Name in Landessprache,
/// z. B. „Administratoren“).
pub fn members(group: &str) -> Result<Vec<String>, String> {
    let name = HSTRING::from(group);
    let mut out = Vec::new();
    let mut resume: usize = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut read: u32 = 0;
        let mut total: u32 = 0;
        let rc = unsafe {
            NetLocalGroupGetMembers(
                None,
                &name,
                0,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                Some(&mut resume),
            )
        };
        if rc != 0 && rc != ERROR_MORE_DATA {
            return Err(format!(
                "NetLocalGroupGetMembers({group}) fehlgeschlagen (Code {rc})"
            ));
        }
        if !buf.is_null() {
            let items = unsafe {
                std::slice::from_raw_parts(buf as *const LOCALGROUP_MEMBERS_INFO_0, read as usize)
            };
            for it in items {
                let p = it.lgrmi0_sid.0 as *const u8;
                if p.is_null() {
                    continue;
                }
                // Länge aus dem SID-Kopf: 8 Byte + 4 Byte je Unterautorität
                let count = unsafe { *p.add(1) } as usize;
                let bytes = unsafe { std::slice::from_raw_parts(p, 8 + 4 * count) };
                if let Some(s) = sid_to_string(bytes) {
                    out.push(s);
                }
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
