//! Auflösung von SIDs in Kontonamen (mit Cache).

use std::collections::HashMap;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NONE_MAPPED};
use windows::Win32::Security::{LookupAccountSidW, PSID, SID_NAME_USE};

use pc_common::sid::string_to_sid;
use pc_common::{wellknown, PrincipalInfo, PrincipalKind};

#[derive(Default)]
pub struct SidResolver {
    cache: HashMap<String, PrincipalInfo>,
}

impl SidResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resolve(&mut self, sid: &str) -> &PrincipalInfo {
        if !self.cache.contains_key(sid) {
            let info = lookup(sid);
            self.cache.insert(sid.to_string(), info);
        }
        &self.cache[sid]
    }

    pub fn is_orphaned(&mut self, sid: &str) -> bool {
        self.resolve(sid).kind.is_orphaned()
    }

    pub fn into_principals(self) -> Vec<PrincipalInfo> {
        let mut v: Vec<_> = self.cache.into_values().collect();
        v.sort_by(|a, b| a.sid.cmp(&b.sid));
        v
    }
}

fn lookup(sid: &str) -> PrincipalInfo {
    let mut info = PrincipalInfo {
        sid: sid.to_string(),
        name: None,
        domain: None,
        kind: PrincipalKind::Unknown,
    };
    let Some(mut bin) = string_to_sid(sid) else {
        return info;
    };
    let psid = PSID(bin.as_mut_ptr() as *mut _);
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    for _ in 0..2 {
        let mut name_len = name.len() as u32;
        let mut dom_len = domain.len() as u32;
        let mut use_ = SID_NAME_USE(0);
        let r = unsafe {
            LookupAccountSidW(
                PCWSTR::null(),
                psid,
                Some(PWSTR(name.as_mut_ptr())),
                &mut name_len,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut dom_len,
                &mut use_,
            )
        };
        match r {
            Ok(()) => {
                info.name = Some(super::from_wide(&name)).filter(|s| !s.is_empty());
                info.domain = Some(super::from_wide(&domain)).filter(|s| !s.is_empty());
                info.kind = map_use(use_.0);
                return info;
            }
            Err(e) if e.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => {
                name.resize(name_len as usize + 1, 0);
                domain.resize(dom_len as usize + 1, 0);
            }
            Err(e) if e.code() == ERROR_NONE_MAPPED.to_hresult() => {
                if let Some(n) = wellknown::well_known_name(sid) {
                    info.name = Some(n.to_string());
                    info.kind = PrincipalKind::WellKnownGroup;
                } else if wellknown::is_well_known(sid) {
                    info.kind = PrincipalKind::WellKnownGroup;
                } else {
                    info.kind = PrincipalKind::Unresolved;
                }
                return info;
            }
            Err(_) => return info,
        }
    }
    info
}

fn map_use(u: i32) -> PrincipalKind {
    match u {
        1 => PrincipalKind::User,
        2 => PrincipalKind::Group,
        4 => PrincipalKind::Alias,
        5 => PrincipalKind::WellKnownGroup,
        6 => PrincipalKind::Deleted,
        8 => PrincipalKind::Unresolved,
        9 => PrincipalKind::Computer,
        _ => PrincipalKind::Other,
    }
}
