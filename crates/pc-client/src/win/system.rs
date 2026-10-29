//! Systeminformationen, Laufwerke und Prozessprivilegien.

use windows::core::{w, HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_NOT_ALL_ASSIGNED, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, TokenElevation,
    LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
use windows::Win32::System::Registry::{
    RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
};
use windows::Win32::System::SystemInformation::{
    ComputerNameDnsDomain, ComputerNameNetBIOS, GetComputerNameExW, COMPUTER_NAME_FORMAT,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use pc_common::HostInfo;

pub const DRIVE_FIXED: u32 = 3;
pub const DRIVE_REMOTE: u32 = 4;

fn computer_name(fmt: COMPUTER_NAME_FORMAT) -> Option<String> {
    let mut len: u32 = 0;
    unsafe {
        let _ = GetComputerNameExW(fmt, None, &mut len);
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u16; len as usize + 1];
        GetComputerNameExW(fmt, Some(PWSTR(buf.as_mut_ptr())), &mut len).ok()?;
        Some(super::from_wide(&buf)).filter(|s| !s.is_empty())
    }
}

fn reg_string(key: PCWSTR, value: PCWSTR) -> Option<String> {
    let mut buf = vec![0u16; 512];
    let mut size = (buf.len() * 2) as u32;
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key,
            value,
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut _),
            Some(&mut size),
        )
    };
    rc.is_ok()
        .then(|| super::from_wide(&buf))
        .filter(|s| !s.is_empty())
}

fn reg_dword(key: PCWSTR, value: PCWSTR) -> Option<u32> {
    let mut v: u32 = 0;
    let mut size = 4u32;
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key,
            value,
            RRF_RT_REG_DWORD,
            None,
            Some(&mut v as *mut u32 as *mut _),
            Some(&mut size),
        )
    };
    rc.is_ok().then_some(v)
}

pub fn host_info() -> HostInfo {
    let cv = w!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    let build: Option<u32> = reg_string(cv, w!("CurrentBuildNumber")).and_then(|s| s.parse().ok());
    let mut os_name = reg_string(cv, w!("ProductName")).unwrap_or_else(|| "Windows".into());
    // ProductName meldet auf Windows 11 weiterhin „Windows 10“.
    if build.unwrap_or(0) >= 22000 && os_name.starts_with("Windows 10") {
        os_name = os_name.replacen("Windows 10", "Windows 11", 1);
    }
    let display = reg_string(cv, w!("DisplayVersion")).or_else(|| reg_string(cv, w!("ReleaseId")));
    let ubr = reg_dword(cv, w!("UBR"));
    let os_version = match (build, ubr, display) {
        (Some(b), Some(u), Some(d)) => format!("{d} (Build {b}.{u})"),
        (Some(b), Some(u), None) => format!("Build {b}.{u}"),
        (Some(b), None, _) => format!("Build {b}"),
        _ => "unbekannt".into(),
    };
    let product_type = reg_string(
        w!("SYSTEM\\CurrentControlSet\\Control\\ProductOptions"),
        w!("ProductType"),
    );
    let hostname = computer_name(ComputerNameNetBIOS)
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "UNKNOWN".into());
    // Ohne DNS-Domäne ist der Rechner Mitglied einer Arbeitsgruppe.
    let domain = computer_name(ComputerNameDnsDomain);
    HostInfo {
        hostname,
        domain,
        os_name,
        os_version,
        os_build: build,
        is_domain_controller: product_type.as_deref() == Some("LanmanNT"),
        machine_sid: None,
    }
}

/// Laufwerksbuchstaben (`C:`) mit dem gewünschten Typ.
pub fn drives(kind: u32) -> Vec<String> {
    let mask = unsafe { GetLogicalDrives() };
    (0..26u8)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| format!("{}:", (b'A' + i) as char))
        .filter(|d| unsafe { GetDriveTypeW(&HSTRING::from(format!("{d}\\"))) } == kind)
        .collect()
}

struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn open_token() -> Option<Token> {
    let mut h = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut h,
        )
    }
    .ok()?;
    Some(Token(h))
}

/// Prozess läuft mit erhöhten Rechten (Administrator).
pub fn is_elevated() -> bool {
    let Some(t) = open_token() else { return false };
    let mut elev = TOKEN_ELEVATION::default();
    let mut ret = 0u32;
    unsafe {
        GetTokenInformation(
            t.0,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
    }
    .is_ok()
        && elev.TokenIsElevated != 0
}

/// Aktiviert ein Privileg (z. B. `SeBackupPrivilege`). `true` bei Erfolg.
pub fn enable_privilege(name: &str) -> bool {
    let Some(t) = open_token() else { return false };
    let mut luid = LUID::default();
    if unsafe { LookupPrivilegeValueW(PCWSTR::null(), &HSTRING::from(name), &mut luid) }.is_err() {
        return false;
    }
    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    let ok = unsafe { AdjustTokenPrivileges(t.0, false, Some(&tp), 0, None, None) }.is_ok();
    ok && unsafe { GetLastError() } != ERROR_NOT_ALL_ASSIGNED
}
