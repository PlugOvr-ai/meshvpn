//! What differs between the operating systems meshvpn runs on.

/// In a `pre_exec` hook: the child gets SIGTERM when meshvpn dies, however it dies (Linux; other
/// systems have no such thing - there children are stopped explicitly).
#[cfg(unix)]
pub fn die_with_parent() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
    }
}

/// This machine's host name.
#[cfg(unix)]
pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    if unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) } != 0 {
        return String::new();
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    let name = String::from_utf8_lossy(&buf[..end]).into_owned();
    // macOS: "MacBook-Pro.local"
    name.strip_suffix(".local").map(str::to_string).unwrap_or(name)
}

/// Running processes with their arguments.
#[cfg(target_os = "linux")]
pub fn processes() -> Vec<(i32, Vec<String>)> {
    let mut out = vec![];
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|p| p.parse::<i32>().ok()) else {
            continue;
        };
        let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let args = raw
            .split(|b| *b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        out.push((pid, args));
    }
    out
}

/// Running processes with their arguments (split at spaces: good enough to find meshvpn's).
#[cfg(all(unix, not(target_os = "linux")))]
pub fn processes() -> Vec<(i32, Vec<String>)> {
    let Ok(out) = std::process::Command::new("ps")
        .args(["-axww", "-o", "pid=,args="])
        .output()
    else {
        return vec![];
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let pid = it.next()?.parse().ok()?;
            Some((pid, it.map(str::to_string).collect()))
        })
        .collect()
}

/// Is process `pid` still there?
#[cfg(unix)]
pub fn alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) }
}

/// The kernel release (`uname -r`).
#[cfg(unix)]
pub fn kernel_release() -> String {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return String::new();
    }
    let r: Vec<u8> = u.release.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
    String::from_utf8_lossy(&r).into_owned()
}

/// The 1-minute load average.
#[cfg(unix)]
pub fn load1() -> f32 {
    let mut l = [0f64; 3];
    if unsafe { libc::getloadavg(l.as_mut_ptr(), 3) } < 1 {
        return 0.0;
    }
    l[0] as f32
}

/// A string or number from sysctl (macOS).
#[cfg(target_os = "macos")]
pub fn sysctl(name: &str) -> Option<Vec<u8>> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut len = 0usize;
    unsafe {
        if libc::sysctlbyname(cname.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
        let mut buf = vec![0u8; len];
        if libc::sysctlbyname(
            cname.as_ptr(),
            buf.as_mut_ptr() as *mut _,
            &mut len,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return None;
        }
        buf.truncate(len);
        Some(buf)
    }
}

#[cfg(target_os = "macos")]
pub fn sysctl_string(name: &str) -> String {
    sysctl(name)
        .map(|b| String::from_utf8_lossy(b.split(|c| *c == 0).next().unwrap_or(&[])).into_owned())
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
pub fn sysctl_u64(name: &str) -> u64 {
    match sysctl(name) {
        Some(b) if b.len() == 8 => u64::from_ne_bytes(b[..8].try_into().unwrap()),
        Some(b) if b.len() == 4 => u32::from_ne_bytes(b[..4].try_into().unwrap()) as u64,
        _ => 0,
    }
}

/// Root (Unix) or an elevated administrator (Windows).
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        win::elevated()
    }
}

/// The account this process runs as.
pub fn user_name() -> Option<String> {
    #[cfg(unix)]
    unsafe {
        let pw = libc::getpwuid(libc::geteuid());
        (!pw.is_null()).then(|| std::ffi::CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned())
    }
    #[cfg(windows)]
    {
        std::env::var("USERNAME").ok().filter(|u| !u.is_empty())
    }
}

/// Unix permission bits; nothing on Windows (files inherit the folder's access list).
#[cfg_attr(windows, allow(unused_variables))]
pub fn set_mode(path: &std::path::Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(windows)]
    {
        Ok(())
    }
}

/// Creates new files readable by the owner only (Unix).
#[cfg_attr(windows, allow(unused_variables))]
pub fn private(opts: &mut std::fs::OpenOptions) -> &mut std::fs::OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts
}

/// Asks process `pid` to stop (SIGTERM; Windows: ends it).
pub fn terminate(pid: i32) -> bool {
    #[cfg(unix)]
    unsafe {
        libc::kill(pid, libc::SIGTERM) == 0
    }
    #[cfg(windows)]
    {
        win::end_process(pid as u32)
    }
}

/// Ends process `pid` (SIGKILL).
pub fn kill(pid: i32) -> bool {
    #[cfg(unix)]
    unsafe {
        libc::kill(pid, libc::SIGKILL) == 0
    }
    #[cfg(windows)]
    {
        win::end_process(pid as u32)
    }
}

#[cfg(windows)]
pub fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default().to_lowercase()
}

/// Windows: meshvpn daemons run as a scheduled task and are managed through it.
#[cfg(windows)]
pub fn processes() -> Vec<(i32, Vec<String>)> {
    vec![]
}

#[cfg(windows)]
pub fn alive(pid: i32) -> bool {
    win::running(pid as u32)
}

#[cfg(windows)]
pub fn kernel_release() -> String {
    // "Microsoft Windows [Version 10.0.22631.4317]"
    std::process::Command::new("cmd")
        .args(["/c", "ver"])
        .output()
        .ok()
        .and_then(|o| {
            let t = String::from_utf8_lossy(&o.stdout).into_owned();
            let v = t.split("Version ").nth(1)?;
            Some(v.trim().trim_end_matches(']').to_string())
        })
        .unwrap_or_default()
}

#[cfg(windows)]
pub fn load1() -> f32 {
    0.0
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, STILL_ACTIVE};
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetExitCodeProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_TERMINATE, TerminateProcess,
    };

    pub fn token_elevated(process: HANDLE) -> bool {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut e as *mut _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            );
            CloseHandle(token);
            ok != 0 && e.TokenIsElevated != 0
        }
    }

    pub fn elevated() -> bool {
        token_elevated(unsafe { GetCurrentProcess() })
    }

    /// Process `pid` runs elevated (an administrator's).
    pub fn pid_elevated(pid: u32) -> bool {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return false;
            }
            let e = token_elevated(h);
            CloseHandle(h);
            e
        }
    }

    pub fn end_process(pid: u32) -> bool {
        unsafe {
            let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if h.is_null() {
                return false;
            }
            let ok = TerminateProcess(h, 1) != 0;
            CloseHandle(h);
            ok
        }
    }

    pub fn running(pid: u32) -> bool {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return false;
            }
            let mut code = 0u32;
            let ok = GetExitCodeProcess(h, &mut code) != 0;
            CloseHandle(h);
            ok && code == STILL_ACTIVE as u32
        }
    }
}

#[cfg(windows)]
pub use win::pid_elevated;

/// IPv4 addresses of this machine's interfaces: (interface, address, prefix length).
#[cfg(unix)]
pub fn ipv4_interfaces() -> Vec<(String, std::net::Ipv4Addr, u8)> {
    let mut out = vec![];
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return out;
    }
    let mut cur = addrs;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null()
            || ifa.ifa_netmask.is_null()
            || unsafe { (*ifa.ifa_addr).sa_family } as i32 != libc::AF_INET
        {
            continue;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let ip = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
        let nm = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in) };
        let ip = std::net::Ipv4Addr::from(u32::from_be(ip.sin_addr.s_addr));
        let prefix = u32::from_be(nm.sin_addr.s_addr).count_ones() as u8;
        out.push((name, ip, prefix));
    }
    unsafe { libc::freeifaddrs(addrs) };
    out
}

#[cfg(windows)]
pub fn ipv4_interfaces() -> Vec<(String, std::net::Ipv4Addr, u8)> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(a) => Some((i.name, a.ip, u32::from(a.netmask).count_ones() as u8)),
            _ => None,
        })
        .collect()
}

/// Runs `cmd` independent of the terminal (and console window) that started it.
pub fn detach(cmd: &mut std::process::Command) {
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
}

/// People's accounts on this machine (and root): (name, home directory).
#[cfg(target_os = "linux")]
pub fn login_users() -> Vec<(String, std::path::PathBuf)> {
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    passwd
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            let uid: u32 = f.get(2)?.parse().ok()?;
            let home = f.get(5)?;
            ((uid == 0 || uid >= 1000) && uid < 65534).then(|| (f[0].to_string(), home.into()))
        })
        .collect()
}

/// macOS keeps accounts in Directory Services, not /etc/passwd; people's homes are in /Users
/// (uids from 501).
#[cfg(target_os = "macos")]
pub fn login_users() -> Vec<(String, std::path::PathBuf)> {
    let mut out = vec![("root".to_string(), std::path::PathBuf::from("/var/root"))];
    for e in std::fs::read_dir("/Users").into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Ok(cname) = std::ffi::CString::new(name.clone()) else {
            continue;
        };
        let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
        if pw.is_null() || unsafe { (*pw).pw_uid } < 500 {
            continue;
        }
        let home = unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) }
            .to_string_lossy()
            .into_owned();
        out.push((name, home.into()));
    }
    out
}

/// Windows: the profiles in C:\\Users (names in lower case, as on the other systems).
#[cfg(windows)]
pub fn login_users() -> Vec<(String, std::path::PathBuf)> {
    let base = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()) + "\\Users";
    std::fs::read_dir(base)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().join(".ssh").is_dir())
        .map(|e| (e.file_name().to_string_lossy().to_lowercase(), e.path()))
        .collect()
}

/// Global IPv6 addresses of this machine (2000::/3: not link-local, not ULA).
pub fn global_ipv6() -> Vec<std::net::Ipv6Addr> {
    let global = |ip: &std::net::Ipv6Addr| ip.segments()[0] & 0xe000 == 0x2000;
    #[cfg(unix)]
    {
        let mut out = vec![];
        let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
            return out;
        }
        let mut cur = addrs;
        while !cur.is_null() {
            let ifa = unsafe { &*cur };
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null() || unsafe { (*ifa.ifa_addr).sa_family } as i32 != libc::AF_INET6 {
                continue;
            }
            let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            if global(&ip) && !out.contains(&ip) {
                out.push(ip);
            }
        }
        unsafe { libc::freeifaddrs(addrs) };
        out
    }
    #[cfg(windows)]
    {
        if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|i| match i.addr {
                if_addrs::IfAddr::V6(a) if global(&a.ip) => Some(a.ip),
                _ => None,
            })
            .collect()
    }
}
