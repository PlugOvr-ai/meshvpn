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
