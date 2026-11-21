//! AppContainer sandbox
//!
//! Every instance gets its own AppContainer, so one instance can't read
//! another. An AppContainer token denies access to everything that doesn't
//! grant its SID (or `ALL APPLICATION PACKAGES`) explicitly. The user's
//! profile, browser data and other launchers never do. We grant:
//!
//! - read/execute on the launcher's runtime files to one custom capability
//!   SID every instance carries
//! - full access on the instance's own folders to the instance's SID
//!
//! Mods are hardlinked into instances from the shared content store, and a
//! hardlink shares one security descriptor. Propagating an instance grant
//! onto a hardlinked jar would give that instance write access to the store's
//! copy, so hardlinked files get a protected DACL before any propagation.

use std::ffi::{OsStr, OsString, c_void};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LocalFree,
    SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SetEntriesInAclW,
    SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, DeriveCapabilitySidsFromName, FreeSid,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_CAPABILITIES,
    SID_AND_ATTRIBUTES, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JobObjectBasicUIRestrictions, SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};

use crate::{Protection, SandboxError, SandboxPolicy, SandboxResult, SpawnSpec};

/// `SE_GROUP_ENABLED`
const SE_GROUP_ENABLED: u32 = 4;
const RUNTIME_CAPABILITY: &str = "oneclientRuntime";
const INTERNET_CLIENT: &str = "S-1-15-3-1";
/// Inbound connections from the internet: Poly+ parties and voice (EOS
/// peer to peer) and servers the game hosts itself
const INTERNET_CLIENT_SERVER: &str = "S-1-15-3-2";
const PRIVATE_NETWORK: &str = "S-1-15-3-3";
const MARKER: &str = ".oneclient-acl-v1";

const READ_EXECUTE: u32 = 0x0012_0089 | 0x0012_00a0;
const MODIFY: u32 = 0x0012_0089 | 0x0012_0116 | 0x0012_00a0 | 0x0001_0000 | 0x0000_0040;

const ERROR_ALREADY_EXISTS_HRESULT: i32 = 0x8007_00B7_u32 as i32;

fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

fn last_error(what: &str) -> SandboxError {
    SandboxError::Setup(format!("{what}: {}", std::io::Error::last_os_error()))
}

/// A SID and how Windows wants it freed
struct Sid {
    ptr: PSID,
    free_with_local_free: bool,
}

unsafe impl Send for Sid {}
unsafe impl Sync for Sid {}

impl Sid {
    fn from_string(s: &str) -> SandboxResult<Self> {
        let mut ptr: PSID = std::ptr::null_mut();
        // SAFETY: valid NUL-terminated string, valid out pointer
        if unsafe { ConvertStringSidToSidW(wide(s).as_ptr(), &mut ptr) } == 0 {
            return Err(last_error("bad SID"));
        }
        Ok(Self {
            ptr,
            free_with_local_free: true,
        })
    }

    fn capability(name: &str) -> SandboxResult<Self> {
        let mut groups: *mut PSID = std::ptr::null_mut();
        let mut group_count = 0u32;
        let mut caps: *mut PSID = std::ptr::null_mut();
        let mut cap_count = 0u32;
        // SAFETY: all out pointers are valid
        let ok = unsafe {
            DeriveCapabilitySidsFromName(
                wide(name).as_ptr(),
                &mut groups,
                &mut group_count,
                &mut caps,
                &mut cap_count,
            )
        };
        if ok == 0 || cap_count == 0 {
            return Err(last_error("could not derive a capability SID"));
        }
        // SAFETY: arrays of `count` LocalAlloc'd SIDs; keep the first
        // capability SID, free everything else
        unsafe {
            for i in 0..group_count as usize {
                LocalFree(*groups.add(i));
            }
            LocalFree(groups.cast());
            let keep = *caps;
            for i in 1..cap_count as usize {
                LocalFree(*caps.add(i));
            }
            LocalFree(caps.cast());
            Ok(Self {
                ptr: keep,
                free_with_local_free: true,
            })
        }
    }

    fn to_string_sid(&self) -> SandboxResult<String> {
        let mut out: windows_sys::core::PWSTR = std::ptr::null_mut();
        // SAFETY: valid SID, valid out pointer
        if unsafe { ConvertSidToStringSidW(self.ptr, &mut out) } == 0 {
            return Err(last_error("could not format a SID"));
        }
        // SAFETY: NUL-terminated LocalAlloc'd string
        unsafe {
            let len = (0..).take_while(|&i| *out.add(i) != 0).count();
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(out, len));
            LocalFree(out.cast());
            Ok(s)
        }
    }
}

impl Drop for Sid {
    fn drop(&mut self) {
        // SAFETY: allocated by the matching API
        unsafe {
            if self.free_with_local_free {
                LocalFree(self.ptr);
            } else {
                FreeSid(self.ptr);
            }
        }
    }
}

fn container_name(instance_id: i64) -> String {
    format!("OneClient.Cluster.{instance_id}")
}

fn container_sid(instance_id: i64) -> SandboxResult<Sid> {
    let name = wide(container_name(instance_id));
    let display = wide(format!("OneClient instance {instance_id}"));
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: valid strings, no capabilities, valid out pointer
    let hr = unsafe {
        CreateAppContainerProfile(
            name.as_ptr(),
            display.as_ptr(),
            display.as_ptr(),
            std::ptr::null(),
            0,
            &mut sid,
        )
    };
    if hr == ERROR_ALREADY_EXISTS_HRESULT {
        // SAFETY: valid name, valid out pointer
        let hr = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
        if hr < 0 {
            return Err(SandboxError::Setup(format!(
                "could not find the AppContainer (0x{hr:08x})"
            )));
        }
    } else if hr < 0 {
        return Err(SandboxError::Setup(format!(
            "could not create the AppContainer (0x{hr:08x})"
        )));
    }
    Ok(Sid {
        ptr: sid,
        free_with_local_free: false,
    })
}

pub(crate) fn grant_live(instance_id: i64, path: &Path, write: bool) -> SandboxResult<()> {
    let sid = container_sid(instance_id)?;
    let sid_string = sid.to_string_sid()?;
    if path.is_file() {
        grant(path, &sid, if write { MODIFY } else { READ_EXECUTE })
    } else {
        grant_once(
            path,
            &sid,
            &sid_string,
            if write { MODIFY } else { READ_EXECUTE },
            true,
        )
    }
}

/// Takes back a folder the user stopped sharing
pub(crate) fn revoke(instance_id: i64, path: &Path) -> SandboxResult<()> {
    let sid = container_sid(instance_id)?;
    let sid_string = sid.to_string_sid()?;
    set_entry(
        path,
        &sid,
        0,
        windows_sys::Win32::Security::Authorization::REVOKE_ACCESS,
    )?;
    let _ = std::fs::remove_file(path.join(format!("{MARKER}-{}", short_hash(&sid_string))));
    Ok(())
}

pub(crate) fn forget(instance_id: i64) {
    // SAFETY: valid NUL-terminated name
    unsafe { DeleteAppContainerProfile(wide(container_name(instance_id)).as_ptr()) };
}

/// Adds an inheritable allow entry for `sid` and lets Windows propagate it
fn grant(path: &Path, sid: &Sid, access: u32) -> SandboxResult<()> {
    set_entry(path, sid, access, GRANT_ACCESS)
}

fn set_entry(
    path: &Path,
    sid: &Sid,
    access: u32,
    mode: windows_sys::Win32::Security::Authorization::ACCESS_MODE,
) -> SandboxResult<()> {
    let name = wide(path);
    let mut old: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: valid path and out pointers
    let err = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut old,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if err != 0 {
        return Err(SandboxError::Setup(format!(
            "could not read permissions of {}: error {err}",
            path.display()
        )));
    }

    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access,
        grfAccessMode: mode,
        grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstrName: sid.ptr.cast(),
        },
    };
    let mut new: *mut ACL = std::ptr::null_mut();
    // SAFETY: `old` belongs to `descriptor`, still alive
    let err = unsafe { SetEntriesInAclW(1, &entry, old, &mut new) };
    if err != 0 {
        unsafe { LocalFree(descriptor) };
        return Err(SandboxError::Setup(format!(
            "could not build permissions: error {err}"
        )));
    }
    // SAFETY: valid path and ACL
    let err = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new,
            std::ptr::null(),
        )
    };
    unsafe {
        LocalFree(new.cast());
        LocalFree(descriptor);
    }
    if err != 0 {
        return Err(SandboxError::Setup(format!(
            "could not set permissions on {}: error {err}",
            path.display()
        )));
    }
    Ok(())
}

/// Freezes a file's current permissions so propagation from a parent folder
/// never changes them
fn protect(path: &Path) -> SandboxResult<()> {
    let name = wide(path);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: as in grant
    let err = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if err != 0 {
        return Err(SandboxError::Setup(format!(
            "could not read {}: {err}",
            path.display()
        )));
    }
    // SAFETY: dacl belongs to descriptor
    let err = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    unsafe { LocalFree(descriptor) };
    if err != 0 {
        return Err(SandboxError::Setup(format!(
            "could not protect {}: {err}",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn link_count(path: &Path) -> Option<u32> {
    let file = std::fs::File::open(path).ok()?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: valid open handle, valid out struct
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return None;
    }
    Some(info.nNumberOfLinks)
}

/// Protects every hardlinked file under `root` (they are content-store
/// copies shared with other instances)
fn protect_hardlinks(root: &Path) -> SandboxResult<usize> {
    let mut protected = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if kind.is_symlink() {
                // junctions and symlinks point at shared folders; never walk
                // into them and never propagate onto them
                continue;
            }
            if kind.is_dir() {
                stack.push(path);
            } else if link_count(&path).is_some_and(|n| n > 1) {
                protect(&path)?;
                protected += 1;
            }
        }
    }
    Ok(protected)
}

/// Grants once; a marker records it so later launches are instant. New
/// files inherit the entry, so the grant never needs repeating
///
/// `shield_links` freezes hardlinked files first. Off for the runtime grant:
/// the content store's files are the hardlink targets and must inherit the
/// runtime read entry before instance grants freeze them
fn grant_once(
    path: &Path,
    sid: &Sid,
    sid_string: &str,
    access: u32,
    shield_links: bool,
) -> SandboxResult<()> {
    std::fs::create_dir_all(path)?;
    let marker = path.join(format!("{MARKER}-{}", short_hash(sid_string)));
    if marker.exists() {
        return Ok(());
    }
    let protected = if shield_links {
        protect_hardlinks(path)?
    } else {
        0
    };
    grant(path, sid, access)?;
    std::fs::write(&marker, b"")?;
    tracing::debug!(path = %path.display(), protected, "granted sandbox access");
    Ok(())
}

fn short_hash(s: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    format!("{:016x}", h.finish())
}

pub(crate) struct Container {
    home: PathBuf,
    temp: PathBuf,
    sid: Arc<Sid>,
    sid_string: String,
    capabilities: Vec<Sid>,
    localhost: bool,
}

impl Container {
    pub(crate) fn prepare(policy: &SandboxPolicy) -> SandboxResult<Self> {
        let sid = container_sid(policy.instance_id)?;
        let sid_string = sid.to_string_sid()?;
        let runtime = Sid::capability(RUNTIME_CAPABILITY)?;
        let runtime_string = runtime.to_string_sid()?;

        // runtime first: store files must carry the runtime entry before an
        // instance grant freezes the ones hardlinked into it
        for dir in &policy.runtime {
            if dir.is_file() {
                grant(dir, &runtime, READ_EXECUTE)?;
            } else {
                grant_once(dir, &runtime, &runtime_string, READ_EXECUTE, false)?;
            }
        }
        for dir in &policy.extra_read_only {
            if dir.is_file() {
                grant(dir, &sid, READ_EXECUTE)?;
            } else {
                grant_once(dir, &sid, &sid_string, READ_EXECUTE, true)?;
            }
        }
        for dir in policy.read_write.iter().chain(&policy.extra_read_write) {
            grant_once(dir, &sid, &sid_string, MODIFY, true)?;
        }

        // an AppContainer without the network capabilities has no network
        let mut capabilities = vec![runtime];
        if !policy.offline {
            capabilities.push(Sid::from_string(INTERNET_CLIENT)?);
            capabilities.push(Sid::from_string(INTERNET_CLIENT_SERVER)?);
            capabilities.push(Sid::from_string(PRIVATE_NETWORK)?);
        }
        if policy.microphone {
            capabilities.push(Sid::capability("microphone")?);
        }
        // what's playing and play/pause/skip (Evergreen HUD's music widget,
        // Poly+'s pause screen): the media session manager refuses an
        // AppContainer without it. It reads titles, not the user's files
        capabilities.push(Sid::capability("globalMediaControl")?);

        if policy.localhost {
            exempt_loopback(&sid_string, &policy.home);
        }
        if let Err(err) = allow_cursor_control(&sid) {
            // the game still runs; only LWJGL 2's grabbed mouse misbehaves
            tracing::warn!("could not let the game move its cursor: {err}");
        }

        Ok(Self {
            home: policy.home.clone(),
            temp: policy.temp.clone(),
            sid: Arc::new(sid),
            sid_string,
            capabilities,
            localhost: policy.localhost,
        })
    }

    pub(crate) fn sid_string(&self) -> &str {
        &self.sid_string
    }

    pub(crate) fn protection(&self) -> Protection {
        expected(self.localhost)
    }

    pub(crate) fn spawn(&self, mut spec: SpawnSpec) -> std::io::Result<crate::GameChild> {
        // CreateProcess rewrites these for the AppContainer and fails with
        // ERROR_ENVVAR_NOT_FOUND when one is missing; they point into the
        // instance anyway
        let defaults = [
            ("USERPROFILE", self.home.clone()),
            ("APPDATA", self.home.join("AppData").join("Roaming")),
            ("LOCALAPPDATA", self.home.join("AppData").join("Local")),
            ("TEMP", self.temp.clone()),
            ("TMP", self.temp.clone()),
        ];
        for (key, value) in defaults {
            let present = spec
                .env
                .iter()
                .any(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case(key));
            if !present {
                let _ = std::fs::create_dir_all(&value);
                spec.set_env(key, value);
            }
        }
        spawn_in(self, spec).map(crate::GameChild::Raw)
    }
}

/// LWJGL 2 recenters a grabbed mouse with `SetCursorPos` and keeps it in the
/// window with `ClipCursor`. Both need `WINSTA_WRITEATTRIBUTES` on the window
/// station, which AppContainers don't get, and without it 1.8.9's camera
/// spins. Grants exactly that to this instance's container, for this logon
/// session only (window station permissions don't persist)
fn allow_cursor_control(sid: &Sid) -> SandboxResult<()> {
    use windows_sys::Win32::Security::Authorization::{
        GetSecurityInfo, SE_WINDOW_OBJECT, SetSecurityInfo,
    };
    use windows_sys::Win32::System::StationsAndDesktops::{CloseWindowStation, OpenWindowStationW};
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WINSTA_READATTRIBUTES: u32 = 0x0002;
    const WINSTA_WRITEATTRIBUTES: u32 = 0x0010;

    // SAFETY: valid NUL-terminated name
    let station =
        unsafe { OpenWindowStationW(wide("WinSta0").as_ptr(), 0, READ_CONTROL | WRITE_DAC) };
    if station.is_null() {
        return Err(last_error("could not open the window station"));
    }
    let mut old: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: valid handle and out pointers
    let err = unsafe {
        GetSecurityInfo(
            station,
            SE_WINDOW_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut old,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    let result = if err != 0 {
        Err(SandboxError::Setup(format!(
            "could not read the window station's permissions: error {err}"
        )))
    } else {
        // GRANT_ACCESS merges with an entry from an earlier launch rather
        // than adding another
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: WINSTA_READATTRIBUTES | WINSTA_WRITEATTRIBUTES,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: 0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: sid.ptr.cast(),
            },
        };
        let mut new: *mut ACL = std::ptr::null_mut();
        // SAFETY: `old` belongs to `descriptor`, still alive
        let err = unsafe { SetEntriesInAclW(1, &entry, old, &mut new) };
        let result = if err != 0 {
            Err(SandboxError::Setup(format!(
                "could not build the window station's permissions: error {err}"
            )))
        } else {
            // SAFETY: valid handle and ACL
            let err = unsafe {
                SetSecurityInfo(
                    station,
                    SE_WINDOW_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    new,
                    std::ptr::null(),
                )
            };
            unsafe { LocalFree(new.cast()) };
            if err != 0 {
                Err(SandboxError::Setup(format!(
                    "could not set the window station's permissions: error {err}"
                )))
            } else {
                Ok(())
            }
        };
        unsafe { LocalFree(descriptor) };
        result
    };
    // SAFETY: opened above
    unsafe { CloseWindowStation(station) };
    result
}

/// AppContainers can't reach loopback by default; lifting that needs admin
/// once per container
fn exempt_loopback(sid: &str, home: &Path) {
    let marker = home.join(".loopback-exempt");
    if marker.exists() {
        return;
    }
    let status = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Start-Process CheckNetIsolation.exe -ArgumentList 'LoopbackExempt -a -p={sid}' -Verb RunAs -Wait -WindowStyle Hidden"
            ),
        ])
        .status();
    if status.is_ok_and(|s| s.success()) {
        let _ = std::fs::write(marker, b"");
    } else {
        tracing::warn!("could not exempt the instance from loopback isolation");
    }
}

// ---- process creation

/// MSVC command-line quoting, the rules `CommandLineToArgvW` undoes
fn quote(arg: &OsStr, out: &mut Vec<u16>) {
    let arg: Vec<u16> = arg.encode_wide().collect();
    let needs = arg.is_empty()
        || arg
            .iter()
            .any(|&c| c == b' ' as u16 || c == b'\t' as u16 || c == b'"' as u16);
    if !needs {
        out.extend_from_slice(&arg);
        return;
    }
    out.push(b'"' as u16);
    let mut backslashes = 0;
    for &c in &arg {
        if c == b'\\' as u16 {
            backslashes += 1;
        } else if c == b'"' as u16 {
            out.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
            out.push(c);
            backslashes = 0;
        } else {
            out.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            out.push(c);
            backslashes = 0;
        }
    }
    out.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    out.push(b'"' as u16);
}

fn command_line(program: &Path, args: &[OsString]) -> Vec<u16> {
    let mut out = Vec::new();
    quote(program.as_os_str(), &mut out);
    for arg in args {
        out.push(b' ' as u16);
        quote(arg, &mut out);
    }
    out.push(0);
    out
}

fn environment_block(env: &[(OsString, OsString)]) -> Vec<u16> {
    let mut sorted: Vec<_> = env.iter().collect();
    sorted.sort_by_key(|(k, _)| k.to_string_lossy().to_uppercase());
    let mut block = Vec::new();
    for (key, value) in sorted {
        block.extend(key.encode_wide());
        block.push(b'=' as u16);
        block.extend(value.encode_wide());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

struct Handle(HANDLE);
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: we own the handle
            unsafe { CloseHandle(self.0) };
        }
    }
}

pub struct RawChild {
    pub pid: u32,
    process: Arc<Handle>,
    _job: Handle,
}

impl RawChild {
    pub(crate) async fn wait(&self) -> std::io::Result<ExitStatus> {
        use std::os::windows::process::ExitStatusExt;
        let process = Arc::clone(&self.process);
        tokio::task::spawn_blocking(move || {
            // SAFETY: valid process handle kept alive by the Arc
            if unsafe { WaitForSingleObject(process.0, INFINITE) } != WAIT_OBJECT_0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut code = 0u32;
            // SAFETY: as above
            if unsafe { GetExitCodeProcess(process.0, &mut code) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(ExitStatus::from_raw(code))
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub(crate) fn kill(&self) -> std::io::Result<()> {
        // SAFETY: valid process handle
        if unsafe { TerminateProcess(self.process.0, 1) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

fn inheritable(file: &std::fs::File) -> std::io::Result<HANDLE> {
    let handle = file.as_raw_handle();
    // SAFETY: valid handle owned by `file`
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(handle)
}

fn spawn_in(container: &Container, spec: SpawnSpec) -> std::io::Result<RawChild> {
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("NUL")?;
    let stdin = inheritable(&null)?;
    let stdout_file = match spec.stdout {
        Some(file) => file,
        None => null.try_clone()?,
    };
    let stderr_file = match spec.stderr {
        Some(file) => file,
        None => null.try_clone()?,
    };
    let stdout = inheritable(&stdout_file)?;
    let stderr = inheritable(&stderr_file)?;
    let mut handles: Vec<HANDLE> = vec![stdin, stdout];
    if stderr != stdout {
        handles.push(stderr);
    }

    let mut capability_entries: Vec<SID_AND_ATTRIBUTES> = container
        .capabilities
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.ptr,
            Attributes: SE_GROUP_ENABLED,
        })
        .collect();
    let security = SECURITY_CAPABILITIES {
        AppContainerSid: container.sid.ptr,
        Capabilities: capability_entries.as_mut_ptr(),
        CapabilityCount: capability_entries.len() as u32,
        Reserved: 0,
    };

    // ---- attribute list
    let mut size = 0usize;
    // SAFETY: size query
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut size) };
    let mut storage = vec![0u64; size.div_ceil(8)];
    let list = storage.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
    // SAFETY: storage is `size` bytes, suitably aligned
    if unsafe { InitializeProcThreadAttributeList(list, 2, 0, &mut size) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    struct ListGuard(LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for ListGuard {
        fn drop(&mut self) {
            // SAFETY: initialised above
            unsafe { DeleteProcThreadAttributeList(self.0) };
        }
    }
    let _guard = ListGuard(list);

    // SAFETY: the values outlive CreateProcessW below
    unsafe {
        if UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            (&security as *const SECURITY_CAPABILITIES).cast::<c_void>(),
            size_of::<SECURITY_CAPABILITIES>(),
            std::ptr::null_mut(),
            std::ptr::null(),
        ) == 0
            || UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast::<c_void>(),
                handles.len() * size_of::<HANDLE>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            ) == 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }

    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin;
    startup.StartupInfo.hStdOutput = stdout;
    startup.StartupInfo.hStdError = stderr;
    startup.lpAttributeList = list;

    let program = resolve_program(&spec.program, &spec.env);
    let mut line = command_line(&program, &spec.args);
    let env = environment_block(&spec.env);
    let cwd = wide(&spec.cwd);
    let application = wide(&program);
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // SAFETY: every buffer is NUL-terminated and alive for the call
    let ok = unsafe {
        CreateProcessW(
            application.as_ptr(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT
                | CREATE_UNICODE_ENVIRONMENT
                | CREATE_SUSPENDED
                | crate::DETACHED_FLAGS,
            env.as_ptr().cast(),
            cwd.as_ptr(),
            &startup.StartupInfo,
            &mut info,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let process = Handle(info.hProcess);
    let thread = Handle(info.hThread);

    let job = Handle(unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) });
    if !job.0.is_null() {
        let limits = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
        };
        // SAFETY: valid job and process handles
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectBasicUIRestrictions,
                (&limits as *const JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
                size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            );
            if AssignProcessToJobObject(job.0, process.0) == 0 {
                tracing::warn!("could not put the game in a job: {}", GetLastError());
            }
        }
    }

    // SAFETY: suspended main thread of the process we just made
    if unsafe { ResumeThread(thread.0) } == u32::MAX {
        let err = std::io::Error::last_os_error();
        unsafe { TerminateProcess(process.0, 1) };
        return Err(err);
    }
    drop(thread);
    drop((stdout_file, stderr_file, null));

    Ok(RawChild {
        pid: info.dwProcessId,
        process: Arc::new(process),
        _job: job,
    })
}

/// CreateProcessW with an application name does no PATH search; resolve a
/// bare program name (a wrapper like `gamemoderun`) the way a shell would
fn resolve_program(program: &Path, env: &[(OsString, OsString)]) -> PathBuf {
    if program.is_absolute() || program.components().count() > 1 {
        return program.to_path_buf();
    }
    let path = env
        .iter()
        .find(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case("PATH"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        for ext in ["", ".exe", ".com", ".bat", ".cmd"] {
            let candidate = dir.join(format!("{}{ext}", program.display()));
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    program.to_path_buf()
}

/// What a container for this policy reports, without making one
pub(crate) fn expected(localhost: bool) -> Protection {
    if localhost {
        Protection::Partial(vec![
            "This instance can reach servers running on this computer".into(),
        ])
    } else {
        Protection::Full
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(args: &[&str]) -> String {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let w = command_line(Path::new(r"C:\Program Files\Java\bin\java.exe"), &args);
        String::from_utf16_lossy(&w[..w.len() - 1])
    }

    #[test]
    fn quotes_like_the_c_runtime() {
        assert_eq!(
            line(&[
                "-Xmx2G",
                "a b",
                r#"say "hi""#,
                r"C:\dir\",
                r"C:\my dir\",
                ""
            ]),
            r#""C:\Program Files\Java\bin\java.exe" -Xmx2G "a b" "say \"hi\"" C:\dir\ "C:\my dir\\" """#
        );
    }

    #[test]
    fn environment_blocks_are_sorted_and_double_terminated() {
        let block = environment_block(&[("b".into(), "2".into()), ("A".into(), "1".into())]);
        assert_eq!(String::from_utf16_lossy(&block), "A=1\0b=2\0\0");
    }
}
