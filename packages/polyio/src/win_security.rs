//! Security descriptors for Windows objects the launcher creates
//!
//! Named pipes made without one get the default DACL, which is fine against
//! other users but says nothing about sandboxed processes. These helpers build
//! an explicit "only this user, never an AppContainer" descriptor so a game
//! running inside a sandbox can never reach the launcher's control channels

use std::ffi::c_void;
use std::io;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// `ALL APPLICATION PACKAGES` and `ALL RESTRICTED APPLICATION PACKAGES`
/// every AppContainer token carries one of these
const APP_PACKAGE_SIDS: [&str; 2] = ["AC", "S-1-15-2-2"];

/// A security descriptor allocated by Windows and freed on drop
pub struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is an immutable self-relative blob once built
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();

        // SAFETY: `wide` is NUL-terminated and outlives the call, the out
        // pointer is valid, and the size out-param is optional
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }

    /// Full access for the current user only; AppContainers are denied
    /// explicitly so a later grant to a capability SID can never let one in
    pub fn current_user_only() -> io::Result<Self> {
        Self::from_sddl(&current_user_only_sddl(&current_user_sid()?))
    }

    /// `SECURITY_ATTRIBUTES` borrowing this descriptor, not inheritable
    pub fn attributes(&self) -> SecurityAttributes<'_> {
        SecurityAttributes {
            raw: SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0,
                bInheritHandle: 0,
            },
            _descriptor: std::marker::PhantomData,
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW
        unsafe { LocalFree(self.0) };
    }
}

pub struct SecurityAttributes<'a> {
    raw: SECURITY_ATTRIBUTES,
    _descriptor: std::marker::PhantomData<&'a SecurityDescriptor>,
}

impl SecurityAttributes<'_> {
    /// For APIs like tokio's `create_with_security_attributes_raw`
    pub fn as_mut_ptr(&mut self) -> *mut c_void {
        (&mut self.raw as *mut SECURITY_ATTRIBUTES).cast()
    }
}

/// SDDL granting `user_sid` full access, denying every AppContainer, with a
/// protected DACL so nothing inherited can widen it
pub fn current_user_only_sddl(user_sid: &str) -> String {
    let mut sddl = String::from("D:P");
    for sid in APP_PACKAGE_SIDS {
        sddl.push_str(&format!("(D;;GA;;;{sid})"));
    }
    sddl.push_str(&format!("(A;;GA;;;{user_sid})"));
    sddl
}

/// The string SID (`S-1-5-21-…`) of the user this process runs as
pub fn current_user_sid() -> io::Result<String> {
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            // SAFETY: opened by OpenProcessToken below
            unsafe { CloseHandle(self.0) };
        }
    }

    let mut handle: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo handle, out pointer is valid
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Token(handle);

    let mut len = 0u32;
    // SAFETY: a size query with a null buffer is the documented first call
    unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }

    // u64 storage keeps TOKEN_USER suitably aligned
    let mut buffer = vec![0u64; (len as usize).div_ceil(size_of::<u64>())];
    // SAFETY: buffer holds at least `len` bytes
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            len,
            &mut len,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: GetTokenInformation filled the buffer with a TOKEN_USER
    let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    let mut string: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: the SID points into `buffer`, which is still alive
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut string) } == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated LocalAlloc string
    let sid = unsafe {
        let len = (0..).take_while(|&i| *string.add(i) != 0).count();
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(string, len));
        LocalFree(string.cast());
        sid
    };
    Ok(sid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sddl_denies_app_containers_before_granting_the_user() {
        let sddl = current_user_only_sddl("S-1-5-21-1-2-3-1001");

        assert_eq!(
            sddl,
            "D:P(D;;GA;;;AC)(D;;GA;;;S-1-15-2-2)(A;;GA;;;S-1-5-21-1-2-3-1001)"
        );
    }

    #[test]
    fn builds_a_descriptor_for_the_current_user() {
        let sid = current_user_sid().expect("user sid");
        assert!(sid.starts_with("S-1-"), "{sid}");

        let descriptor = SecurityDescriptor::current_user_only().expect("descriptor");
        let mut attributes = descriptor.attributes();
        assert!(!attributes.as_mut_ptr().is_null());
    }

    #[tokio::test]
    async fn the_current_user_can_still_open_a_protected_pipe() {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

        let name = format!(r"\\.\pipe\polyio-win-security-test-{}", std::process::id());
        let descriptor = SecurityDescriptor::current_user_only().expect("descriptor");
        let mut attributes = descriptor.attributes();
        // SAFETY: attributes and descriptor outlive the call
        let server = unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .create_with_security_attributes_raw(&name, attributes.as_mut_ptr())
        }
        .expect("create pipe");

        let client = ClientOptions::new().open(&name);
        assert!(client.is_ok(), "{:?}", client.err());
        drop(server);
    }
}
