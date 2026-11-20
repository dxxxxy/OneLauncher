//! The game starts from a clean environment. The launcher's own may hold
//! tokens (CI secrets, GitHub tokens in a dev shell, proxy passwords) that a
//! mod could read with one `System.getenv()`

use std::ffi::OsStr;

const EXACT: &[&str] = &[
    // every platform
    "PATH",
    "LANG",
    "LANGUAGE",
    "TZ",
    "USER",
    "USERNAME",
    "LOGNAME",
    // Windows
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "PATHEXT",
    "COMSPEC",
    "OS",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "COMMONPROGRAMFILES",
    "PROGRAMDATA",
    "PUBLIC",
    // Linux desktop: display, audio, GPU
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
    "XAUTHORITY",
    "PULSE_SERVER",
    "DRI_PRIME",
    "vblank_mode",
    "LIBGL_ALWAYS_SOFTWARE",
];

const PREFIXES: &[&str] = &["LC_", "__GL", "__NV", "MESA", "VK_", "SDL_", "_JAVA_AWT"];

/// Kept for the game when the launcher has it
pub(crate) fn passes(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    EXACT.iter().any(|k| k.eq_ignore_ascii_case(key))
        || PREFIXES
            .iter()
            .any(|p| upper.starts_with(&p.to_ascii_uppercase()))
}

pub(crate) fn same_key(a: &OsStr, b: &OsStr) -> bool {
    if cfg!(windows) {
        a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
    } else {
        a == b
    }
}

#[cfg(test)]
mod tests {
    use super::passes;

    #[test]
    fn secrets_in_the_environment_stay_with_the_launcher() {
        assert!(passes("PATH"));
        assert!(passes("LC_ALL"));
        assert!(passes("__GL_THREADED_OPTIMIZATIONS"));
        assert!(!passes("GITHUB_TOKEN"));
        assert!(!passes("AWS_SECRET_ACCESS_KEY"));
        assert!(!passes("APPDATA"));
        assert!(!passes("HOME"));
        assert!(!passes("DBUS_SESSION_BUS_ADDRESS"));
        assert!(!passes("SSH_AUTH_SOCK"));
    }
}
