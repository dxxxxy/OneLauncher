//! Checks whether a game can switch the display mode where this runs (used
//! inside the sandbox through `probe`). LWJGL 2's fullscreen calls
//! `ChangeDisplaySettingsExW(.., CDS_FULLSCREEN)`; this asks for the mode the
//! screen is already in, so nothing visibly changes, then resets it
#[cfg(windows)]
fn main() {
    use std::ffi::c_void;
    #[link(name = "user32")]
    unsafe extern "system" {
        fn EnumDisplaySettingsW(device: *const u16, mode: u32, devmode: *mut u8) -> i32;
        fn ChangeDisplaySettingsExW(
            device: *const u16,
            devmode: *const u8,
            hwnd: *mut c_void,
            flags: u32,
            param: *mut c_void,
        ) -> i32;
    }
    const ENUM_CURRENT_SETTINGS: u32 = u32::MAX;
    const CDS_FULLSCREEN: u32 = 4;
    // DEVMODEW is 220 bytes; dmSize sits after the 32-char device name and two u16s
    let mut devmode = [0u8; 220];
    devmode[68..70].copy_from_slice(&220u16.to_le_bytes());
    unsafe {
        let read = EnumDisplaySettingsW(std::ptr::null(), ENUM_CURRENT_SETTINGS, devmode.as_mut_ptr());
        println!("EnumDisplaySettings -> {read}");
        let set = ChangeDisplaySettingsExW(
            std::ptr::null(),
            devmode.as_ptr(),
            std::ptr::null_mut(),
            CDS_FULLSCREEN,
            std::ptr::null_mut(),
        );
        println!(
            "ChangeDisplaySettingsEx(CDS_FULLSCREEN) -> {set} ({})",
            std::io::Error::last_os_error()
        );
        let reset = ChangeDisplaySettingsExW(
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        );
        println!("reset -> {reset}");
    }
}

#[cfg(not(windows))]
fn main() {}
