//! Checks whether a game can control its cursor where this runs (used inside
//! the sandbox through `probe`). LWJGL 2 recenters a grabbed mouse every
//! frame with `SetCursorPos` and keeps it in the window with `ClipCursor`,
//! from the game's own focused window, so this opens one and does the same
#[cfg(windows)]
fn main() {
    use std::ffi::c_void;
    type Hwnd = *mut c_void;
    #[repr(C)]
    struct WndClass {
        style: u32,
        proc_: unsafe extern "system" fn(Hwnd, u32, usize, isize) -> isize,
        cls: i32,
        wnd: i32,
        instance: *mut c_void,
        icon: *mut c_void,
        cursor: *mut c_void,
        brush: *mut c_void,
        menu: *const u16,
        name: *const u16,
    }
    #[repr(C)]
    struct Msg {
        hwnd: Hwnd,
        message: u32,
        w: usize,
        l: isize,
        time: u32,
        pt: [i32; 2],
        private: u32,
    }
    #[link(name = "user32")]
    unsafe extern "system" {
        fn GetCursorPos(point: *mut [i32; 2]) -> i32;
        fn SetCursorPos(x: i32, y: i32) -> i32;
        fn ClipCursor(rect: *const [i32; 4]) -> i32;
        fn RegisterClassW(class: *const WndClass) -> u16;
        fn CreateWindowExW(
            ex: u32,
            class: *const u16,
            title: *const u16,
            style: u32,
            x: i32,
            y: i32,
            w: i32,
            h: i32,
            parent: Hwnd,
            menu: *mut c_void,
            instance: *mut c_void,
            param: *mut c_void,
        ) -> Hwnd;
        fn DefWindowProcW(hwnd: Hwnd, msg: u32, w: usize, l: isize) -> isize;
        fn SetForegroundWindow(hwnd: Hwnd) -> i32;
        fn GetForegroundWindow() -> Hwnd;
        fn PeekMessageW(msg: *mut Msg, hwnd: Hwnd, min: u32, max: u32, remove: u32) -> i32;
        fn DispatchMessageW(msg: *const Msg) -> isize;
        fn DestroyWindow(hwnd: Hwnd) -> i32;
    }
    unsafe extern "system" fn proc_(hwnd: Hwnd, msg: u32, w: usize, l: isize) -> isize {
        unsafe { DefWindowProcW(hwnd, msg, w, l) }
    }
    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    unsafe {
        let name = wide("OneClientCursorProbe");
        let class = WndClass {
            style: 0,
            proc_,
            cls: 0,
            wnd: 0,
            instance: std::ptr::null_mut(),
            icon: std::ptr::null_mut(),
            cursor: std::ptr::null_mut(),
            brush: std::ptr::null_mut(),
            menu: std::ptr::null(),
            name: name.as_ptr(),
        };
        RegisterClassW(&class);
        // WS_POPUP | WS_VISIBLE, WS_EX_TOPMOST
        let hwnd = CreateWindowExW(
            0x8,
            name.as_ptr(),
            name.as_ptr(),
            0x9000_0000,
            100,
            100,
            400,
            300,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        let mut before = [0i32; 2];
        GetCursorPos(&mut before);
        let mut focused = false;
        let mut moved = false;
        let mut set_err = String::new();
        let mut msg = std::mem::zeroed::<Msg>();
        for _ in 0..100 {
            SetForegroundWindow(hwnd);
            while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, 1) != 0 {
                DispatchMessageW(&msg);
            }
            focused |= GetForegroundWindow() == hwnd;
            if SetCursorPos(300, 250) != 0 {
                let mut now = [0i32; 2];
                GetCursorPos(&mut now);
                moved |= now == [300, 250];
            } else {
                set_err = std::io::Error::last_os_error().to_string();
            }
            if focused && moved {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(30));
        }
        let clip = ClipCursor(&[100, 100, 500, 400]);
        let clip_err = std::io::Error::last_os_error();
        ClipCursor(std::ptr::null());
        SetCursorPos(before[0], before[1]);
        DestroyWindow(hwnd);
        println!("own window focused: {focused}");
        println!("SetCursorPos moved the cursor: {moved} {set_err}");
        println!("ClipCursor -> {clip} ({clip_err})");
    }
}

#[cfg(not(windows))]
fn main() {}
