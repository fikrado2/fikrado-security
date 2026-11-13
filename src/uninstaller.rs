#![windows_subsystem = "windows"]

use std::os::windows::process::CommandExt;
use std::process::Command;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, IDYES, MB_ICONINFORMATION, MB_ICONQUESTION, MB_OK, MB_YESNO,
};

const CREATE_NO_WINDOW: u32 = 0x08000000;

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn main() {
    let title = to_wide("Fikrado Security - Uninstall");
    let msg = to_wide("Are you sure you want to completely uninstall Fikrado Security and all its components from this computer?");

    let res = unsafe { MessageBoxW(std::ptr::null_mut(), msg.as_ptr(), title.as_ptr(), MB_YESNO | MB_ICONQUESTION) };

    if res != IDYES {
        return;
    }

    // 1. Terminate running process if any
    let _ = Command::new("taskkill")
        .args(["/F", "/IM", "FikradoSecurity.exe"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    // 2. Remove desktop shortcut
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        let desktop_lnk = std::path::PathBuf::from(&userprofile).join("Desktop").join("Fikrado Security.lnk");
        let _ = std::fs::remove_file(desktop_lnk);
        let onedrive_lnk = std::path::PathBuf::from(&userprofile).join("OneDrive").join("Desktop").join("Fikrado Security.lnk");
        let _ = std::fs::remove_file(onedrive_lnk);
    }

    // 3. Remove start menu shortcut
    if let Ok(appdata) = std::env::var("APPDATA") {
        let start_lnk = std::path::PathBuf::from(&appdata)
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Fikrado Security.lnk");
        let _ = std::fs::remove_file(start_lnk);
    }

    // 4. Remove registry uninstall key
    let _ = Command::new("reg")
        .args([
            "delete",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FikradoSecurity",
            "/f",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    // 5. Success message
    let done_msg = to_wide("Fikrado Security was successfully uninstalled from your computer.");
    unsafe {
        MessageBoxW(std::ptr::null_mut(), done_msg.as_ptr(), title.as_ptr(), MB_OK | MB_ICONINFORMATION);
    }

    // 6. Spawn cmd process to clean up install directory after exit
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(install_dir) = exe_path.parent() {
            let dir_str = install_dir.to_string_lossy().to_string();
            let _ = Command::new("cmd")
                .args([
                    "/c",
                    "ping",
                    "127.0.0.1",
                    "-n",
                    "2",
                    ">",
                    "nul",
                    "&",
                    "rmdir",
                    "/s",
                    "/q",
                    &format!("\"{}\"", dir_str),
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .spawn();
        }
    }
}
