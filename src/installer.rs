#![windows_subsystem = "windows"]

use std::fs;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, IDYES, MB_ICONINFORMATION, MB_ICONQUESTION, MB_YESNO,
};

const CREATE_NO_WINDOW: u32 = 0x08000000;

static MAIN_EXE: &[u8] = include_bytes!("../dist/FikradoSecurity.exe");
static UNINSTALL_EXE: &[u8] = include_bytes!("../dist/FikradoSecurityUninstall.exe");
static ICON_BYTES: &[u8] = include_bytes!("../assets/logo.ico");
static README_BYTES: &[u8] = include_bytes!("../dist/README.txt");

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn create_shortcut(target_exe: &str, shortcut_path: &str, icon_path: &str, work_dir: &str) {
    let script = format!(
        "$ws = New-Object -ComObject WScript.Shell; \
         $s = $ws.CreateShortcut('{}'); \
         $s.TargetPath = '{}'; \
         $s.WorkingDirectory = '{}'; \
         $s.IconLocation = '{},0'; \
         $s.Description = 'Fikrado Security - Enterprise Windows Threat Defense Platform'; \
         $s.Save();",
        shortcut_path.replace('\'', "''"),
        target_exe.replace('\'', "''"),
        work_dir.replace('\'', "''"),
        icon_path.replace('\'', "''")
    );

    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

fn register_uninstall_entry(install_dir: &str, _exe_path: &str, uninstaller_path: &str, icon_path: &str) {
    let reg_base = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FikradoSecurity";

    let commands = [
        format!("reg add \"{}\" /v \"DisplayName\" /t REG_SZ /d \"Fikrado Security\" /f", reg_base),
        format!("reg add \"{}\" /v \"DisplayVersion\" /t REG_SZ /d \"2.6.87\" /f", reg_base),
        format!("reg add \"{}\" /v \"Publisher\" /t REG_SZ /d \"Fikrado Security\" /f", reg_base),
        format!("reg add \"{}\" /v \"DisplayIcon\" /t REG_SZ /d \"{}\" /f", reg_base, icon_path),
        format!("reg add \"{}\" /v \"UninstallString\" /t REG_SZ /d \"{}\" /f", reg_base, uninstaller_path),
        format!("reg add \"{}\" /v \"InstallLocation\" /t REG_SZ /d \"{}\" /f", reg_base, install_dir),
        format!("reg add \"{}\" /v \"URLInfoAbout\" /t REG_SZ /d \"https://fikrado2.github.io\" /f", reg_base),
        format!("reg add \"{}\" /v \"HelpLink\" /t REG_SZ /d \"https://fikrado2.github.io\" /f", reg_base),
        format!("reg add \"{}\" /v \"EstimatedSize\" /t REG_DWORD /d 4500 /f", reg_base),
        format!("reg add \"{}\" /v \"NoModify\" /t REG_DWORD /d 1 /f", reg_base),
        format!("reg add \"{}\" /v \"NoRepair\" /t REG_DWORD /d 1 /f", reg_base),
    ];

    for cmd in &commands {
        let _ = Command::new("cmd")
            .args(["/c", cmd])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
}

fn main() {
    let title = to_wide("Fikrado Security Setup - v2.6.87");
    let welcome = to_wide(
        "Welcome to Fikrado Security Setup!\n\n\
         This installer will install Fikrado Security (Enterprise Windows Threat Defense Platform) on your computer.\n\n\
         Do you want to proceed with the installation?"
    );

    let res = unsafe { MessageBoxW(std::ptr::null_mut(), welcome.as_ptr(), title.as_ptr(), MB_YESNO | MB_ICONQUESTION) };
    if res != IDYES {
        return;
    }

    // 1. Determine destination directory
    let install_dir: PathBuf = if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
        PathBuf::from(localappdata).join("Programs").join("Fikrado Security")
    } else if let Ok(userprofile) = std::env::var("USERPROFILE") {
        PathBuf::from(userprofile).join("AppData").join("Local").join("Programs").join("Fikrado Security")
    } else {
        PathBuf::from("C:\\FikradoSecurity")
    };

    if let Err(e) = fs::create_dir_all(&install_dir) {
        let err_msg = to_wide(&format!("Failed to create installation directory:\n{}", e));
        unsafe { MessageBoxW(std::ptr::null_mut(), err_msg.as_ptr(), title.as_ptr(), 0x10) };
        return;
    }

    // 2. Write application files
    let target_exe = install_dir.join("FikradoSecurity.exe");
    let target_icon = install_dir.join("logo.ico");
    let target_readme = install_dir.join("README.txt");
    let target_uninstall = install_dir.join("uninstall.exe");

    let _ = fs::write(&target_exe, MAIN_EXE);
    let _ = fs::write(&target_icon, ICON_BYTES);
    let _ = fs::write(&target_readme, README_BYTES);
    let _ = fs::write(&target_uninstall, UNINSTALL_EXE);

    // Write a self-contained uninstaller script/binary
    let uninst_script = format!(
        "@echo off\r\n\
         taskkill /F /IM FikradoSecurity.exe >nul 2>&1\r\n\
         del /f /q \"%USERPROFILE%\\Desktop\\Fikrado Security.lnk\" >nul 2>&1\r\n\
         del /f /q \"%USERPROFILE%\\OneDrive\\Desktop\\Fikrado Security.lnk\" >nul 2>&1\r\n\
         del /f /q \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Fikrado Security.lnk\" >nul 2>&1\r\n\
         reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FikradoSecurity\" /f >nul 2>&1\r\n\
         start /b \"\" cmd /c ping 127.0.0.1 -n 2 >nul & rmdir /s /q \"{}\"\r\n\
         msg * \"Fikrado Security was successfully uninstalled from your computer.\"\r\n",
        install_dir.to_string_lossy()
    );
    let uninst_bat = install_dir.join("uninstall.cmd");
    let _ = fs::write(&uninst_bat, uninst_script);

    // 3. Create Desktop shortcut across standard and OneDrive Desktop folders
    let mut desktop_dirs = Vec::new();
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        desktop_dirs.push(PathBuf::from(&userprofile).join("Desktop"));
        desktop_dirs.push(PathBuf::from(&userprofile).join("OneDrive").join("Desktop"));
    }
    if let Ok(onedrive) = std::env::var("OneDrive") {
        desktop_dirs.push(PathBuf::from(&onedrive).join("Desktop"));
    }
    for d in desktop_dirs {
        if d.exists() {
            let desktop_lnk = d.join("Fikrado Security.lnk");
            create_shortcut(
                &target_exe.to_string_lossy(),
                &desktop_lnk.to_string_lossy(),
                &target_icon.to_string_lossy(),
                &install_dir.to_string_lossy(),
            );
        }
    }

    // 4. Create Start Menu shortcut
    if let Ok(appdata) = std::env::var("APPDATA") {
        let start_dir = PathBuf::from(&appdata)
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs");
        let _ = fs::create_dir_all(&start_dir);
        let start_lnk = start_dir.join("Fikrado Security.lnk");
        create_shortcut(
            &target_exe.to_string_lossy(),
            &start_lnk.to_string_lossy(),
            &target_icon.to_string_lossy(),
            &install_dir.to_string_lossy(),
        );
    }

    // 5. Register in Windows Uninstall Registry
    let uninstaller_cmd = format!("\"{}\"", target_uninstall.to_string_lossy());

    register_uninstall_entry(
        &install_dir.to_string_lossy(),
        &target_exe.to_string_lossy(),
        &uninstaller_cmd,
        &target_icon.to_string_lossy(),
    );

    // 6. Installation complete prompt
    let finish_msg = to_wide(
        "Fikrado Security has been successfully installed on your computer!\n\n\
         • Desktop shortcut created\n\
         • Start Menu shortcut created\n\
         • Registered in Windows Settings (Apps & Features)\n\n\
         Would you like to launch Fikrado Security now?"
    );

    let launch_res = unsafe { MessageBoxW(std::ptr::null_mut(), finish_msg.as_ptr(), title.as_ptr(), MB_YESNO | MB_ICONINFORMATION) };
    if launch_res == IDYES {
        let _ = Command::new(&target_exe)
            .current_dir(&install_dir)
            .spawn();
    }
}
