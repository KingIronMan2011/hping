//! Windows installer and self-installation helper.
#![cfg(windows)]

use std::env;
use std::ffi::c_void;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows_sys::Win32::System::Console::GetConsoleProcessList;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegGetValueW, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_READ, KEY_SET_VALUE, REG_EXPAND_SZ, RRF_RT_ANY,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    HWND_BROADCAST, SMTO_ABORTIFHUNG, SW_SHOWNORMAL, SendMessageTimeoutW,
};

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Checks if the application was double-clicked or launched from a GUI without an existing console.
pub fn is_launched_from_explorer() -> bool {
    let mut pids = [0u32; 4];
    let count = unsafe { GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) };
    // If count <= 1, our process is the sole owner of the console window created for it.
    count <= 1
}

/// Checks if the current process is running with elevated Administrator privileges.
pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut ret_len = 0u32;
        let success = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);

        success != 0 && elevation.TokenIsElevated != 0
    }
}

/// Relaunches the current executable with Administrator elevation via UAC prompt ("runas").
pub fn relaunch_elevated(args: &[&str]) -> io::Result<()> {
    let current_exe = env::current_exe()?;
    let exe_wide = to_wide(&current_exe.to_string_lossy());
    let verb_wide = to_wide("runas");
    let args_str = args.join(" ");
    let args_wide = to_wide(&args_str);

    let mut sei: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = verb_wide.as_ptr();
    sei.lpFile = exe_wide.as_ptr();
    sei.lpParameters = if args.is_empty() {
        ptr::null()
    } else {
        args_wide.as_ptr()
    };
    sei.nShow = SW_SHOWNORMAL as i32;

    let res = unsafe { ShellExecuteExW(&mut sei) };
    if res == 0 {
        return Err(io::Error::last_os_error());
    }

    if !sei.hProcess.is_null() {
        unsafe {
            WaitForSingleObject(sei.hProcess, INFINITE);
            let mut exit_code: u32 = 0;
            GetExitCodeProcess(sei.hProcess, &mut exit_code);
            CloseHandle(sei.hProcess);
        }
    }

    Ok(())
}

/// Gets the system PATH from `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`.
fn get_system_path() -> Result<String, io::Error> {
    let subkey = to_wide(r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment");
    let value_name = to_wide("Path");

    let mut data_size = 0u32;
    let mut data_type = 0u32;

    unsafe {
        let status = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            value_name.as_ptr(),
            RRF_RT_ANY,
            &mut data_type,
            ptr::null_mut(),
            &mut data_size,
        );

        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        let mut buffer = vec![0u8; data_size as usize];
        let status = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            value_name.as_ptr(),
            RRF_RT_ANY,
            ptr::null_mut(),
            buffer.as_mut_ptr() as *mut c_void,
            &mut data_size,
        );

        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        let u16_slice = std::slice::from_raw_parts(
            buffer.as_ptr() as *const u16,
            buffer.len() / 2,
        );
        let len = u16_slice.iter().position(|&c| c == 0).unwrap_or(u16_slice.len());
        Ok(String::from_utf16_lossy(&u16_slice[..len]))
    }
}

/// Sets the system PATH in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`.
fn set_system_path(new_path: &str) -> Result<(), io::Error> {
    let subkey = to_wide(r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment");
    let value_name = to_wide("Path");
    let wide_val = to_wide(new_path);

    let mut hkey: HKEY = ptr::null_mut();
    unsafe {
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_READ | KEY_SET_VALUE,
            &mut hkey,
        );
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        let cb_data = (wide_val.len() * std::mem::size_of::<u16>()) as u32;
        let status = RegSetValueExW(
            hkey,
            value_name.as_ptr(),
            0,
            REG_EXPAND_SZ,
            wide_val.as_ptr() as *const u8,
            cb_data,
        );
        RegCloseKey(hkey);

        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        // Broadcast WM_SETTINGCHANGE so all windows and shells update their environment
        let env_wide = to_wide("Environment");
        let mut result: usize = 0;
        SendMessageTimeoutW(
            HWND_BROADCAST,
            0x001A, // WM_SETTINGCHANGE
            0,
            env_wide.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            3000,
            &mut result,
        );
    }

    Ok(())
}

/// Installs hping to `C:\Program Files\hping\hping.exe` and adds `C:\Program Files\hping` to system PATH.
pub fn install_to_program_files() -> io::Result<()> {
    let current_exe = env::current_exe()?;
    let program_files = env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());
    let target_dir = PathBuf::from(program_files).join("hping");
    let target_exe = target_dir.join("hping.exe");

    println!("============================================================");
    println!("               hping for Windows Installer                  ");
    println!("============================================================");
    println!();
    println!("Target installation folder: {}", target_dir.display());

    // 1. Create directory if not exists
    if !target_dir.exists() {
        fs::create_dir_all(&target_dir)?;
        println!("[+] Created directory: {}", target_dir.display());
    }

    // 2. Copy current executable to target destination
    // If the file is currently being run from the destination, no need to overwrite itself
    if current_exe.canonicalize().unwrap_or_else(|_| current_exe.clone())
        != target_exe.canonicalize().unwrap_or_else(|_| target_exe.clone())
    {
        fs::copy(&current_exe, &target_exe)?;
        println!("[+] Installed hping.exe to: {}", target_exe.display());
    } else {
        println!("[*] hping.exe is already running from the installation directory.");
    }

    // 3. Failsafe PATH management: check if directory is already in PATH
    let target_dir_str = target_dir.to_string_lossy().to_string();
    let current_path = get_system_path().unwrap_or_default();

    let already_in_path = current_path
        .split(';')
        .map(|entry| entry.trim().trim_end_matches('\\'))
        .any(|entry| entry.eq_ignore_ascii_case(target_dir_str.trim_end_matches('\\')));

    if already_in_path {
        println!("[*] '{}' is already in system PATH. No duplicate added.", target_dir.display());
    } else {
        let mut updated_path = current_path;
        if !updated_path.is_empty() && !updated_path.ends_with(';') {
            updated_path.push(';');
        }
        updated_path.push_str(&target_dir_str);

        match set_system_path(&updated_path) {
            Ok(_) => {
                println!("[+] Added '{}' to system PATH successfully!", target_dir.display());
            }
            Err(e) => {
                eprintln!("[-] Warning: Failed to update system PATH: {}", e);
            }
        }
    }

    println!();
    println!("Installation completed successfully!");
    println!("You can now open a new Command Prompt or PowerShell and type:");
    println!("    hping --help");
    println!();

    Ok(())
}

/// Runs the installer workflow. Elevates if necessary, runs the install, and pauses for user input if GUI.
pub fn run_installer(interactive: bool) {
    if !is_elevated() {
        if interactive {
            println!("Administrator rights are required to install hping to Program Files.");
            println!("Requesting elevation via UAC...");
        }

        if let Err(e) = relaunch_elevated(&["--install"]) {
            eprintln!("Elevation failed: {}. Installation aborted.", e);
            if interactive {
                pause_on_exit();
            }
            std::process::exit(1);
        }
        // Successfully waited for the elevated installer child process to finish
        std::process::exit(0);
    }

    // Elevated execution
    match install_to_program_files() {
        Ok(_) => {
            if interactive {
                pause_on_exit();
            }
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Installation failed: {}", e);
            if interactive {
                pause_on_exit();
            }
            std::process::exit(1);
        }
    }
}

pub fn pause_on_exit() {
    print!("\nPress Enter to exit...");
    let _ = io::stdout().flush();
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
}
