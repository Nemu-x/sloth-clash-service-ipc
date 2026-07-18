#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn main() {
    panic!("This program is not intended to run on this platform.");
}

use anyhow::Error;

/// Parse `--core-sha256 <hex,hex;...>` (or `--core-sha256=<...>`) from argv and
/// return a normalized, comma-joined list of valid 64-char SHA-256 hex strings, or
/// `None` if the flag is absent or has no valid hashes. When `None`, nothing is
/// persisted and the service falls back to the admin-only location allow-list.
/// The persisted value is read by the service from its own environment
/// (`SLOTH_CLASH_CORE_SHA256`); the accepted format mirrors `security.rs`.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn parse_core_sha256() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    let mut raw: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(v) = a.strip_prefix("--core-sha256=") {
            raw = Some(v.to_string());
        } else if a == "--core-sha256" {
            if let Some(v) = args.get(i + 1) {
                raw = Some(v.clone());
            }
            i += 1;
        }
        i += 1;
    }

    let hashes: Vec<String> = raw?
        .split([',', ';', ' ', '\t'])
        .map(|s| s.trim().to_lowercase())
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .collect();

    if hashes.is_empty() {
        None
    } else {
        Some(hashes.join(","))
    }
}

/// Directory the service binary is copied into before it is registered.
///
/// The installer is executed from wherever the caller staged it — the desktop
/// app extracts it into a *per-user temp dir* and only then elevates — so
/// registering the service against `current_exe()`'s sibling would point the
/// SYSTEM/root service at a **user-writable** path. A non-admin could then swap
/// that binary while the service is stopped and get code execution as
/// SYSTEM/root: precisely the Layer-1 boundary `security.rs` exists to hold
/// ("never let the service execute a binary a non-admin could have swapped").
///
/// So we mirror what the macOS installer already does with
/// `/Library/PrivilegedHelperTools`: copy into an admin-only directory and
/// register THAT path. The staging dir then carries no trust at all.
#[cfg(windows)]
fn privileged_install_dir() -> anyhow::Result<std::path::PathBuf> {
    // ProgramW6432 resolves to the real (64-bit) Program Files even from a
    // 32-bit installer process; ProgramFiles is the normal fallback. Both are
    // admin-only by inherited ACL, which is exactly the property we need.
    let base = std::env::var("ProgramW6432")
        .or_else(|_| std::env::var("ProgramFiles"))
        .map_err(|_| anyhow::anyhow!("neither ProgramW6432 nor ProgramFiles is set"))?;
    Ok(std::path::PathBuf::from(base)
        .join("SlothClash")
        .join("service"))
}

/// Copy the staged binary over the privileged one, retrying briefly: right
/// after the old service is stopped/deleted Windows can still hold the image
/// open for a moment, which would fail the copy.
#[cfg(windows)]
fn copy_binary_with_retry(from: &std::path::Path, to: &std::path::Path) -> anyhow::Result<()> {
    let mut last_err = None;
    for _ in 0..40 {
        match std::fs::copy(from, to) {
            Ok(_) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
    }
    Err(anyhow::anyhow!(
        "failed to copy service binary to {}: {}",
        to.display(),
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".into())
    ))
}

#[cfg(unix)]
fn env_u32(key: &str) -> Option<u32> {
    std::env::var(key).ok()?.parse().ok()
}

#[cfg(unix)]
fn resolve_service_group_name() -> String {
    use nix::unistd::{Gid, Group, Uid, User};

    if let Some(gid) = env_u32("SLOTH_CLASH_SERVICE_GID")
        && let Ok(Some(group)) = Group::from_gid(Gid::from_raw(gid))
    {
        return group.name;
    }

    if let Some(uid) = env_u32("SUDO_UID").or_else(|| env_u32("PKEXEC_UID"))
        && let Ok(Some(user)) = User::from_uid(Uid::from_raw(uid))
        && let Ok(Some(group)) = Group::from_gid(user.gid)
    {
        return group.name;
    }

    if let Some(gid) = env_u32("SUDO_GID")
        && let Ok(Some(group)) = Group::from_gid(Gid::from_raw(gid))
    {
        return group.name;
    }

    panic!("Please use sudo or pkexec to install service.");
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Error> {
    use std::env;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    let debug = env::args().any(|arg| arg == "--debug");
    let _ = uninstall_old_service();

    let service_binary_path = env::current_exe()
        .unwrap()
        .with_file_name("sloth-clash-service");

    if !service_binary_path.exists() {
        return Err(anyhow::anyhow!("sloth-clash-service binary not found"));
    }

    // 定义 bundle 路径
    let bundle_path =
        "/Library/PrivilegedHelperTools/dev.slothclash.desktop.ipc.service.bundle";
    let contents_path = format!("{}/Contents", bundle_path);
    let macos_path = format!("{}/MacOS", contents_path);

    // 创建 bundle 目录结构
    std::fs::create_dir_all(&macos_path)
        .map_err(|e| anyhow::anyhow!("Failed to create bundle directories: {}", e))?;

    // 复制二进制文件到 bundle 的 MacOS 目录
    let target_binary_path = format!("{}/sloth-clash-service", macos_path);
    std::fs::copy(&service_binary_path, &target_binary_path)
        .map_err(|e| anyhow::anyhow!("Failed to copy service file: {}", e))?;

    // 创建并写入 Info.plist
    let info_plist_path = format!("{}/Info.plist", contents_path);
    let info_plist_content = include_str!("../../resources/info.plist.tmpl");

    std::fs::write(&info_plist_path, info_plist_content)
        .map_err(|e| anyhow::anyhow!("Failed to write Info.plist: {}", e))?;

    // 创建 LaunchDaemons 目录（如果不存在）
    let plist_dir = Path::new("/Library/LaunchDaemons");
    if !plist_dir.exists() {
        std::fs::create_dir(plist_dir)
            .map_err(|e| anyhow::anyhow!("Failed to create plist directory: {}", e))?;
    }

    // 创建并写入 launchd plist
    let plist_file = "/Library/LaunchDaemons/dev.slothclash.desktop.ipc.service.plist";
    let plist_file = Path::new(plist_file);

    // Persist the core content pin into the daemon's environment via the plist's
    // EnvironmentVariables dict (empty when no pin was supplied).
    let env_block = match parse_core_sha256() {
        Some(pin) => format!(
            "    <key>EnvironmentVariables</key>\n    <dict>\n        \
             <key>SLOTH_CLASH_CORE_SHA256</key>\n        <string>{pin}</string>\n    </dict>\n\n"
        ),
        None => String::new(),
    };

    let launchd_plist_content = format!(
        include_str!("../../resources/launchd.plist.tmpl"),
        group_name = resolve_service_group_name(),
        env_block = env_block,
    );

    File::create(plist_file)
        .and_then(|mut file| file.write_all(launchd_plist_content.as_bytes()))
        .map_err(|e| anyhow::anyhow!("Failed to write plist file: {}", e))?;

    // 设置权限
    // 设置 LaunchDaemons plist 权限
    let _ = run_command("chmod", &["644", plist_file.to_str().unwrap()], debug);
    let _ = run_command(
        "chown",
        &["root:wheel", plist_file.to_str().unwrap()],
        debug,
    );

    // 设置二进制文件权限
    let _ = run_command("chmod", &["544", &target_binary_path], debug);
    let _ = run_command("chown", &["root:wheel", &target_binary_path], debug);

    // 设置 bundle 目录及其内容的权限
    let _ = run_command("chmod", &["755", bundle_path], debug);
    let _ = run_command("chown", &["-R", "root:wheel", bundle_path], debug);

    // 加载和启动服务
    let _ = run_command(
        "launchctl",
        &[
            "enable",
            "system/dev.slothclash.desktop.ipc.service",
        ],
        debug,
    );
    let _ = run_command(
        "launchctl",
        &["bootout", "system", plist_file.to_str().unwrap()],
        debug,
    );
    let _ = run_command(
        "launchctl",
        &["bootstrap", "system", plist_file.to_str().unwrap()],
        debug,
    );
    let _ = run_command(
        "launchctl",
        &["start", "dev.slothclash.desktop.ipc.service"],
        debug,
    );

    Ok(())
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Error> {
    const SERVICE_NAME: &str = "sloth-clash-service";
    use std::env;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    let debug = env::args().any(|arg| arg == "--debug");

    // The binary as staged next to this installer (typically a per-user temp
    // dir) — untrusted location, used only as the copy source.
    let staged_binary = env::current_exe()
        .unwrap()
        .with_file_name("sloth-clash-service");

    if !staged_binary.exists() {
        return Err(anyhow::anyhow!("sloth-clash-service binary not found"));
    }

    // Idempotent, self-healing install (mirrors the Windows path): always stop,
    // re-lay the binary and rewrite the unit, so an upgrade actually replaces a
    // previously shipped-vulnerable install instead of returning early. The old
    // behaviour ("running -> return Ok") meant an existing install could never
    // be migrated or repaired.
    let _ = run_command(
        "systemctl",
        &["stop", &format!("{}.service", SERVICE_NAME)],
        debug,
    );

    // Land the binary in a root-only directory and point the unit at THAT path,
    // so a non-admin can never swap what the root service executes.
    let install_dir = Path::new("/usr/local/lib/sloth-clash");
    std::fs::create_dir_all(install_dir).map_err(|e| {
        anyhow::anyhow!(
            "Failed to create service directory {}: {}",
            install_dir.display(),
            e
        )
    })?;
    let service_binary_path = install_dir.join(SERVICE_NAME);
    if staged_binary != service_binary_path {
        std::fs::copy(&staged_binary, &service_binary_path)
            .map_err(|e| anyhow::anyhow!("Failed to copy service binary: {}", e))?;
    }
    let service_binary_str = service_binary_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("service binary path is not valid UTF-8"))?;
    let _ = run_command("chown", &["root:root", service_binary_str], debug);
    let _ = run_command("chmod", &["755", service_binary_str], debug);
    let install_dir_str = install_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("service directory path is not valid UTF-8"))?;
    let _ = run_command("chown", &["root:root", install_dir_str], debug);
    let _ = run_command("chmod", &["755", install_dir_str], debug);

    // Create and write unit file
    let unit_file = format!("/etc/systemd/system/{}.service", SERVICE_NAME);
    let unit_file = Path::new(&unit_file);

    // Persist the core content pin into the service environment via a systemd
    // `Environment=` line (empty when no pin was supplied).
    let env_line = match parse_core_sha256() {
        Some(pin) => format!("Environment=SLOTH_CLASH_CORE_SHA256={pin}\n"),
        None => String::new(),
    };

    let unit_file_content = format!(
        include_str!("../../resources/systemd_service_unit.tmpl"),
        exec_start = service_binary_str,
        group = resolve_service_group_name(),
        env_line = env_line,
    );

    File::create(unit_file)
        .and_then(|mut file| file.write_all(unit_file_content.as_bytes()))
        .map_err(|e| anyhow::anyhow!("Failed to write unit file: {}", e))?;

    // Reload and start service
    let _ = run_command("systemctl", &["daemon-reload"], debug);
    let _ = run_command("systemctl", &["enable", SERVICE_NAME, "--now"], debug);

    Ok(())
}

/// install and start the service
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use platform_lib::{
        service::{
            ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
            ServiceType,
        },
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    use std::env;
    use std::ffi::{OsStr, OsString};
    use std::time::Duration;

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    // Idempotent, self-healing install: if a service already exists (possibly an
    // older, vulnerable build), stop and delete it, then recreate from this binary.
    // This is how a fixed version replaces a shipped-vulnerable one on upgrade.
    let manage_access =
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    if let Ok(service) = service_manager.open_service("sloth_clash_service", manage_access) {
        if let Ok(status) = service.query_status()
            && status.current_state != ServiceState::Stopped
        {
            let _ = service.stop();
            for _ in 0..20 {
                std::thread::sleep(Duration::from_millis(250));
                match service.query_status() {
                    Ok(s) if s.current_state == ServiceState::Stopped => break,
                    _ => {}
                }
            }
        }

        let _ = service.delete();
        drop(service);

        // The SCM removes the record only once the last handle closes; wait until a
        // fresh open fails so the subsequent create_service does not hit
        // ERROR_SERVICE_MARKED_FOR_DELETE.
        for _ in 0..40 {
            if service_manager
                .open_service("sloth_clash_service", ServiceAccess::QUERY_STATUS)
                .is_err()
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    // The binary as staged next to this installer (typically a per-user temp
    // dir) — untrusted location, used only as the copy source.
    let staged_binary = env::current_exe()
        .unwrap()
        .with_file_name("sloth-clash-service.exe");

    if !staged_binary.exists() {
        eprintln!("sloth-clash-service.exe not found");
        std::process::exit(2);
    }

    // Land the binary in an admin-only directory and register THAT path, so a
    // non-admin can never swap what the SYSTEM service executes. The old
    // service (if any) was stopped and deleted above, releasing the image.
    let install_dir = privileged_install_dir()?;
    std::fs::create_dir_all(&install_dir).map_err(|e| {
        anyhow::anyhow!(
            "failed to create service directory {}: {e}",
            install_dir.display()
        )
    })?;
    let service_binary_path = install_dir.join("sloth-clash-service.exe");
    if staged_binary != service_binary_path {
        copy_binary_with_retry(&staged_binary, &service_binary_path)?;
    }

    let service_info = ServiceInfo {
        name: OsString::from("sloth_clash_service"),
        display_name: OsString::from("Sloth Clash Service"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_binary_path,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // run as System
        account_password: None,
    };

    let start_access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::START;
    let service = service_manager.create_service(&service_info, start_access)?;

    service.set_description("Sloth Clash Service — IPC helper for Sloth Clash / mihomo.")?;

    // Persist the core content pin into the service's OWN environment so it is read
    // at service start (Fix 1 / security.rs). The SCM applies the per-service
    // `Environment` value — a REG_MULTI_SZ of "NAME=VALUE" entries under
    // HKLM\SYSTEM\CurrentControlSet\Services\<name> — to the service process. Written
    // before start so the immediate start below picks it up. Idempotent install
    // (stop→delete→recreate) means each reinstall overwrites it with the fresh pin.
    if let Some(pin) = parse_core_sha256() {
        let data = format!("SLOTH_CLASH_CORE_SHA256={pin}");
        let key = r"HKLM\SYSTEM\CurrentControlSet\Services\sloth_clash_service";
        let status = std::process::Command::new("reg")
            .args([
                "add", key, "/v", "Environment", "/t", "REG_MULTI_SZ", "/d", &data, "/f",
            ])
            .status()
            .map_err(|e| anyhow::anyhow!("failed to run reg.exe to persist core pin: {e}"))?;
        if !status.success() {
            return Err(anyhow::anyhow!(
                "failed to persist SLOTH_CLASH_CORE_SHA256 to service environment (reg exit {:?})",
                status.code()
            ));
        }
    }

    service.start(&Vec::<&OsStr>::new())?;

    Ok(())
}

#[cfg(target_os = "macos")]
pub fn uninstall_old_service() -> Result<(), Error> {
    use std::path::Path;

    let target_binary_path = "/Library/PrivilegedHelperTools/io.github.clashverge.helper";
    let plist_file = "/Library/LaunchDaemons/io.github.clashverge.helper.plist";

    // Stop and unload service
    run_command("launchctl", &["stop", "io.github.clashverge.helper"], false)?;
    run_command("launchctl", &["bootout", "system", plist_file], false)?;
    run_command(
        "launchctl",
        &["disable", "system/io.github.clashverge.helper"],
        false,
    )?;

    // Remove files
    if Path::new(plist_file).exists() {
        std::fs::remove_file(plist_file)
            .map_err(|e| anyhow::anyhow!("Failed to remove plist file: {}", e))?;
    }

    if Path::new(target_binary_path).exists() {
        std::fs::remove_file(target_binary_path)
            .map_err(|e| anyhow::anyhow!("Failed to remove service binary: {}", e))?;
    }

    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// Locks in the Layer-1 intent: the registered service binary must live in
    /// an admin-only directory, never in a user-writable one (a temp dir being
    /// the regression this guards against).
    #[test]
    fn privileged_install_dir_is_admin_only_not_temp() {
        let dir = privileged_install_dir().expect("ProgramFiles should resolve on Windows");
        let path = dir.to_string_lossy().to_lowercase();

        assert!(
            path.contains("program files"),
            "service dir must be under Program Files (admin-only ACL), got: {path}"
        );
        assert!(
            !path.contains("\\temp\\") && !path.contains("\\appdata\\"),
            "service dir must never be user-writable (temp/appdata), got: {path}"
        );
        assert!(
            path.ends_with("slothclash\\service"),
            "unexpected service dir layout: {path}"
        );
    }
}

pub fn run_command(cmd: &str, args: &[&str], debug: bool) -> Result<(), Error> {
    if debug {
        println!("Executing: {} {}", cmd, args.join(" "));
    }

    let output = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to execute '{}': {}", cmd, e))?;

    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if debug {
        eprintln!(
            "Command failed (status: {}):\nstdout: {}\nstderr: {}",
            output.status, stdout, stderr
        );
    }

    Err(anyhow::anyhow!(
        "Command '{}' failed (status: {}):\nstdout: {}\nstderr: {}",
        cmd,
        output.status,
        stdout,
        stderr
    ))
}
