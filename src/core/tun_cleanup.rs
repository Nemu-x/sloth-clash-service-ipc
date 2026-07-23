//! Force-removal of stale wintun TUN adapters.
//!
//! Why this exists: mihomo creates its Windows TUN interface with the userspace
//! `wintun.dll`. When the core is force-killed (an in-app update replacing the
//! binary, a crash, or Task-Manager), it never calls `WintunCloseAdapter`, so
//! the adapter stays registered as a PnP network device. On the next start the
//! core calls `WintunCreateAdapter`, which fails with **"access is denied"**
//! whenever a stale adapter with the same name is still registered *or* the new
//! `wintun.dll` refuses to adopt an adapter created by an older one. This
//! survives a reboot and a service reinstall, because a registered PnP device is
//! untouched by either — only an explicit device removal clears it.
//!
//! The unprivileged desktop app cannot remove a network PnP device; the SYSTEM
//! service can. This module is that removal, exposed over IPC as
//! [`IpcCommand::RemoveTun`](super::command::IpcCommand::RemoveTun).
//!
//! Matching is by **driver** (the wintun driver description), not by adapter
//! name, so it clears both the historical default name ("Meta") and any explicit
//! name we set going forward — a name we do not have to know in advance. On the
//! access-denied path the app has just failed to create its adapter, so no
//! *healthy* wintun adapter is in use; removing every wintun adapter there is
//! safe. On non-Windows there is no wintun and this is a no-op.

/// Number of wintun adapters removed by a [`remove_tun_adapters`] call.
pub type RemovedCount = u32;

#[cfg(target_os = "windows")]
pub async fn remove_tun_adapters() -> anyhow::Result<RemovedCount> {
    use tokio::process::Command;

    // A single PowerShell pass: enumerate Net-class PnP devices, keep the ones
    // whose driver description contains "Wintun" (locale-independent — the
    // description is not localized), and remove each by instance id via
    // `pnputil /remove-device`. It prints one "REMOVED <id>" line per success so
    // we can report a count without parsing pnputil's localized output.
    //
    // `-NonInteractive -NoProfile` keeps this deterministic under the SYSTEM
    // token; every lookup is `-ErrorAction SilentlyContinue` so a single flaky
    // device never aborts the sweep.
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$removed = 0
Get-PnpDevice -Class Net -EA SilentlyContinue | ForEach-Object {
    $desc = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_DriverDesc' -EA SilentlyContinue).Data
    if ($desc -like '*Wintun*') {
        & pnputil /remove-device $_.InstanceId | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $removed++
            Write-Output ("REMOVED " + $_.InstanceId)
        }
    }
}
Write-Output ("COUNT " + $removed)
"#;

    let output = Command::new("powershell.exe")
        .args([
            "-NonInteractive",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            SCRIPT,
        ])
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let count = stdout
        .lines()
        .find_map(|line| {
            line.strip_prefix("COUNT ")
                .and_then(|n| n.trim().parse().ok())
        })
        .unwrap_or(0);

    if !output.status.success() {
        // pnputil / PowerShell failing is not fatal to the caller — the app will
        // simply see the create still fail and surface its guidance. Log the
        // detail so a failed sweep is diagnosable from the service log.
        tracing::warn!(
            "remove_tun_adapters: powershell exited {:?}; stderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    } else {
        tracing::info!("remove_tun_adapters: removed {count} wintun adapter(s)");
    }

    Ok(count)
}

#[cfg(not(target_os = "windows"))]
pub async fn remove_tun_adapters() -> anyhow::Result<RemovedCount> {
    // No wintun outside Windows — mihomo tears its own tun/utun down on stop, and
    // the app's disable-before-kill path handles the graceful case. Nothing to do.
    Ok(0)
}
