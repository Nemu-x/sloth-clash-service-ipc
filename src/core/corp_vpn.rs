//! Corporate-VPN sidecar (corp-vpn-coexistence). Cross-platform.
//!
//! The privileged service spawns and supervises a bundled OpenConnect (Cisco
//! AnyConnect protocol) and captures the routes/DNS the gateway pushes, so the
//! app can split traffic: corp subnets go through OpenConnect, everything else
//! through mihomo (which excludes those subnets). Only the SYSTEM/root service
//! can bring up the corp tunnel and configure its routes.
//!
//! Architecture: the ORCHESTRATION (spawn OpenConnect, learn the split from a
//! wrapper vpnc-script's env dump, install routes, wire DNS, teardown) is
//! shared. Everything OS-specific — the script body, route/DNS/search-domain
//! application, graceful kill — lives behind the `platform` seam, implemented
//! per OS (macOS / Windows / Linux). Adding a platform = implement that seam,
//! not re-implement the lifecycle.
//!
//! Teardown-safe model: the vpnc-script only brings up the tunnel interface and
//! dumps config — it never installs routes or DNS. We own those, so a crash/kill
//! can't leave stale system state (interface-scoped routes die with the tunnel;
//! DNS is removed deterministically + swept on startup). [`parse_vpnc_env`] is
//! the dump parser — pure and unit-tested against a real gateway's shape.

use std::collections::HashMap;

use crate::core::structure::{CorpVpnStartRequest, CorpVpnStatusData};

/// Split config learned from the vpnc-script environment.
// Used by the process impl and by unit tests; unused on the `client`-only build,
// so allow dead_code there.
#[allow(dead_code)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CorpSplit {
    /// Corp subnets to route through OpenConnect (CIDR strings).
    pub routes: Vec<String>,
    pub dns_servers: Vec<String>,
    pub dns_domains: Vec<String>,
    /// The gateway advertised the default route (0/0) — no split is possible.
    pub full_tunnel: bool,
    /// Tunnel interface name (from `TUNDEV`), e.g. "utun4".
    pub tundev: String,
    /// Gateway public IP (from `VPNGATEWAY`) — excluded from mihomo's TUN.
    pub gateway_ip: String,
}

/// parse_vpnc_env turns the `KEY=VALUE` dump the wrapper vpnc-script writes on
/// tunnel-up into a [`CorpSplit`]. Pure — no process, no I/O.
///
/// - `CISCO_SPLIT_INC` = number of split-include routes; each `i` has
///   `CISCO_SPLIT_INC_{i}_ADDR` + `_MASKLEN` → `ADDR/MASKLEN`.
/// - `CISCO_SPLIT_INC` absent/0 → the gateway owns the default route (full tunnel).
/// - `INTERNAL_IP4_DNS` = space-separated corp resolvers.
/// - `CISCO_DEF_DOMAIN` (+ `CISCO_SPLIT_DNS`) = corp search domains.
#[allow(dead_code)]
pub fn parse_vpnc_env(dump: &str) -> CorpSplit {
    let mut map: HashMap<&str, &str> = HashMap::new();
    for line in dump.lines() {
        let line = line.trim();
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim(), v.trim());
        }
    }

    let mut split = CorpSplit::default();
    let n: usize = map
        .get("CISCO_SPLIT_INC")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    for i in 0..n {
        let addr = map
            .get(format!("CISCO_SPLIT_INC_{i}_ADDR").as_str())
            .copied();
        let masklen = map
            .get(format!("CISCO_SPLIT_INC_{i}_MASKLEN").as_str())
            .copied();
        if let (Some(a), Some(m)) = (addr, masklen)
            && !a.is_empty()
            && !m.is_empty()
        {
            split.routes.push(format!("{a}/{m}"));
        }
    }
    // No split-includes → gateway took the default route.
    split.full_tunnel = split.routes.is_empty();

    if let Some(dns) = map.get("INTERNAL_IP4_DNS") {
        split.dns_servers = dns.split_whitespace().map(|s| s.to_string()).collect();
    }

    let mut domains: Vec<String> = Vec::new();
    if let Some(d) = map.get("CISCO_DEF_DOMAIN") {
        domains.extend(d.split_whitespace().map(|s| s.to_string()));
    }
    if let Some(d) = map.get("CISCO_SPLIT_DNS") {
        domains.extend(
            d.split([',', ' '])
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        );
    }
    domains.sort();
    domains.dedup();
    split.dns_domains = domains;

    if let Some(dev) = map.get("TUNDEV") {
        split.tundev = dev.to_string();
    }
    if let Some(gw) = map.get("VPNGATEWAY") {
        split.gateway_ip = gw.to_string();
    }

    split
}

/// extract_servercert_pin scans OpenConnect's stderr for the SHA-256 fingerprint
/// it prints when a server certificate is not yet trusted, returning the value
/// to pin (`sha256:<hex>`). Trust-on-first-use: the app shows it to the user,
/// then reconnects with it pinned. Best-effort text parsing.
#[allow(dead_code)]
pub fn extract_servercert_pin(stderr: &str) -> Option<String> {
    for line in stderr.lines() {
        // OpenConnect prints e.g. `--servercert sha256:ABCD...` as the hint, and
        // `SHA256:ABCD...` in the fingerprint block.
        if let Some(idx) = line.to_ascii_lowercase().find("sha256:") {
            let rest = &line[idx + "sha256:".len()..];
            let hex: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            if hex.len() >= 32 {
                return Some(format!("sha256:{hex}"));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Shared orchestration. OS-specific bits live behind `platform` (below).
// ---------------------------------------------------------------------------

#[cfg(feature = "standalone")]
mod imp {
    use super::*;
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use once_cell::sync::Lazy;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    /// Cap on retained OpenConnect log lines (ring buffer).
    const LOG_CAP: usize = 200;

    type LogBuffer = Arc<Mutex<VecDeque<String>>>;

    struct State {
        child: Option<tokio::process::Child>,
        status: CorpVpnStatusData,
        dump_path: Option<PathBuf>,
        logs: LogBuffer,
    }

    static STATE: Lazy<Mutex<State>> = Lazy::new(|| {
        Mutex::new(State {
            child: None,
            status: CorpVpnStatusData::default(),
            dump_path: None,
            logs: Arc::new(Mutex::new(VecDeque::new())),
        })
    });

    /// Stream a child's stderr into a capped ring buffer. Feeds the UI log view
    /// AND keeps the OS pipe drained so OpenConnect never blocks writing stderr.
    fn spawn_stderr_reader(stderr: tokio::process::ChildStderr, logs: LogBuffer) {
        tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let mut buf = logs.lock().await;
                if buf.len() >= LOG_CAP {
                    buf.pop_front();
                }
                buf.push_back(line);
            }
        });
    }

    pub async fn start(req: CorpVpnStartRequest) -> anyhow::Result<CorpVpnStatusData> {
        // One corp tunnel at a time — tear down any previous run, and sweep any
        // system state a previous crash may have left so nothing stale lingers.
        stop().await.ok();
        platform::sweep().await;

        let bin = PathBuf::from(&req.bin_path);
        if !bin.is_file() {
            anyhow::bail!("openconnect binary not found at {}", req.bin_path);
        }

        // Per-run scratch dir for the env dump + the interface-only vpnc-script.
        let run_dir = std::env::temp_dir().join(format!("sloth-corp-{}", std::process::id()));
        tokio::fs::create_dir_all(&run_dir).await?;
        let dump = run_dir.join("vpnc-env.dump");
        let _ = tokio::fs::remove_file(&dump).await;
        let wrapper = run_dir.join(format!("vpnc-script{}", platform::VPNC_SCRIPT_EXT));
        tokio::fs::write(&wrapper, platform::vpnc_script_body(&dump)).await?;
        platform::make_executable(&wrapper).await;

        let mut cmd = tokio::process::Command::new(&bin);
        cmd.arg("--script")
            .arg(&wrapper)
            .arg("--user")
            .arg(&req.username)
            .arg("--passwd-on-stdin")
            .arg("--non-inter");
        for a in platform::openconnect_extra_args() {
            cmd.arg(a);
        }
        if !req.servercert.trim().is_empty() {
            cmd.arg("--servercert").arg(req.servercert.trim());
        }
        cmd.arg(&req.gateway);
        cmd.stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // If this future is dropped (client disconnect, handler-timeout, supersede)
        // kill OpenConnect with it — a leaked tunnel keeps corp routes/DNS live and
        // breaks normal traffic. Once connected the child moves into STATE.
        cmd.kill_on_drop(true);

        let mut child = cmd.spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin
                .write_all(format!("{}\n", req.password).as_bytes())
                .await;
            let _ = stdin.shutdown().await;
        }

        let logs: LogBuffer = Arc::new(Mutex::new(VecDeque::new()));
        if let Some(stderr) = child.stderr.take() {
            spawn_stderr_reader(stderr, logs.clone());
        }
        let collected_logs = || async {
            logs.lock()
                .await
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        };

        // Race: tunnel-up (dump file appears) vs early process exit (auth/cert).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(35);
        loop {
            if let Ok(true) = tokio::fs::try_exists(&dump).await {
                tokio::time::sleep(Duration::from_millis(150)).await;
                let dumped = tokio::fs::read_to_string(&dump).await.unwrap_or_default();
                let split = parse_vpnc_env(&dumped);
                // We own routing + DNS: install corp routes onto the tunnel iface,
                // and make corp domains (incl. bare hostnames) resolvable system-wide.
                platform::install_routes(&split.routes, &split.tundev).await;
                platform::setup_dns(&split.dns_domains, &split.dns_servers, &req.gateway).await;
                let status = CorpVpnStatusData {
                    connected: true,
                    needs_cert_trust: false,
                    servercert_sha256: String::new(),
                    routes: split.routes,
                    dns_servers: split.dns_servers,
                    dns_domains: split.dns_domains,
                    full_tunnel: split.full_tunnel,
                    tundev: split.tundev,
                    gateway_ip: split.gateway_ip,
                    log_tail: Vec::new(),
                };
                let mut st = STATE.lock().await;
                st.child = Some(child);
                st.dump_path = Some(dump.clone());
                st.status = status.clone();
                st.logs = logs.clone();
                tracing::info!(
                    "corp-vpn: connected on {}, {} route(s)",
                    status.tundev,
                    status.routes.len()
                );
                return Ok(status);
            }
            if let Ok(Some(exit)) = child.try_wait() {
                tokio::time::sleep(Duration::from_millis(120)).await;
                let stderr = collected_logs().await;
                let _ = exit;
                if req.servercert.trim().is_empty()
                    && let Some(pin) = extract_servercert_pin(&stderr)
                {
                    return Ok(CorpVpnStatusData {
                        connected: false,
                        needs_cert_trust: true,
                        servercert_sha256: pin,
                        ..Default::default()
                    });
                }
                anyhow::bail!(
                    "openconnect exited before the tunnel came up: {}",
                    tail(&stderr)
                );
            }
            if tokio::time::Instant::now() > deadline {
                let _ = child.start_kill();
                anyhow::bail!("corp-vpn: timed out waiting for the tunnel to come up");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    pub async fn stop() -> anyhow::Result<()> {
        let mut st = STATE.lock().await;
        let routes = st.status.routes.clone();
        let tundev = st.status.tundev.clone();
        platform::teardown_dns().await;
        if let Some(mut child) = st.child.take() {
            platform::graceful_kill(&mut child).await;
        }
        if !tundev.is_empty() {
            platform::teardown_routes(&routes, &tundev).await;
        }
        if let Some(p) = st.dump_path.take() {
            let _ = tokio::fs::remove_file(p).await;
        }
        st.status = CorpVpnStatusData::default();
        st.logs.lock().await.clear();
        Ok(())
    }

    pub async fn status() -> CorpVpnStatusData {
        let mut st = STATE.lock().await;
        // If the child died, reflect disconnected — but keep the log tail so the
        // UI can still show why it dropped.
        if let Some(child) = st.child.as_mut()
            && let Ok(Some(_)) = child.try_wait()
        {
            st.child = None;
            st.status = CorpVpnStatusData::default();
        }
        let mut status = st.status.clone();
        status.log_tail = st.logs.lock().await.iter().cloned().collect();
        status
    }

    /// Boot-time cleanup: drop any corp routes/DNS a previous (crashed) run left.
    pub async fn sweep_orphans() {
        platform::sweep().await;
    }

    fn tail(s: &str) -> String {
        let t = s.trim();
        let start = t.len().saturating_sub(400);
        t[start..].to_string()
    }

    // =======================================================================
    // Platform seam — one backend per OS. Each provides the same surface.
    // =======================================================================
    mod platform {
        #[cfg(target_os = "macos")]
        pub use macos::*;
        #[cfg(all(unix, not(target_os = "macos")))]
        pub use unixlike::*;
        #[cfg(target_os = "windows")]
        pub use windows::*;

        // ----------------------------- macOS -------------------------------
        #[cfg(target_os = "macos")]
        mod macos {
            use std::path::Path;

            pub const VPNC_SCRIPT_EXT: &str = ".sh";
            const RESOLVER_MARKER: &str = "# managed-by: sloth-corp";
            const SEARCH_BACKUP: &str = "/var/db/sloth-corp/searchdomains.bak";

            pub fn openconnect_extra_args() -> Vec<String> {
                Vec::new()
            }

            pub fn vpnc_script_body(dump: &Path) -> String {
                // Interface up + env dump ONLY. No routes, no DNS (we own those).
                // Prefix grep with NO trailing '=' so indexed subkeys
                // (CISCO_SPLIT_INC_0_ADDR, INTERNAL_IP4_DNS) are captured.
                format!(
                    r#"#!/bin/sh
case "$reason" in
  connect|reconnect)
    /sbin/ifconfig "$TUNDEV" inet "$INTERNAL_IP4_ADDRESS" "$INTERNAL_IP4_ADDRESS" netmask 255.255.255.255 mtu "${{INTERNAL_IP4_MTU:-1400}}" up
    env | grep -E '^(CISCO_SPLIT_INC|INTERNAL_IP4|CISCO_.*DOMAIN|VPNGATEWAY|TUNDEV)' > '{dump}'
    ;;
esac
exit 0
"#,
                    dump = dump.display(),
                )
            }

            pub async fn make_executable(path: &Path) {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(md) = tokio::fs::metadata(path).await {
                    let mut perms = md.permissions();
                    perms.set_mode(0o755);
                    let _ = tokio::fs::set_permissions(path, perms).await;
                }
            }

            pub async fn install_routes(routes: &[String], tundev: &str) {
                if tundev.is_empty() {
                    return;
                }
                for r in routes {
                    let out = tokio::process::Command::new("/sbin/route")
                        .args(["-n", "add", "-net", r, "-interface", tundev])
                        .output()
                        .await;
                    match out {
                        Ok(o) if o.status.success() => {
                            tracing::info!("corp-vpn: route {r} -> {tundev}")
                        }
                        Ok(o) => tracing::warn!(
                            "corp-vpn: route add {r} failed: {}",
                            String::from_utf8_lossy(&o.stderr).trim()
                        ),
                        Err(e) => tracing::warn!("corp-vpn: route add {r} spawn failed: {e}"),
                    }
                }
            }

            pub async fn teardown_routes(routes: &[String], tundev: &str) {
                for r in routes {
                    let _ = tokio::process::Command::new("/sbin/route")
                        .args(["-n", "delete", "-net", r, "-interface", tundev])
                        .output()
                        .await;
                }
            }

            pub async fn setup_dns(domains: &[String], servers: &[String], gateway: &str) {
                configure_corp_resolvers(domains, servers, gateway).await;
                configure_corp_search_domains(domains).await;
            }

            pub async fn teardown_dns() {
                sweep_resolvers().await;
                restore_corp_search_domains().await;
            }

            pub async fn sweep() {
                restore_corp_search_domains().await;
                sweep_resolvers().await;
            }

            pub async fn graceful_kill(child: &mut tokio::process::Child) {
                // SIGTERM first so OpenConnect closes the CSTP session cleanly,
                // then SIGKILL as a backstop.
                if let Some(pid) = child.id() {
                    unsafe {
                        platform_lib::kill(pid as platform_lib::pid_t, platform_lib::SIGTERM);
                    }
                    let _ =
                        tokio::time::timeout(std::time::Duration::from_secs(3), child.wait()).await;
                }
                let _ = child.start_kill();
                let _ = child.wait().await;
            }

            // corp domains → /etc/resolver/<domain> → corp resolver (reachable via
            // the tunnel). Gateway host gets a more-specific PUBLIC override to
            // avoid a resolve deadlock. Marked so the sweep can reap crash leftovers.
            async fn configure_corp_resolvers(
                domains: &[String],
                servers: &[String],
                gateway: &str,
            ) {
                if servers.is_empty() {
                    return;
                }
                let _ = tokio::fs::create_dir_all("/etc/resolver").await;
                let ns: String = servers
                    .iter()
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| format!("nameserver {}\n", s.trim()))
                    .collect();
                for d in domains {
                    let d = d.trim();
                    if d.is_empty() {
                        continue;
                    }
                    let path = format!("/etc/resolver/{d}");
                    let _ = tokio::fs::write(&path, format!("{RESOLVER_MARKER}\n{ns}")).await;
                }
                let gw = gateway.trim();
                if !gw.is_empty() && gw.parse::<std::net::IpAddr>().is_err() {
                    let body =
                        format!("{RESOLVER_MARKER}\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n");
                    let _ = tokio::fs::write(format!("/etc/resolver/{gw}"), body).await;
                }
            }

            async fn sweep_resolvers() {
                let mut dir = match tokio::fs::read_dir("/etc/resolver").await {
                    Ok(d) => d,
                    Err(_) => return,
                };
                while let Ok(Some(entry)) = dir.next_entry().await {
                    let p = entry.path();
                    if let Ok(body) = tokio::fs::read_to_string(&p).await
                        && body.contains(RESOLVER_MARKER)
                    {
                        let _ = tokio::fs::remove_file(&p).await;
                    }
                }
            }

            async fn primary_network_service() -> Option<String> {
                let iface = {
                    let out = tokio::process::Command::new("/sbin/route")
                        .args(["-n", "get", "default"])
                        .output()
                        .await
                        .ok()?;
                    String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
                        l.trim()
                            .strip_prefix("interface:")
                            .map(|s| s.trim().to_string())
                    })?
                };
                let out = tokio::process::Command::new("/usr/sbin/networksetup")
                    .arg("-listnetworkserviceorder")
                    .output()
                    .await
                    .ok()?;
                let text = String::from_utf8_lossy(&out.stdout);
                let needle = format!("Device: {iface})");
                let mut service = String::new();
                for line in text.lines() {
                    let l = line.trim();
                    if l.starts_with('(')
                        && let Some(close) = l.find(") ")
                        && l[1..close].chars().all(|c| c.is_ascii_digit())
                    {
                        service = l[close + 2..].trim().to_string();
                        continue;
                    }
                    if l.contains(&needle) && !service.is_empty() {
                        return Some(service);
                    }
                }
                None
            }

            async fn get_search_domains(service: &str) -> Vec<String> {
                let out = match tokio::process::Command::new("/usr/sbin/networksetup")
                    .args(["-getsearchdomains", service])
                    .output()
                    .await
                {
                    Ok(o) => o,
                    Err(_) => return Vec::new(),
                };
                let text = String::from_utf8_lossy(&out.stdout);
                if text.contains("aren't any") {
                    return Vec::new();
                }
                text.lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            }

            async fn set_search_domains(service: &str, domains: &[String]) {
                let mut cmd = tokio::process::Command::new("/usr/sbin/networksetup");
                cmd.arg("-setsearchdomains").arg(service);
                if domains.is_empty() {
                    cmd.arg("empty");
                } else {
                    for d in domains {
                        cmd.arg(d);
                    }
                }
                let _ = cmd.output().await;
            }

            async fn configure_corp_search_domains(domains: &[String]) {
                let domains: Vec<String> = domains
                    .iter()
                    .map(|d| d.trim().to_string())
                    .filter(|d| !d.is_empty())
                    .collect();
                if domains.is_empty() {
                    return;
                }
                let Some(service) = primary_network_service().await else {
                    return;
                };
                let original = get_search_domains(&service).await;
                let _ = tokio::fs::create_dir_all("/var/db/sloth-corp").await;
                let backup = format!("{service}\n{}", original.join("\n"));
                let _ = tokio::fs::write(SEARCH_BACKUP, backup).await;
                let mut combined = domains;
                for d in &original {
                    if !combined.contains(d) {
                        combined.push(d.clone());
                    }
                }
                set_search_domains(&service, &combined).await;
                tracing::info!("corp-vpn: set search domains on {service}");
            }

            async fn restore_corp_search_domains() {
                let body = match tokio::fs::read_to_string(SEARCH_BACKUP).await {
                    Ok(b) => b,
                    Err(_) => return,
                };
                let mut lines = body.lines();
                let Some(service) = lines.next().map(|s| s.trim().to_string()) else {
                    return;
                };
                if !service.is_empty() {
                    let original: Vec<String> = lines
                        .map(|l| l.trim().to_string())
                        .filter(|l| !l.is_empty())
                        .collect();
                    set_search_domains(&service, &original).await;
                }
                let _ = tokio::fs::remove_file(SEARCH_BACKUP).await;
            }
        }

        // ------------------------- Linux / other unix ----------------------
        // Interface + routes are functional (iproute2). DNS via /etc/resolver is
        // macOS-only; Linux resolver wiring (systemd-resolved / resolv.conf) is
        // the remaining piece — validated on a real Linux box before shipping P3.
        #[cfg(all(unix, not(target_os = "macos")))]
        mod unixlike {
            use std::path::Path;

            pub const VPNC_SCRIPT_EXT: &str = ".sh";

            pub fn openconnect_extra_args() -> Vec<String> {
                Vec::new()
            }

            pub fn vpnc_script_body(dump: &Path) -> String {
                format!(
                    r#"#!/bin/sh
case "$reason" in
  connect|reconnect)
    ip addr add "$INTERNAL_IP4_ADDRESS/32" dev "$TUNDEV" 2>/dev/null
    ip link set dev "$TUNDEV" mtu "${{INTERNAL_IP4_MTU:-1400}}" up
    env | grep -E '^(CISCO_SPLIT_INC|INTERNAL_IP4|CISCO_.*DOMAIN|VPNGATEWAY|TUNDEV)' > '{dump}'
    ;;
esac
exit 0
"#,
                    dump = dump.display(),
                )
            }

            pub async fn make_executable(path: &Path) {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(md) = tokio::fs::metadata(path).await {
                    let mut perms = md.permissions();
                    perms.set_mode(0o755);
                    let _ = tokio::fs::set_permissions(path, perms).await;
                }
            }

            pub async fn install_routes(routes: &[String], tundev: &str) {
                if tundev.is_empty() {
                    return;
                }
                for r in routes {
                    let _ = tokio::process::Command::new("ip")
                        .args(["route", "add", r, "dev", tundev])
                        .output()
                        .await;
                }
            }

            pub async fn teardown_routes(routes: &[String], tundev: &str) {
                for r in routes {
                    let _ = tokio::process::Command::new("ip")
                        .args(["route", "del", r, "dev", tundev])
                        .output()
                        .await;
                }
            }

            // TODO(P3): wire corp DNS via systemd-resolved (`resolvectl domain
            // <iface> <domain>` + `resolvectl dns <iface> <server>`) or a managed
            // resolv.conf edit, with the same deterministic teardown + sweep.
            pub async fn setup_dns(_domains: &[String], _servers: &[String], _gateway: &str) {
                tracing::warn!("corp-vpn: Linux DNS wiring not implemented yet (P3)");
            }
            pub async fn teardown_dns() {}
            pub async fn sweep() {}

            pub async fn graceful_kill(child: &mut tokio::process::Child) {
                if let Some(pid) = child.id() {
                    unsafe {
                        platform_lib::kill(pid as platform_lib::pid_t, platform_lib::SIGTERM);
                    }
                    let _ =
                        tokio::time::timeout(std::time::Duration::from_secs(3), child.wait()).await;
                }
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
        }

        // ----------------------------- Windows -----------------------------
        // OpenConnect on Windows uses wintun + a WSH vpnc-script. Routes via
        // `netsh`. DNS via NRPT (Name Resolution Policy Table). The interface
        // bring-up + NRPT wiring need validation on a real Windows box (the
        // owner's) with the Windows OpenConnect+wintun bundle before shipping P2.
        #[cfg(target_os = "windows")]
        mod windows {
            use std::path::Path;

            pub const VPNC_SCRIPT_EXT: &str = ".js";

            pub fn openconnect_extra_args() -> Vec<String> {
                Vec::new()
            }

            pub fn vpnc_script_body(dump: &Path) -> String {
                // Windows Script Host (cscript) — dump the pushed config env vars.
                // OpenConnect+wintun brings the adapter up itself; we only learn
                // the split here and apply routes/DNS from Rust (below).
                let dump = dump.display().to_string().replace('\\', "\\\\");
                format!(
                    r#"var sh = WScript.CreateObject("WScript.Shell");
var env = sh.Environment("PROCESS");
var reason = "" + env("reason");
if (reason == "connect" || reason == "reconnect") {{
  var fso = WScript.CreateObject("Scripting.FileSystemObject");
  var f = fso.CreateTextFile("{dump}", true);
  var e = new Enumerator(env);
  var re = /^(CISCO_SPLIT_INC|INTERNAL_IP4|CISCO_.*DOMAIN|VPNGATEWAY|TUNDEV)/;
  for (; !e.atEnd(); e.moveNext()) {{
    var line = "" + e.item();
    if (re.test(line)) f.WriteLine(line);
  }}
  f.Close();
}}
WScript.Quit(0);
"#,
                    dump = dump,
                )
            }

            pub async fn make_executable(_path: &Path) {}

            pub async fn install_routes(routes: &[String], tundev: &str) {
                if tundev.is_empty() {
                    return;
                }
                for r in routes {
                    // netsh interface ipv4 add route <prefix> "<iface>"
                    let _ = tokio::process::Command::new("netsh")
                        .args([
                            "interface",
                            "ipv4",
                            "add",
                            "route",
                            r,
                            &format!("interface={tundev}"),
                            "store=active",
                        ])
                        .output()
                        .await;
                }
            }

            pub async fn teardown_routes(routes: &[String], tundev: &str) {
                for r in routes {
                    let _ = tokio::process::Command::new("netsh")
                        .args([
                            "interface",
                            "ipv4",
                            "delete",
                            "route",
                            r,
                            &format!("interface={tundev}"),
                        ])
                        .output()
                        .await;
                }
            }

            // Corp DNS on Windows = NRPT (Name Resolution Policy Table): per-domain
            // rules routing corp namespaces to the corp resolver, plus the corp
            // domains added to the global suffix search list so BARE hostnames
            // resolve. We record what we added (a file of namespaces + a suffix
            // backup) so teardown/sweep is deterministic even after a crash.
            const WIN_STATE_DIR: &str = r"C:\ProgramData\sloth-corp";
            const WIN_NRPT_NS: &str = r"C:\ProgramData\sloth-corp\nrpt-namespaces.txt";
            const WIN_SUFFIX_BACKUP: &str = r"C:\ProgramData\sloth-corp\suffix-backup.txt";

            async fn powershell(script: &str) -> Option<String> {
                let out = tokio::process::Command::new("powershell")
                    .args(["-NoProfile", "-NonInteractive", "-Command", script])
                    .output()
                    .await
                    .ok()?;
                Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
            }

            pub async fn setup_dns(domains: &[String], servers: &[String], gateway: &str) {
                let domains: Vec<String> = domains
                    .iter()
                    .map(|d| d.trim().trim_start_matches('.').to_string())
                    .filter(|d| !d.is_empty())
                    .collect();
                if domains.is_empty() || servers.is_empty() {
                    return;
                }
                let servers_ps = servers
                    .iter()
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| format!("'{}'", s.trim()))
                    .collect::<Vec<_>>()
                    .join(",");
                let _ = tokio::fs::create_dir_all(WIN_STATE_DIR).await;

                // Back up the current suffix search list for restore.
                if let Some(cur) =
                    powershell("(Get-DnsClientGlobalSetting).SuffixSearchList -join ','").await
                {
                    let _ = tokio::fs::write(WIN_SUFFIX_BACKUP, &cur).await;
                }

                // NRPT rules: corp domains → corp resolver. `.<domain>` matches the
                // domain and its subdomains. Record namespaces for teardown.
                let mut namespaces: Vec<String> = Vec::new();
                for d in &domains {
                    let ns = format!(".{d}");
                    let _ = powershell(&format!(
                        "Add-DnsClientNrptRule -Namespace '{ns}' -NameServers @({servers_ps})"
                    ))
                    .await;
                    namespaces.push(ns);
                }
                // Gateway host → PUBLIC resolver (more specific), else the corp
                // resolver would capture it and deadlock the next connect.
                let gw = gateway.trim();
                if !gw.is_empty() && gw.parse::<std::net::IpAddr>().is_err() {
                    let _ = powershell(&format!(
                        "Add-DnsClientNrptRule -Namespace '{gw}' -NameServers @('1.1.1.1','8.8.8.8')"
                    ))
                    .await;
                    namespaces.push(gw.to_string());
                }
                let _ = tokio::fs::write(WIN_NRPT_NS, namespaces.join("\n")).await;

                // Suffix search list: prepend corp domains (bare hostnames resolve).
                let original = tokio::fs::read_to_string(WIN_SUFFIX_BACKUP)
                    .await
                    .unwrap_or_default();
                let mut list = domains.clone();
                for s in original
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                {
                    if !list.iter().any(|x| x == s) {
                        list.push(s.to_string());
                    }
                }
                let list_ps = list
                    .iter()
                    .map(|s| format!("'{s}'"))
                    .collect::<Vec<_>>()
                    .join(",");
                let _ = powershell(&format!(
                    "Set-DnsClientGlobalSetting -SuffixSearchList @({list_ps})"
                ))
                .await;
                tracing::info!(
                    "corp-vpn: NRPT + suffix search configured ({} domains)",
                    domains.len()
                );
            }

            pub async fn teardown_dns() {
                // Remove the NRPT rules we recorded.
                if let Ok(body) = tokio::fs::read_to_string(WIN_NRPT_NS).await {
                    for ns in body.lines().map(|l| l.trim()).filter(|l| !l.is_empty()) {
                        let ns = ns.replace('\'', "''");
                        let _ = powershell(&format!(
                            "Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -eq '{ns}' }} | Remove-DnsClientNrptRule -Force"
                        ))
                        .await;
                    }
                    let _ = tokio::fs::remove_file(WIN_NRPT_NS).await;
                }
                // Restore the suffix search list.
                if let Ok(cur) = tokio::fs::read_to_string(WIN_SUFFIX_BACKUP).await {
                    let list = cur
                        .split(',')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .map(|s| format!("'{s}'"))
                        .collect::<Vec<_>>()
                        .join(",");
                    let cmd = if list.is_empty() {
                        "Set-DnsClientGlobalSetting -SuffixSearchList @()".to_string()
                    } else {
                        format!("Set-DnsClientGlobalSetting -SuffixSearchList @({list})")
                    };
                    let _ = powershell(&cmd).await;
                    let _ = tokio::fs::remove_file(WIN_SUFFIX_BACKUP).await;
                }
            }

            pub async fn sweep() {
                teardown_dns().await;
            }

            pub async fn graceful_kill(child: &mut tokio::process::Child) {
                // No POSIX signals on Windows; terminate the process. wintun dies
                // with it, so the tunnel routes go away; we clean DNS explicitly.
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
        }
    }
}

#[cfg(feature = "standalone")]
pub use imp::{start, status, stop, sweep_orphans};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_real_split_tunnel_gateway() {
        // Shape validated on a real Cisco AnyConnect gateway (netstat/scutil):
        // split-tunnel with a couple of corp subnets, one corp resolver, one
        // corp search domain.
        let dump = "\
VPNGATEWAY=203.0.113.10
CISCO_SPLIT_INC=2
CISCO_SPLIT_INC_0_ADDR=10.0.0.0
CISCO_SPLIT_INC_0_MASKLEN=8
CISCO_SPLIT_INC_1_ADDR=172.16.0.0
CISCO_SPLIT_INC_1_MASKLEN=12
INTERNAL_IP4_DNS=10.16.32.100
CISCO_DEF_DOMAIN=corp.example
TUNDEV=utun4
";
        let got = parse_vpnc_env(dump);
        assert_eq!(got.routes, vec!["10.0.0.0/8", "172.16.0.0/12"]);
        assert_eq!(got.dns_servers, vec!["10.16.32.100"]);
        assert_eq!(got.dns_domains, vec!["corp.example"]);
        assert!(!got.full_tunnel, "split-tunnel must not be flagged full");
        assert_eq!(got.tundev, "utun4", "tunnel device must be captured");
        assert_eq!(
            got.gateway_ip, "203.0.113.10",
            "gateway IP must be captured"
        );
    }

    #[test]
    fn full_tunnel_when_no_split_includes() {
        // Gateway pushes the default route (no CISCO_SPLIT_INC) → no split.
        let dump = "VPNGATEWAY=203.0.113.10\nINTERNAL_IP4_DNS=10.1.1.1\n";
        let got = parse_vpnc_env(dump);
        assert!(got.routes.is_empty());
        assert!(got.full_tunnel, "no split-includes means full tunnel");
        assert_eq!(got.dns_servers, vec!["10.1.1.1"]);
    }

    #[test]
    fn multiple_dns_servers_and_domains_deduped() {
        let dump = "\
CISCO_SPLIT_INC=1
CISCO_SPLIT_INC_0_ADDR=10.0.0.0
CISCO_SPLIT_INC_0_MASKLEN=8
INTERNAL_IP4_DNS=10.1.1.1 10.1.1.2
CISCO_DEF_DOMAIN=corp.example
CISCO_SPLIT_DNS=corp.example,sub.corp.example
";
        let got = parse_vpnc_env(dump);
        assert_eq!(got.dns_servers, vec!["10.1.1.1", "10.1.1.2"]);
        assert_eq!(got.dns_domains, vec!["corp.example", "sub.corp.example"]);
    }

    #[test]
    fn ignores_blank_and_malformed_lines() {
        let dump = "\n   \nCISCO_SPLIT_INC=0\ngarbage-without-equals\n";
        let got = parse_vpnc_env(dump);
        assert!(got.routes.is_empty());
        assert!(got.full_tunnel);
    }

    #[test]
    fn extracts_servercert_fingerprint() {
        let stderr = "Certificate from VPN server failed verification.\n    --servercert sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef to trust\n";
        let pin = extract_servercert_pin(stderr).expect("should find a pin");
        assert!(pin.starts_with("sha256:"));
        assert_eq!(pin.len(), "sha256:".len() + 64);
    }

    #[test]
    fn no_servercert_pin_when_absent() {
        assert!(extract_servercert_pin("all good, connected\n").is_none());
    }
}
