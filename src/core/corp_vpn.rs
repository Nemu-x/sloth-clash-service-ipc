//! Corporate-VPN sidecar (corp-vpn-coexistence, P1, macOS-first).
//!
//! The privileged service spawns and supervises a bundled OpenConnect (Cisco
//! AnyConnect protocol) and captures the routes/DNS the gateway pushes, so the
//! app can split traffic: corp subnets go through OpenConnect, everything else
//! through mihomo (which excludes those subnets). Only the SYSTEM/root service
//! can bring up the corp tun and configure its routes.
//!
//! The route/DNS learning uses a **wrapper vpnc-script**: OpenConnect runs it on
//! tunnel-up with the pushed config in the environment (CISCO_SPLIT_INC_* etc.);
//! the wrapper dumps that env to a file and then execs the real bundled
//! vpnc-script so the corp tunnel's own routes/DNS are still configured. The
//! service reads the dump and reports it. [`parse_vpnc_env`] is that parser —
//! pure and fully unit-tested against a real gateway's shape.

use std::collections::HashMap;

use crate::core::structure::{CorpVpnStartRequest, CorpVpnStatusData};

/// Split config learned from the vpnc-script environment.
// Used by the macOS process impl and by unit tests; unused on the non-macOS
// build (the port lands in P2/P3), so allow dead_code there.
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
// Process management (macOS-first). Non-macOS returns a clear "unsupported"
// until the Windows/Linux ports land (P2/P3).
// ---------------------------------------------------------------------------

#[cfg(all(feature = "standalone", target_os = "macos"))]
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

    /// Spawn a task that streams a child's stderr into a capped ring buffer. This
    /// both feeds the UI log view AND keeps the OS pipe drained so OpenConnect
    /// never blocks writing stderr once the tunnel is up (it logs periodically).
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
        // One corp tunnel at a time — tear down any previous run first.
        stop().await.ok();

        let bin = PathBuf::from(&req.bin_path);
        if !bin.is_file() {
            anyhow::bail!("openconnect binary not found at {}", req.bin_path);
        }
        // A per-run scratch dir for the env dump + wrapper script.
        let run_dir = std::env::temp_dir().join(format!("sloth-corp-{}", std::process::id()));
        tokio::fs::create_dir_all(&run_dir).await?;
        let dump = run_dir.join("vpnc-env.dump");
        let _ = tokio::fs::remove_file(&dump).await;
        let wrapper = run_dir.join("vpnc-script.sh");

        // Teardown-safe model: our vpnc-script brings up the tunnel interface and
        // NOTHING else — no `route add`, no `scutil`/DNS. That keeps all
        // persistent system state ours: the service installs corp routes onto the
        // utun (which the kernel scrubs when the interface dies, even on SIGKILL),
        // and mihomo owns DNS. So a crash/kill can never leave stale routes or a
        // stuck resolver behind. See openspec corp-vpn-coexistence design.
        let wrapper_body = format!(
            r#"#!/bin/sh
case "$reason" in
  connect|reconnect)
    /sbin/ifconfig "$TUNDEV" inet "$INTERNAL_IP4_ADDRESS" "$INTERNAL_IP4_ADDRESS" netmask 255.255.255.255 mtu "${{INTERNAL_IP4_MTU:-1400}}" up
    env | grep -E '^(CISCO_SPLIT_INC|INTERNAL_IP4|CISCO_.*DOMAIN|VPNGATEWAY|TUNDEV)=' > '{dump}'
    ;;
esac
exit 0
"#,
            dump = dump.display(),
        );
        tokio::fs::write(&wrapper, wrapper_body).await?;
        set_exec(&wrapper).await?;

        let mut cmd = tokio::process::Command::new(&bin);
        cmd.arg("--script")
            .arg(&wrapper)
            .arg("--user")
            .arg(&req.username)
            .arg("--passwd-on-stdin")
            .arg("--non-inter");
        if !req.servercert.trim().is_empty() {
            cmd.arg("--servercert").arg(req.servercert.trim());
        }
        cmd.arg(&req.gateway);
        cmd.stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // If this handler's future is ever dropped (client disconnect, server
        // handler-timeout, supersede), kill OpenConnect with it — a leaked
        // process keeps installing corp routes/DNS and breaks the machine's
        // normal traffic. Once connected we move the child into STATE, so a live
        // tunnel is unaffected; only an in-flight/abandoned connect is reaped.
        cmd.kill_on_drop(true);

        let mut child = cmd.spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin
                .write_all(format!("{}\n", req.password).as_bytes())
                .await;
            let _ = stdin.shutdown().await;
        }

        // Continuously drain stderr into a ring buffer for the UI log view (and
        // so the pipe never fills and stalls OpenConnect once connected).
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
                // Give the wrapper a beat to finish writing.
                tokio::time::sleep(Duration::from_millis(150)).await;
                let dumped = tokio::fs::read_to_string(&dump).await.unwrap_or_default();
                let split = parse_vpnc_env(&dumped);
                // We own routing: install each corp subnet onto the tunnel iface.
                // Interface-scoped routes die with the utun (kernel scrubs them on
                // process death), so this is self-cleaning even on SIGKILL.
                install_corp_routes(&split.routes, &split.tundev).await;
                let status = CorpVpnStatusData {
                    connected: true,
                    needs_cert_trust: false,
                    servercert_sha256: String::new(),
                    routes: split.routes,
                    dns_servers: split.dns_servers,
                    dns_domains: split.dns_domains,
                    full_tunnel: split.full_tunnel,
                    tundev: split.tundev,
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
                // Let the reader flush the final lines before we inspect them.
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
        if let Some(mut child) = st.child.take() {
            // Graceful first: SIGTERM lets OpenConnect close the CSTP session with
            // the gateway cleanly. Give it a moment, then SIGKILL as a backstop.
            // Either way the utun dies with the process and the kernel scrubs our
            // interface-scoped routes; the explicit delete below is belt-and-braces.
            if let Some(pid) = child.id() {
                unsafe {
                    platform_lib::kill(pid as platform_lib::pid_t, platform_lib::SIGTERM);
                }
                let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
            }
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
        if !tundev.is_empty() {
            remove_corp_routes(&routes, &tundev).await;
        }
        if let Some(p) = st.dump_path.take() {
            let _ = tokio::fs::remove_file(p).await;
        }
        st.status = CorpVpnStatusData::default();
        st.logs.lock().await.clear();
        Ok(())
    }

    /// install_corp_routes points each corp subnet at the tunnel interface. Route
    /// entries scoped to an interface are removed by the kernel when that
    /// interface goes away, so they are self-cleaning on any process death.
    async fn install_corp_routes(routes: &[String], tundev: &str) {
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
                    tracing::info!("corp-vpn: route {r} -> {tundev}");
                }
                Ok(o) => tracing::warn!(
                    "corp-vpn: route add {r} failed: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                ),
                Err(e) => tracing::warn!("corp-vpn: route add {r} spawn failed: {e}"),
            }
        }
    }

    /// remove_corp_routes deletes what install_corp_routes added. Best-effort: the
    /// kernel usually removed them already when the utun died.
    async fn remove_corp_routes(routes: &[String], tundev: &str) {
        for r in routes {
            let _ = tokio::process::Command::new("/sbin/route")
                .args(["-n", "delete", "-net", r, "-interface", tundev])
                .output()
                .await;
        }
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

    async fn set_exec(path: &std::path::Path) -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = tokio::fs::metadata(path).await?.permissions();
        perms.set_mode(0o755);
        tokio::fs::set_permissions(path, perms).await?;
        Ok(())
    }

    fn tail(s: &str) -> String {
        let t = s.trim();
        let start = t.len().saturating_sub(400);
        t[start..].to_string()
    }
}

#[cfg(all(feature = "standalone", not(target_os = "macos")))]
mod imp {
    use super::*;

    pub async fn start(_req: CorpVpnStartRequest) -> anyhow::Result<CorpVpnStatusData> {
        anyhow::bail!("corporate VPN is only supported on macOS in this build")
    }
    pub async fn stop() -> anyhow::Result<()> {
        Ok(())
    }
    pub async fn status() -> CorpVpnStatusData {
        CorpVpnStatusData::default()
    }
}

#[cfg(feature = "standalone")]
pub use imp::{start, status, stop};

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
