use serde::{Deserialize, Serialize};
#[cfg(feature = "client")]
use serde_json::Value;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClashConfig {
    pub core_config: CoreConfig,
    pub log_config: WriterConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    pub core_path: String,
    pub core_ipc_path: String,
    pub config_path: String,
    pub config_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriterConfig {
    pub directory: String,
    pub max_log_size: u64,
    pub max_log_files: usize,
}

/// Request to bring up the corporate VPN. `bin_path` points at the OpenConnect
/// executable the app downloaded on-demand (its bundle also contains the
/// `vpnc-script` alongside it). `servercert` is empty on the first connect; the
/// service returns the fingerprint to trust, and the app retries with it pinned.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CorpVpnStartRequest {
    pub bin_path: String,
    pub gateway: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub servercert: String,
}

/// Corporate-VPN state reported back to the app. On a first connect against an
/// untrusted certificate, `needs_cert_trust` is true and `servercert_sha256`
/// carries the fingerprint to show the user. On success, `routes`/`dns_*` are
/// what the gateway pushed — the app excludes `routes` from mihomo and splits
/// DNS for `dns_domains`. `full_tunnel` means the gateway took the default route
/// (no split is possible).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CorpVpnStatusData {
    pub connected: bool,
    pub needs_cert_trust: bool,
    pub servercert_sha256: String,
    pub routes: Vec<String>,
    pub dns_servers: Vec<String>,
    pub dns_domains: Vec<String>,
    pub full_tunnel: bool,
    /// The tunnel interface OpenConnect brought up (e.g. "utun4"). The app binds
    /// the corp DNS resolver to it (`<resolver>#<tundev>`) so corp-domain queries
    /// egress the tunnel, and the service installs corp routes onto it.
    #[serde(default)]
    pub tundev: String,
    /// The gateway's public IP (`VPNGATEWAY`). The app excludes it from mihomo's
    /// TUN so OpenConnect's OWN traffic to the gateway goes out the physical NIC
    /// instead of looping through the proxy — otherwise DTLS/CSTP to the gateway
    /// runs over the proxy and the corp tunnel flaps (DPD dead peer).
    #[serde(default)]
    pub gateway_ip: String,
    /// Recent OpenConnect stderr lines (most recent last), for the UI log view.
    #[serde(default)]
    pub log_tail: Vec<String>,
}

#[cfg(feature = "response")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response<T> {
    pub code: u16,
    pub message: String,
    pub data: Option<T>,
}

impl Default for CoreConfig {
    fn default() -> Self {
        let core_ipc_path = if cfg!(windows) {
            r"\\.\pipe\sloth-mihomo".to_string()
        } else {
            "/tmp/slothclash/sloth-mihomo.sock".to_string()
        };
        Self {
            core_path: "./clash".to_string(),
            core_ipc_path,
            config_path: "./config.yaml".to_string(),
            config_dir: "./configs".to_string(),
        }
    }
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            directory: "./logs".to_string(),
            max_log_size: 10 * 1024 * 1024, // 10 MB
            max_log_files: 8,
        }
    }
}

#[cfg(feature = "client")]
pub trait JsonConvert: Serialize + for<'de> Deserialize<'de> {
    /// 转换为 JSON Value
    fn to_json_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    // /// 从 JSON Value 转换
    // fn from_json_value(value: Value) -> Result<Self, serde_json::Error> {
    //     serde_json::from_value(value)
    // }

    // /// 序列化为 JSON 字符串
    // fn to_json_string(&self) -> Result<String, serde_json::Error> {
    //     serde_json::to_string(self)
    // }

    // /// 从 JSON 字符串转换
    // fn from_json_string(json: &str) -> Result<Self, serde_json::Error> {
    //     serde_json::from_str(json)
    // }
}
#[cfg(feature = "client")]
impl<T> JsonConvert for T where T: Serialize + for<'de> Deserialize<'de> {}
