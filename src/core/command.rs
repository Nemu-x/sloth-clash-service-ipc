use serde::{Deserialize, Serialize};
use strum_macros::{AsRefStr, EnumString};

#[derive(Debug, Clone, Serialize, Deserialize, EnumString, AsRefStr)]
pub enum IpcCommand {
    #[strum(serialize = "/version")]
    GetVersion,
    // #[strum(serialize = "/clash")]
    // GetClash,

    // 用于日志界面加载上一次日志内容
    #[strum(serialize = "/clash/logs")]
    GetClashLogs,

    #[strum(serialize = "/clash/start")]
    StartClash,
    #[strum(serialize = "/clash/stop")]
    StopClash,
    // Force-remove a stale wintun TUN adapter (Windows). A core force-killed
    // during an app update/crash never gets to delete its adapter, and a newer
    // wintun.dll cannot reopen an adapter created by an older one — either way
    // the next create fails with "access is denied" until the registered PnP
    // device is removed. The unprivileged app cannot do this; only the SYSTEM
    // service can. No-op on non-Windows and when no wintun adapter exists.
    #[strum(serialize = "/tun/remove")]
    RemoveTun,
    #[strum(serialize = "/writer")]
    UpdateWriter,
    #[strum(serialize = "/magic")]
    Magic,
}
