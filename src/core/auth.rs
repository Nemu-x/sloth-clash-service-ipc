// TODO(Layer 3 — real trust boundary, pending code-signing certificate):
// The `X-IPC-Magic` check below is NOT security. `IPC_AUTH_EXPECT` is a public
// compile-time constant, and in the deployment model the attacker shares the
// legitimate GUI's SID, so it authenticates nothing. Replace/augment this with an
// OS-level caller check before any privileged action:
//   * Windows: `GetNamedPipeClientProcessId` -> resolve the client image path ->
//     verify its Authenticode signature chains to our publisher (subject/thumbprint)
//     and matches the expected product.
//   * macOS: `LOCAL_PEERCRED`/`getpeereid` + `SecCodeCreateWithPeerAuditToken` +
//     `SecCodeCheckValidity` against our signing requirement.
// Until the cert exists, the magic header is kept only as a weak liveness token;
// the actual LPE mitigations live in `security.rs` (Layer 1) and `server.rs`/socket
// permissions (Layer 2).
use crate::IPC_AUTH_EXPECT;
use kode_bridge::errors::KodeBridgeError;
use kode_bridge::ipc_http_server::RequestContext;

#[derive(Debug, PartialEq, Eq)]
pub enum AuthStatus {
    Authorized,
}

pub fn ipc_request_context_to_auth_context(
    ctx: &RequestContext,
) -> Result<AuthStatus, KodeBridgeError> {
    let headers = &ctx.headers;
    match headers.get("X-IPC-Magic") {
        Some(token) if token == IPC_AUTH_EXPECT => Ok(AuthStatus::Authorized),
        Some(_) => Err(KodeBridgeError::ClientError { status: 401 }),
        None => Err(KodeBridgeError::ClientError { status: 401 }),
    }
}
