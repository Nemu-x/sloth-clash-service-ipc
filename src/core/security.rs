//! Layer-1 LPE mitigations for the privileged IPC service.
//!
//! Threat model note: in the supported deployment an administrator installs the
//! service and the desktop app, then a *non-admin* user drives the GUI. The
//! attacker is a process running as that same non-admin user, so it shares the
//! SID of the legitimate GUI. Therefore **neither the pipe DACL nor the static
//! `X-IPC-Magic` header is a real trust boundary** — both are only nuisance
//! hardening (Layer 2). The real boundaries are:
//!
//!   * Layer 1 (this module): never let a caller make the SYSTEM/root service
//!     execute a binary a non-admin could have swapped, and confine the files it
//!     is pointed at. Implemented without a caller-signing certificate.
//!   * Layer 3 (pending code-signing cert, see `auth.rs`): authenticate the
//!     caller's process. Only this fully stops a same-user attacker.
//!
//! Core-trust strategy (see `validate_core_path`):
//!   * The SlothClash desktop app extracts its embedded core into a *user-writable*
//!     `%APPDATA%\SlothClash\runtime\_sidecar\...` — so a location allow-list alone
//!     would either reject the legit core or (if that dir were allow-listed) let a
//!     same-user attacker swap the binary. The primary control is therefore a
//!     **content pin (SHA-256)** supplied out-of-band in the SYSTEM service's own
//!     environment, which a non-admin attacker cannot influence.
//!   * When no hash is pinned, fall back to the admin-only-location allow-list for
//!     deployments that install the core under a privileged directory.

use anyhow::{Result, bail};
use std::path::{Component, Path, PathBuf};

/// Env var (read from the SYSTEM/root service's own environment) holding one or
/// more expected core SHA-256 hashes, separated by comma / semicolon / whitespace.
/// Multiple hashes allow a seamless core bump (old + new both valid).
const CORE_SHA256_ENV: &str = "SLOTH_CLASH_CORE_SHA256";
/// Env var listing extra admin-only directories the core may live in (fallback
/// mode, when no hash is pinned). Platform path separator (`;` win / `:` unix).
const CORE_ALLOWED_DIRS_ENV: &str = "SLOTH_CLASH_CORE_ALLOWED_DIRS";

/// Validate a client-supplied core executable path and return the canonical
/// (symlink-resolved) path to spawn.
///
/// Precedence: if `SLOTH_CLASH_CORE_SHA256` is set, the binary's content MUST match
/// a pinned hash (path may live anywhere, including a user-writable dir — the hash
/// is what is trusted). Otherwise, the binary must reside under an administrator-only
/// directory. In both cases the path must resolve to an existing regular file.
pub fn validate_core_path(core_path: &str) -> Result<PathBuf> {
    if core_path.trim().is_empty() {
        bail!("core_path is empty");
    }

    let canonical = std::fs::canonicalize(core_path)
        .map_err(|e| anyhow::anyhow!("core_path cannot be resolved ({core_path}): {e}"))?;
    if !canonical.is_file() {
        bail!("core_path is not a regular file: {}", canonical.display());
    }

    // Primary: content pin. Preferred and stricter — decoupled from location.
    let pinned = pinned_core_hashes();
    if !pinned.is_empty() {
        let actual = sha256_hex(&canonical)?;
        if pinned.iter().any(|h| h == &actual) {
            return Ok(canonical);
        }
        bail!(
            "core binary SHA-256 {} does not match any pinned hash ({})",
            actual,
            canonical.display()
        );
    }

    // Fallback: admin-only location allow-list (no hash configured).
    if !is_admin_only_location(&canonical) {
        bail!(
            "refusing to execute core from a non-privileged location: {} \
             (no SHA-256 pin configured and path is not under an administrator-only directory)",
            canonical.display()
        );
    }

    Ok(canonical)
}

/// Best-effort confinement for a client-supplied config/log path handed to (or
/// written by) the privileged service. Blocks clearly sensitive system locations
/// while allowing per-user paths (the GUI's config and log dirs live under
/// `%APPDATA%`). Works even for paths that do not exist yet — important for the log
/// directory, which the service *creates* (a not-yet-existing `%SystemRoot%\evil`
/// must still be refused). Full per-user confinement needs caller authentication
/// (Layer 3).
pub fn validate_config_location(path: &str, kind: &str) -> Result<()> {
    if path.trim().is_empty() {
        return Ok(());
    }
    let p = Path::new(path);
    // Relative paths are resolved by the core / logger against their own working
    // directory and cannot reach a system location without an absolute prefix.
    if !p.is_absolute() {
        return Ok(());
    }
    let normalized = normalize_abs(p);
    if is_sensitive_location(&normalized) {
        bail!(
            "refusing {kind} inside a protected location: {}",
            normalized.display()
        );
    }
    Ok(())
}

/// Fixed, administrator-only directory used only as a *fallback* when the client
/// supplies no log directory. The normal path is to honor the client's per-user
/// log dir (validated by `validate_config_location`) so the GUI can read logs back.
pub fn pinned_log_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        return dir.join("logs");
    }
    #[cfg(windows)]
    {
        std::env::temp_dir().join("slothclash-logs")
    }
    #[cfg(unix)]
    {
        PathBuf::from("/var/log/slothclash")
    }
}

fn pinned_core_hashes() -> Vec<String> {
    match std::env::var(CORE_SHA256_ENV) {
        Ok(v) => v
            .split([',', ';', ' ', '\t', '\n', '\r'])
            .map(|s| s.trim().to_lowercase())
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn sha256_hex(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("cannot read core for hashing ({}): {e}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    Ok(out)
}

/// Directories that are, by OS convention, writable only by administrators/root
/// AND expected to hold app/core binaries. Deliberately excludes `C:\Windows`,
/// `/bin`, `/usr/bin`, etc.: admin-only but full of interpreters/LOLBins that would
/// re-open the exec primitive.
fn allowed_core_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();

    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        roots.push(dir.to_path_buf());
    }

    #[cfg(windows)]
    {
        for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
            if let Some(v) = std::env::var_os(var) {
                roots.push(PathBuf::from(v));
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        for p in ["/Applications", "/Library"] {
            roots.push(PathBuf::from(p));
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for p in ["/opt", "/usr/lib", "/usr/libexec"] {
            roots.push(PathBuf::from(p));
        }
    }

    if let Some(extra) = std::env::var_os(CORE_ALLOWED_DIRS_ENV) {
        let sep = if cfg!(windows) { ';' } else { ':' };
        for part in extra.to_string_lossy().split(sep) {
            let part = part.trim();
            if !part.is_empty() {
                roots.push(PathBuf::from(part));
            }
        }
    }

    roots
        .into_iter()
        .filter_map(|r| std::fs::canonicalize(r).ok())
        .collect()
}

fn is_admin_only_location(canonical_file: &Path) -> bool {
    allowed_core_roots()
        .iter()
        .any(|root| is_under(canonical_file, root))
}

fn is_sensitive_location(candidate: &Path) -> bool {
    let mut roots: Vec<PathBuf> = Vec::new();

    #[cfg(windows)]
    {
        if let Some(v) = std::env::var_os("SystemRoot") {
            roots.push(PathBuf::from(v));
        }
        // %ProgramFiles% is admin-only: clients must not aim config/log writes here.
        for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
            if let Some(v) = std::env::var_os(var) {
                roots.push(PathBuf::from(v));
            }
        }
    }
    #[cfg(unix)]
    {
        for p in ["/etc", "/root", "/var/root", "/usr", "/bin", "/sbin"] {
            roots.push(PathBuf::from(p));
        }
    }

    // The service's own directory must never be a client read/write target.
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        roots.push(dir.to_path_buf());
    }

    roots
        .into_iter()
        .map(|r| normalize_abs(&r))
        .any(|r| is_under(candidate, &r))
}

/// Lexically normalize an absolute path (resolve `.`/`..`) without requiring the
/// path to exist. If it does exist, prefer the canonical form (also resolves
/// symlinks). Used so protected-location checks work on not-yet-created paths.
fn normalize_abs(p: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(p) {
        return c;
    }
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Case- and separator-insensitive (on Windows) "is `candidate` inside `root`?",
/// tolerant of the `\\?\` verbatim prefix that `canonicalize` adds.
fn is_under(candidate: &Path, root: &Path) -> bool {
    let c = norm_key(candidate);
    let r = norm_key(root);
    if r.is_empty() {
        return false;
    }
    c == r || c.starts_with(&format!("{r}/"))
}

fn norm_key(p: &Path) -> String {
    let s = p.to_string_lossy();
    let s = s
        .strip_prefix(r"\\?\")
        .map(|x| x.to_string())
        .unwrap_or_else(|| s.to_string());
    let mut s = s.replace('\\', "/");
    if cfg!(windows) {
        s = s.to_lowercase();
    }
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    s
}
