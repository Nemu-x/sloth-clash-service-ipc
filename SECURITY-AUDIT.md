# Security Audit — `sloth-clash-service-ipc`

**Scope:** Local privilege escalation (LPE) via the privileged IPC helper (Windows
SYSTEM service + named pipe; macOS root launchd daemon + unix socket).
**Threat model:** unprivileged local user / malicious process running as a normal
user on the same machine. Question: can they get code execution as SYSTEM/root, or
coerce a privileged action they should not be able to?

**Verdict up front: YES — trivial, reliable local user → SYSTEM (Windows) and
→ root (macOS).** See CRIT-1. Most of the weakness is inherited verbatim from the
direct upstream `clash-verge-rev/clash-verge-service-ipc`, but it is fully live here.

---

## 1. IPC surface map

### Transport / endpoint

| Platform | Endpoint | Created at |
|---|---|---|
| Windows | Named pipe `\\.\pipe\sloth-clash-service` | [lib.rs:17](src/lib.rs#L17), server built in [server.rs:242](src/core/server.rs#L242) |
| macOS/Linux | Unix socket `/tmp/slothclash/sloth-clash-service.sock` | [lib.rs:15](src/lib.rs#L15) |

The server is `kode_bridge::IpcHttpServer` — an HTTP-over-pipe/socket server. Clients
send normal REST-looking requests (method + path + JSON body).

### Access control on the transport (checklist A)

**Windows — pipe DACL:** [server.rs:255](src/core/server.rs#L255)
```rust
let server = server.with_listener_security_descriptor("D:(A;;GA;;;WD)");
```
`D:(A;;GA;;;WD)` = DACL, Allow, **GENERIC_ALL**, to **`WD` = Everyone / World**.
The pipe is **wide open to every local user**. There is an explicit SDDL — it is
explicitly permissive, not a missing/default descriptor.

**macOS/Linux — socket mode:** the listener is created with mode `0o660`
([server.rs:246-249](src/core/server.rs#L246-L249)) but then **immediately relaxed to
`0o777`** ([server.rs:56](src/core/server.rs#L56)), the parent dir is `0o2770`
([server.rs:138](src/core/server.rs#L138)) but the watchdog re-creates it `0o777`
([server.rs:224](src/core/server.rs#L224)), and per the last commit `/tmp/slothclash`
is `1777`. Net effect: **any local user can connect to the root daemon's socket.**

### Authentication / authorization of the caller (checklist B)

The *only* check before every privileged action is a static header compare
([auth.rs:10-19](src/core/auth.rs#L10-L19)):
```rust
match headers.get("X-IPC-Magic") {
    Some(token) if token == IPC_AUTH_EXPECT => Ok(AuthStatus::Authorized),
    ...
}
```
`IPC_AUTH_EXPECT` is a **hardcoded, public constant** compiled into the binary and
committed to this open-source repo ([lib.rs:25-26](src/lib.rs#L25-L26)):
```rust
pub static IPC_AUTH_EXPECT: &str =
    r#"Like as the waves make towards the pebbl'd shore, So do our minutes hasten to their end;"#;
```
This is **not a secret** — it is a fixed Shakespeare sonnet line, identical for every
install, readable in the source or by `strings` on the shipped binary. Every handler
calls `ipc_request_context_to_auth_context(&ctx)` and then proceeds
([server.rs:262-388](src/core/server.rs#L262-L388)).

**There is NO OS-level caller check anywhere:** no `GetNamedPipeClientProcessId`, no
token/SID inspection, no impersonation, no `SO_PEERCRED`/`getpeereid` on the unix
side (grep for all of these returns nothing). So authorization = "knows a public
string" = **any local process is fully trusted.**

### Command surface (checklist C) — [command.rs](src/core/command.rs), [server.rs](src/core/server.rs)

| Method + path | Handler | Client-controlled input | Runs as |
|---|---|---|---|
| `GET /magic` | [server.rs:262](src/core/server.rs#L262) | — | SYSTEM/root |
| `GET /version` | [server.rs:267](src/core/server.rs#L267) | — | SYSTEM/root |
| `POST /clash/start` | [server.rs:279](src/core/server.rs#L279) | **`ClashConfig`** (see below) | SYSTEM/root |
| `GET /clash/logs` | [server.rs:314](src/core/server.rs#L314) | — | SYSTEM/root |
| `DELETE /clash/stop` | [server.rs:327](src/core/server.rs#L327) | — | SYSTEM/root |
| `PUT /writer` | [server.rs:354](src/core/server.rs#L354) | **`WriterConfig.directory`** | SYSTEM/root |

`ClashConfig` ([structure.rs:5-24](src/core/structure.rs#L5-L24)) is **entirely
client-supplied**:
```rust
pub struct CoreConfig {
    pub core_path: String,      // ← path to the executable to run
    pub core_ipc_path: String,
    pub config_path: String,    // ← -f <config>
    pub config_dir: String,     // ← -d <dir>
}
pub struct WriterConfig { pub directory: String, ... }  // ← log output dir
```

`start_core` runs `core_path` **verbatim, with no validation, no allow-list, no
signature/hash check**, as SYSTEM/root ([manager.rs:120-144](src/core/manager.rs#L120-L144)
→ [manager.rs:369-394](src/core/manager.rs#L369-L394)):
```rust
let child_guard = run_with_logging(&config.core_config.core_path, &args, ...).await?;
// ...
Command::new(bin_path).args(args)...spawn()?
```
There is no impersonation of the caller before spawn — the child inherits the
service's SYSTEM/root token (checklist D-10: everything is done as SYSTEM).

---

## 2. Ranked findings

### CRIT-1 — Any local user gets SYSTEM/root code execution (world-open IPC + public static auth + client-supplied executable path)
**Severity: CRITICAL.** *Inherited from upstream `clash-verge-service-ipc` (same SDDL,
same magic constant) — but fully exploitable here.*

**Where:**
- Open transport: [server.rs:255](src/core/server.rs#L255) (`D:(A;;GA;;;WD)`), and
  macOS `0o777` socket [server.rs:56](src/core/server.rs#L56).
- Fake auth: [auth.rs:14-15](src/core/auth.rs#L14-L15) + public constant
  [lib.rs:25-26](src/lib.rs#L25-L26).
- Arbitrary exec: [structure.rs:13](src/core/structure.rs#L13) (`core_path`) →
  [manager.rs:144](src/core/manager.rs#L144) → [manager.rs:377/385](src/core/manager.rs#L377).

**Exploit (Windows), start to finish:**
1. Attacker is a normal user. Drops `C:\Users\pub\evil.exe` (payload: add admin
   user, drop SYSTEM shell, etc.).
2. Connects to `\\.\pipe\sloth-clash-service` — allowed, the pipe is World-accessible.
3. Sends `GET /magic` with header `X-IPC-Magic: Like as the waves make towards the
   pebbl'd shore, So do our minutes hasten to their end;` — the value is public.
4. Sends `POST /clash/start` with body
   `{"core_config":{"core_path":"C:\\Users\\pub\\evil.exe","core_ipc_path":"x","config_path":"x","config_dir":"x"},"log_config":{...}}`.
5. Service does `Command::new("C:\\Users\\pub\\evil.exe")...spawn()` **as SYSTEM**.
   → arbitrary code as `NT AUTHORITY\SYSTEM`.

**Exploit (macOS):** identical, connect to the world-writable
`/tmp/slothclash/sloth-clash-service.sock`, same magic header, `core_path` =
`/tmp/evil` → runs as **root**.

**Why the auth doesn't help:** the magic string is a compile-time constant in a
public repo and in every shipped binary. Knowledge of it conveys nothing — it is not
per-install, not random, not derived from any user secret.

**Fix (defense in depth — do all three):**
1. **Lock the transport down.** Windows: set the pipe DACL to SYSTEM + Administrators
   only, e.g. `D:P(A;;GA;;;SY)(A;;GA;;;BA)` (deny inheritance, no `WD`/`AU`/`BU`).
   macOS/Linux: create the socket `0o600` owned by root and drop the `0o777`/`1777`
   relaxations; if the GUI runs non-root, use a dedicated group and `0o660` root:that-group
   instead of world.
2. **Authenticate the caller at the OS level.** Windows: `GetNamedPipeClientProcessId`
   → open the process → verify its image path/signature (the signed desktop app) and
   token. macOS: `LOCAL_PEERCRED`/`getpeereid` + `SecCode`/audit-token signature check
   (Apple's XPC `SecCodeCheckValidity` pattern). Reject everyone else.
3. **Do not execute a client-supplied path.** Ship/pin the mihomo core path
   (install-dir-relative, in a root-only directory) and verify its
   signature/hash before spawn. Reduce the API to "start the known core with this
   *validated* config", never "run this arbitrary exe".

---

### HIGH-2 — Arbitrary config path/dir + args → privileged action / RCE even if the exec path were pinned
**Severity: HIGH.** *Inherited design.*

Even with a fixed core binary, `config_dir` / `config_path` are attacker-controlled
([structure.rs:14-16](src/core/structure.rs#L14-L16)) and passed as `-d`/`-f` to a
process running as SYSTEM/root ([manager.rs:130-141](src/core/manager.rs#L130-L141)).
mihomo/clash configs can reference external rule-providers, proxy-providers, and
(depending on build) script/exec hooks and DNS hijacking — all now driven by an
attacker and executed with SYSTEM/root network privilege. At minimum this is a
confused-deputy giving attacker-chosen TUN/routing/DNS config as root; at worst a
config-driven code path.

**Fix:** validate/normalize `config_dir` and `config_path` to a per-user, non-privileged
location the *authenticated* caller is actually allowed to use, and constrain the
config schema the service will accept. Never accept absolute paths into
system-writable areas.

---

### HIGH-3 — `PUT /writer` = arbitrary-directory file write as SYSTEM/root (confused deputy)
**Severity: HIGH.** *Inherited design.*

`WriterConfig.directory` is fully client-controlled
([structure.rs:22](src/core/structure.rs#L22)). `set_or_update_writer` →
`service_writer` builds a `FileLogWriter` that **creates and writes log files in that
directory as SYSTEM/root**, with no impersonation and no path validation
([logger.rs:14-31](src/core/logger.rs#L14-L31)). The file content is the core's
stdout/stderr, which the attacker also controls (they chose `core_path`), so the
content is attacker-influenced too ([manager.rs:408-448](src/core/manager.rs#L408-L448)).

**Exploit:** `PUT /writer {"directory":"C:\\Windows\\System32","max_log_size":...}` (or
any protected/AV-exclusion/DLL-search location); SYSTEM creates `service*.log` there.
Combined with a symlink/junction in a predictable temp dir this becomes a
TOCTOU/redirect primitive (checklist D-11). Even standalone it is a
write-where-you-shouldn't primitive that a normal user cannot otherwise achieve.

**Fix:** confine the log directory to a fixed root-only path (or per-user path chosen
by the *authenticated* GUI), reject paths outside it, and open with
`O_NOFOLLOW`/no-reparse semantics. Better: don't take a directory over IPC at all.

---

### MED-4 — No impersonation; the entire service acts as SYSTEM/root for every request
**Severity: MEDIUM (root cause of the confused-deputy findings above).**

Confirmed absence of any caller impersonation or peer-credential check (grep for
`impersonat`/`GetNamedPipeClientProcessId`/`peercred` is empty). Every file access
and process spawn uses the service token. This is the structural reason CRIT-1/HIGH-3
work. Track as the design fix behind those.

---

### MED-5 — macOS/Linux: world-writable daemon socket and socket directory
**Severity: MEDIUM (this is the macOS half of CRIT-1's transport).**

[server.rs:56](src/core/server.rs#L56) sets the socket to `0o777`;
[server.rs:224](src/core/server.rs#L224) re-creates the parent dir `0o777`;
[manager.rs:340](src/core/manager.rs#L340) sets the mihomo control socket `0o777`; the
last commit sets `/tmp/slothclash` to `1777`. A predictable, world-writable path in
`/tmp` also invites pre-creation / squatting of the socket path before the daemon
binds (DoS / redirect). **This is looser than what the upstream Unix comments intend
(`0o2770` group-scoped)** — the `0o777` relaxations were added locally to "just make
it work" and should be reverted to a root-owned, group-scoped scheme.

**Fix:** socket `0o660` root:`<gui-group>`, directory `0o750` root:`<gui-group>`, no
`0o777`, no `1777`; drop the watchdog's `0o777` reset.

---

### LOW-6 — `panic = "abort"` + broad SYSTEM service = crash/DoS surface
**Severity: LOW.** [Cargo.toml:115](Cargo.toml#L115). A panic in any handler aborts
the whole SYSTEM service. Not an LPE by itself, but any unauthenticated client can
feed malformed input to try to crash it; combined with the auto-restart/recovery this
is a nuisance-DoS. Handlers already return errors for bad JSON, so risk is low.

---

### INFO-7 — Install-time posture depends on the external installer (checklist E)
**Severity: INFORMATIONAL — verify in the desktop-app repo, not fixable here.**

- Windows service is created with `account_name: None` (LocalSystem), `AutoStart`,
  `ImagePath = <install-dir>\sloth-clash-service.exe`
  ([install_service.rs:236-262](src/bin/install_service.rs#L236-L262)). The
  `windows-service` crate does **not** auto-quote the `ImagePath`, so if the desktop
  installer places the binary under a path containing spaces, the registry `ImagePath`
  will be **unquoted** → classic unquoted-service-path if any earlier path segment is
  user-writable. Verify the installer (a) quotes/uses a space-free or non-user-writable
  path, and (b) ACLs the install dir to Administrators/SYSTEM only. If a normal user can
  overwrite `sloth-clash-service.exe` or plant a DLL beside it, that is a second,
  independent SYSTEM LPE (checklist E-12/14) — but that ACL is set by the installer,
  not by this repo.
- macOS install posture here **is** correct: helper binary `chmod 544` + `chown
  root:wheel`, plist `644 root:wheel`, bundle `root:wheel`
  ([install_service.rs:99-114](src/bin/install_service.rs#L99-L114)). No world-write on
  the binary/plist — good. (The runtime *socket* is still the problem, see MED-5.)

---

### INFO-8 — Secret logging (checklist G-20)
The magic constant is not logged (`trace!` lines log command names, not header values,
[server.rs:262-355](src/core/server.rs#L262-L355)). And it is not a secret anyway. No
finding beyond CRIT-1.

---

## 3. Verdict

**Is there an unprivileged-user → SYSTEM/root path? YES — directly and reliably, on
both Windows and macOS.**

The chain is: **world-accessible IPC transport** (Windows pipe `D:(A;;GA;;;WD)`,
macOS `0o777` socket) + **fake authentication** (a public hardcoded magic string, no
OS-level caller check) + **`POST /clash/start` executes a client-supplied
`core_path` as SYSTEM/root with no validation or signature check**. Any local user
completes it with a few dozen lines of client code.

Both of the enabling weaknesses (the `WD` pipe DACL and the static magic header) are
**inherited unchanged from the direct upstream `clash-verge-rev/clash-verge-service-ipc`**,
which itself regressed from the older `clash-verge-service` (that at least used
HMAC-SHA256 request signing + timestamps — still not an OS access-control boundary,
but not a world-public constant). The macOS `0o777` socket/dir relaxations
(MED-5) appear to be **local changes** in this fork and are looser than the upstream
`0o2770` intent.

Fixing CRIT-1 requires all three of: (1) restrict the transport ACL to
SYSTEM/Administrators (Windows) / root+group (macOS), (2) authenticate the caller at
the OS level (client PID → image signature/token; peercred + code-signature on
macOS), and (3) stop executing client-supplied binary paths — pin and verify the
core. HIGH-2/HIGH-3 should be fixed in the same pass by validating config/log paths
and not acting as an unconditional deputy.
