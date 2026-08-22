# Changelog

## [5.0.0] - 2026-08-22

### Unification Architecture (26 to 7 MCP Tools)

- **Ergonomic grouping & Token optimization (-70%)**:
  - `ssh_session`: Connect, disconnect, pool listing (with jump hosts, keepalive, zlib compression).
  - `ssh_server`: Inventory servers.json (save, remove, list).
  - `ssh_exec`: Unified shell execution (sync, sudo with prompt detection, background jobs).
  - `ssh_job`: Background jobs supervision (status, streaming tail, kill).
  - `ssh_sftp`: File & directory transfers (upload, download, upload_dir, download_dir, list).
  - `ssh_network`: NetOps automation (exec, push config, backup, restore dry-run/confirm, diff).
  - `ssh_tunnel`: TCP port-forwarding tunnels and dynamic SOCKS5 proxy.
- **Full Backward Compatibility**: All legacy tool names (`ssh_connect`, `ssh_upload`, `ssh_exec_sudo`, etc.) continue to be transparently routed.
- **Test Suite**: 28/28 unit tests passing.

## [4.3.0] - 2026-08-22

### 5 Major Improvements (NetOps & Pentest Architecture)

1. **Recursive directory transfers (`ssh_upload_dir` / `ssh_download_dir`) & SFTP Timeouts**:
   - Full directory tree transfer over SFTP without requiring manual zip archives.
   - Configurable `timeout` parameter on `ssh_upload`, `ssh_download`, `ssh_upload_dir` and `ssh_download_dir`.
   - Transparent recursive remote directory creation (`mkdir -p` SFTP).

2. **Dynamic SOCKS5 Proxy (`ssh_socks` / `ssh_close_socks`)**:
   - Integrated SOCKS5 RFC 1928 server bound to `127.0.0.1:local_port`.
   - Supports no-auth handshake, address resolution for IPv4 (`0x01`), domain names (`0x03`) and IPv6 (`0x04`).
   - Routes traffic from local tools (Burp Suite, curl, browser, scanner) through the remote SSH host via `direct-tcpip` channels.

3. **Native Jump Host / Bastion Support (`jump_alias`)**:
   - `jump_alias` parameter in `ssh_connect` and `servers.json`.
   - Transparent chaining through active bastion's `direct-tcpip` channels.
   - Automatic ordering during startup autoconnect (bastions connect first).

4. **Asynchronous Background Jobs (`ssh_exec_background`, `ssh_job_status`, `ssh_job_tail`, `ssh_job_kill`)**:
   - Run long commands in the background without blocking MCP client requests.
   - Bounded streaming memory capture of `stdout` and `stderr` streams.
   - Real-time status tracking, log inspection, and kill on demand.

5. **Keepalive & Transport Compression**:
   - Zlib compression (`compress=True`) enabled by default to accelerate SFTP transfers.
   - Periodic keepalive packets (`keepalive_interval=30`) to eliminate silent NAT/firewall drops.

### Tests
- New `tests/test_new_features.py` covering:
  - SOCKS5 handshake and connection
  - Recursive directory transfers
  - Background job lifecycle
  - Jump Host chaining
  - Compression & keepalive options
- Full suite: 27/27 tests passed.

## [4.2.1] - 2026-08-22

### Client Safety & MCP Protocol Compliance

- **MCP Return Validation (`TextContent`)**: `call_tool` guarantees returned text is always a non-null string (`str`), preventing client-side crashes (`undefined is not an object` / `output.slice` crash).
- **Missing arguments protection**: All tools explicitly validate required arguments and return clean standardized error messages (`ERREUR : '...' est requis`).
- **MCP Test Suite**: Systematic validation of tools with empty and `None` arguments.

## [4.2.0] - 2026-08-21

### Security Fixes

- **Sudo password leak prevention**: With `get_pty=True`, stdout and stderr are merged into a single stream. Password is now only written when prompt `[sudo] password:` / `Password:` is detected. On NOPASSWD hosts, no secret is transmitted.
  - Password is masked (`***`) in all output, including PTY echo.
  - Exception messages containing the password are also sanitized.
- **Anti-OOM**: Output reads are bounded (`_read_bounded`, default 10MB limit, configurable via `SSH_MCP_MAX_OUTPUT_BYTES`).

### Robustness

- **Atomic write for `servers.json`**: tmp + `os.replace` + threading lock prevents JSON corruption.

### Improvements

- **Secret portability**: `SecretStore` supports `keyring` fallback (Linux Secret Service / macOS Keychain) when `win32cred` is absent.
- `ssh_exec_network`: `max_total_timeout` exposed in tool schema.

### Tests

- New `tests/test_sudo_security.py` (3 tests) validating sudo security.

## [4.1.0] - 2026-08-03

### Fixes

- **Network device backups cleaning**: `backup_config` output sanitized (`clean_device_output`) and filtered (`strip_config_noise`).
- **Pagination `--More--`**: Proper marker removal and page limit guards.
- **Isolated timeout handling**: Command errors isolated per command with clean socket closure in finally blocks.

### Breaking

- `ssh_restore_config` is dry-run by default. Pass `confirm=true` to execute.

### Improvements

- `ssh_push_config`: Automatic pre-deployment backup (`backup_first`, enabled by default).
- `ssh_save_server`: Partial updates preserve existing fields.
- `ssh_connect`: Merge saved configuration with explicit arguments.
- SFTP: Automatic reconnection.
- Tunnels: Resilient transport handles reconnections.
- Keepalive set to 30s.

## [4.0.0] - 2026-05-31

### Major Features

- **Smart Connection Mode**: `ssh_connect` accepts alias to load credentials from `servers.json` automatically.
- **Rate Limiting**: 100ms minimum interval between network commands.
- **Timeout handling**: Raises `TimeoutError` instead of returning incomplete buffers.
- **Code Quality**: Named constants for shell dimensions.
- **Documentation**: New usage and configuration guides.

---

## [3.0.0] - Initial Release

- Core MCP tools for SSH management.
- Linux/Unix and network device support.
- Secure credential storage via Windows Credential Manager.
- SFTP support and port forwarding tunnels.

---

## License

MIT License
