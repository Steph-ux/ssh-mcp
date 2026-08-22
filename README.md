# ssh-mcp v5.0

Unified MCP server for persistent SSH work across Linux hosts, network devices, and offensive pentest environments.

## Features (7 Unified Tools)

- **`ssh_session`**: Persistent SSH connections (connect/disconnect/list), jump hosts (bastions), zlib compression, proactive keepalive
- **`ssh_server`**: Credential-safe server inventory management (save/remove/list) via Windows Credential Manager
- **`ssh_exec`**: Unified shell execution (standard sync, sudo with automated prompt detection & secret masking, background job dispatching)
- **`ssh_job`**: Background job supervision (status, realtime log streaming tail, kill)
- **`ssh_sftp`**: File & recursive directory transfers (upload, download, upload_dir, download_dir, list) with configurable timeouts
- **`ssh_network`**: Network automation for Cisco, MikroTik, FortiGate, Juniper (interactive exec, config push, backup, safe dry-run restore, diff)
- **`ssh_tunnel`**: TCP port forwarding and dynamic SOCKS5 proxy server

## Quick Start

### 1. Save a server (once)

```python
ssh_server(
    action='save',
    alias='vps',
    host='192.168.10.1',
    username='admin',
    password='your-password',
    auto_connect=True  # Auto-connect on startup
)
```

### 2. Connect (simple mode)

```python
ssh_session(action='connect', alias='vps')  # Loads credentials automatically
```

### 3. Execute commands

```python
ssh_exec(alias='vps', command='df -h')
ssh_exec(alias='vps', command='systemctl restart nginx', sudo_password='...')
ssh_exec(alias='vps', command='nmap -sS -p- 10.0.0.0/24', background=True, label='full-scan')
```

### 4. SFTP & SOCKS5 Proxy

```python
# Recursive download without manual zip:
ssh_sftp(action='download_dir', alias='vps', remote_path='/home/user/app', local_path='D:\\home\\app')

# Dynamic SOCKS5 proxy on port 1080:
ssh_tunnel(action='start_socks', alias='vps', label='socks-vps', local_port=1080)
```

## What's New in v4.0

### Smart Connection Mode
- `ssh_connect` now accepts just an alias to load credentials automatically
- No need to provide host, username, password every time
- Fixes Claude Code integration issues

### Critical Fixes
- **Timeout handling**: Now raises `TimeoutError` instead of silently returning incomplete buffers
- **Rate limiting**: 100ms minimum between network commands to prevent device saturation
- **Magic numbers eliminated**: Named constants for shell dimensions

### Documentation
- New `CLAUDE_CODE_USAGE.md` with complete usage examples
- New `CLAUDE_CODE_SETUP.md` for configuration
- New `CHANGELOG.md` with full version history

## Security Model

`servers.json` only keeps non-sensitive metadata. Secrets live in Windows Credential Manager under targets like:

- `ssh-mcp:<alias>:password`
- `ssh-mcp:<alias>:key_passphrase`

## Host Key Policy

- `strict`: default, rejects unknown host keys (production)
- `auto_add`: accepts unknown host keys (lab only)

## Network Devices

Supported device types:
- `cisco` - Cisco IOS/IOS-XE
- `cisco_xr` - Cisco IOS-XR
- `mikrotik` - MikroTik RouterOS
- `fortigate` - FortiGate FortiOS
- `juniper` - Juniper JunOS
- `generic` - Linux/Unix (default)

### Example: Cisco backup

```python
# Save once
ssh_save_server(
    alias='cisco-core',
    host='10.0.0.1',
    username='admin',
    password='...',
    device_type='cisco',
    auto_connect=True
)

# Connect
ssh_connect(alias='cisco-core')

# Backup config
ssh_backup_config(alias='cisco-core', device_type='cisco')
# Saved to: backups/cisco-core/cisco-core_2026-05-31_14-30-00.txt

# Execute commands
ssh_exec_network(
    alias='cisco-core',
    commands=['show version', 'show ip interface brief'],
    device_type='cisco'
)

# Push config
ssh_push_config(
    alias='cisco-core',
    config='''
interface GigabitEthernet0/1
 description Uplink to Core
 ip address 10.0.1.1 255.255.255.0
 no shutdown
''',
    device_type='cisco',
    save_config=True
)
```

## Usage with Claude Code

See [CLAUDE_CODE_USAGE.md](CLAUDE_CODE_USAGE.md) for detailed examples.

**TL;DR:**
```python
1. Save: ssh_server(action='save', alias='vps', host='192.168.10.1', username='admin', password='...')
2. Connect: ssh_session(action='connect', alias='vps')
3. Execute: ssh_exec(alias='vps', command='df -h')
```

## 7 Unified Tools

### 1. `ssh_session`
- `connect` - Establish or reuse persistent SSH connection (smart mode: just provide alias)
- `disconnect` - Close connection, tunnels, SOCKS proxies, and jobs
- `list` - List all active connections with uptime, tunnels, proxies, and background jobs

### 2. `ssh_server`
- `save` - Save/update server in `servers.json` (secrets securely kept in Credential Manager)
- `remove` - Delete server from inventory
- `list` - List all saved servers

### 3. `ssh_exec`
- Standard sync execution (`command`)
- Sudo execution with prompt detection (`sudo_password`)
- Background execution (`background=True`, `label='...'`)

### 4. `ssh_job`
- `status` - Check background job status or list all jobs
- `tail` - Stream last N lines of stdout/stderr
- `kill` - Terminate running background job

### 5. `ssh_sftp`
- `upload` / `download` - Transfer single files with configurable timeout
- `upload_dir` / `download_dir` - Recursive directory transfers without manual zip
- `list` - List remote files and directories

### 6. `ssh_network`
- `exec` - Run sequence of interactive commands on network devices
- `push` - Push multiline configuration block (with auto-backup)
- `backup` - Backup running config to timestamped local file
- `restore` - Restore config (dry-run by default, confirm=True to apply)
- `diff` - Compare two configs or current config vs backup

### 7. `ssh_tunnel`
- `start` / `stop` - Persistent local port forwarding (TCP tunnels)
- `start_socks` / `stop_socks` - Dynamic SOCKS5 proxy server
- `list` - List active tunnels and proxies

## Installation in MCP Clients (Claude Desktop, OpenCode, Cursor, Windsurf)

### Option 1: uvx (Instant - No Installation Required)

Add directly to your MCP client configuration (`claude_desktop_config.json`, `opencode.json`, etc.):

```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/Steph-ux/ssh-mcp.git", "ssh-mcp"]
    }
  }
}
```

### Option 2: pip install

```bash
pip install git+https://github.com/Steph-ux/ssh-mcp.git
```

Then in your MCP config:
```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "ssh-mcp"
    }
  }
}
```

### Option 3: Local Clone (Development)

```bash
git clone https://github.com/Steph-ux/ssh-mcp.git
cd ssh-mcp
pip install -e .
```

## Architecture

- **SSHPool**: Thread-safe connection pool with automatic reconnection and jump host chaining
- **SSHConnection**: Per-connection state with RLock for thread safety
- **ThreadPoolExecutor**: Async/await wrapper for Paramiko
- **Rate limiter**: 100ms minimum between commands to prevent device saturation
- **SecretStore**: Windows Credential Manager on Windows, keyring on Linux/macOS

## Run Tests

```bash
pytest tests
```

## Documentation

- [CLAUDE_CODE_USAGE.md](CLAUDE_CODE_USAGE.md) - Usage examples for AI agents
- [CLAUDE_CODE_SETUP.md](CLAUDE_CODE_SETUP.md) - Complete client configuration guide
- [CHANGELOG.md](CHANGELOG.md) - Version history and migration guide

## License

MIT
