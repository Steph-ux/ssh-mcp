# ssh-mcp v4.0

MCP server for persistent SSH work across Linux hosts and network devices.

## Features

- **Persistent SSH connections** with automatic reconnection
- **Secure credential storage** via Windows Credential Manager
- **Network device support**: Cisco IOS/IOS-XE/XR, MikroTik, FortiGate, Juniper
- **Config management**: backup, restore, diff for network devices
- **SFTP**: upload, download, list remote files
- **SSH tunnels**: persistent port forwarding
- **Rate limiting**: prevents device saturation (100ms minimum between commands)
- **Smart connection**: use `ssh_connect(alias='vps')` to load saved credentials automatically

## Quick Start

### 1. Save a server (once)

```python
ssh_save_server(
    alias='vps',
    host='192.168.10.1',
    username='sassogba',
    password='your-password',
    auto_connect=True  # Auto-connect on startup
)
```

### 2. Connect (simple mode)

```python
ssh_connect(alias='vps')  # Loads credentials from servers.json
```

### 3. Execute commands

```python
ssh_exec(alias='vps', command='df -h')
ssh_exec_sudo(alias='vps', command='systemctl restart nginx', sudo_password='...')
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
```
1. Save: ssh_save_server(alias='vps', host='192.168.10.1', username='sassogba', password='...')
2. Connect: ssh_connect(alias='vps')
3. Execute: ssh_exec(alias='vps', command='df -h')
```

## 18 Tools Available

### Connection Management
- `ssh_connect` - Establish persistent SSH connection (smart mode: just provide alias)
- `ssh_disconnect` - Close connection and tunnels
- `ssh_list` - List active connections with status

### Persistent Configuration
- `ssh_save_server` - Save server to servers.json (secrets in Credential Manager)
- `ssh_remove_server` - Remove saved server
- `ssh_list_servers` - List all saved servers

### Linux/Unix Execution
- `ssh_exec` - Execute shell command
- `ssh_exec_sudo` - Execute with sudo (auto password injection)

### Network Device Execution
- `ssh_exec_network` - Execute commands on network devices (handles pagination, prompts)
- `ssh_push_config` - Deploy configuration block
- `ssh_backup_config` - Backup running config to local file
- `ssh_restore_config` - Restore config from backup file
- `ssh_diff_config` - Compare configs (git-style diff)

### SFTP
- `ssh_upload` - Upload file to remote server
- `ssh_download` - Download file from remote server
- `ssh_list_remote` - List remote directory contents

### Tunnels
- `ssh_tunnel` - Create persistent SSH tunnel (port forwarding)
- `ssh_close_tunnel` - Close tunnel by label

## Architecture

- **SSHPool**: Thread-safe connection pool with automatic reconnection
- **SSHConnection**: Per-connection state with RLock for thread safety
- **ThreadPoolExecutor**: Async/await wrapper for Paramiko (which is synchronous)
- **Rate limiter**: 100ms minimum between commands to prevent device saturation
- **Timeout handling**: Multiple levels (per-command, total, absolute) with proper error propagation

## Requirements

```
paramiko>=3.0.0
mcp>=1.0.0
pywin32>=306
```

Install with:
```bash
pip install -r requirements.txt
```

## Run Tests

```powershell
python -m pytest tests -v
```

## Documentation

- [CLAUDE_CODE_USAGE.md](CLAUDE_CODE_USAGE.md) - Usage examples for Claude Code
- [CLAUDE_CODE_SETUP.md](CLAUDE_CODE_SETUP.md) - Configuration guide
- [CHANGELOG.md](CHANGELOG.md) - Version history and migration guide

## License

MIT
