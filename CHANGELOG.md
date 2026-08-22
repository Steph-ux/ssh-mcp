# Changelog

## [4.2.1] - 2026-08-22

### 🛡️ Client Safety & MCP Protocol Compliance

- **Validation des retours MCP (`TextContent`)** : `call_tool` garantit désormais que le texte renvoyé est toujours une chaîne de caractères non-nulle (`str`), évitant les exceptions côté client (`undefined is not an object` / `output.slice` crash).
- **Protection contre les arguments manquants** : tous les 18 outils vérifient explicitement la présence des arguments requis et retournent un message d'erreur standardisé (`ERREUR : '...' est requis`) au lieu de laisser fuiter des `KeyError`.
- **Suite de tests MCP** : validation systématique des 18 outils avec arguments vides et `None` (22/22 tests passants).

## [4.2.0] - 2026-08-21

### 🔒 Security Fixes

- **Fuite possible du mot de passe sudo (critique)** : avec `get_pty=True`, stdout et stderr sont fusionnés en un seul flux — l'ancien filtre ne nettoyait que stderr, donc le password pouvait apparaître en clair dans la sortie combinée (ex : commande qui lit stdin). Désormais :
  - Le password n'est écrit sur stdin **que lorsqu'un prompt `[sudo] password:` / `Password:` est réellement détecté**. Sur un hôte NOPASSWD, aucun secret n'est transmis (il ne peut plus fuiter dans le stdin de la commande elle-même).
  - Le password est **masqué (`***`) dans toute la sortie**, y compris l'écho PTY.
  - Les messages d'exception contenant le password sont également masqués.
- **Anti-OOM** : les lectures de sortie sont désormais bornées (`_read_bounded`, limite 10 Mo par défaut, configurable via `SSH_MCP_MAX_OUTPUT_BYTES`). Un `cat /dev/urandom` ou un log géant retourne une erreur au lieu d'aspirer la mémoire du serveur MCP.

### 🛡️ Robustesse

- **Écriture atomique de `servers.json`** : tmp + `os.replace` + lock threading — plus de JSON corrompu si le process meurt mid-write.

### ✨ Improvements

- **Portabilité des secrets** : `SecretStore` supporte maintenant un fallback `keyring` (Linux Secret Service / macOS Keychain) quand `win32cred` est absent. Sur une machine sans store disponible, erreur explicite à l'usage au lieu d'un crash à l'import.
- `ssh_exec_network` : le paramètre `max_total_timeout` est désormais exposé dans le schéma du tool (était codé en dur à 120 s côté handler).

### 🧪 Tests

- Nouveau `tests/test_sudo_security.py` (3 tests) prouvant :
  - NOPASSWD → password jamais envoyé sur stdin
  - Prompt détecté → password envoyé une fois, écho PTY masqué
  - Exception contenant le password → masqué dans stderr
- Suite complète : **19/19 passent**.

## [4.1.0] - 2026-08-03

### 🐛 Critical Fixes

- **Backups d'équipements réseau corrompus** : `backup_config` renvoyait la sortie brute du shell (en-têtes `[alias] # cmd`, écho de commande, prompt). Ces lignes passaient le filtre de `ssh_restore_config` et étaient **poussées comme commandes de configuration**. La sortie est désormais nettoyée (`clean_device_output`) et le filtrage de restore (`strip_config_noise`) écarte en-têtes, bannières et commentaires.
- **Pagination `--More--`** : le marqueur était re-détecté indéfiniment dans le buffer cumulé (envoi d'espaces en boucle) et la troncature à `rfind("\n")` supprimait une ligne réelle par page. Le marqueur est maintenant retiré du buffer, avec garde-fou `MAX_PAGES`.
- **Un timeout annulait tout le batch** : `timeout_s` et `max_timeout_absolu` étaient identiques, donc toute commande lente levait `TimeoutError` et abandonnait les commandes restantes, en laissant le canal SSH ouvert. Timeout d'inactivité et deadline absolue sont désormais distincts, l'erreur est isolée par commande, et `shell.close()` est dans un `finally`.

### ⚠️ Breaking

- `ssh_restore_config` est en **dry-run par défaut**. Passer `confirm=true` pour exécuter réellement.

### ✨ Improvements

- `ssh_push_config` : backup automatique avant déploiement (`backup_first`, activé par défaut) servant de point de rollback.
- `ssh_save_server` : mise à jour partielle — les champs non fournis (`key_path`, `device_type`, `known_hosts_path`…) sont conservés. `host`/`username` ne sont plus requis sur un alias existant.
- `ssh_connect` : fusion config sauvegardée + arguments explicites. Fournir `host` n'écarte plus les credentials du Credential Manager.
- SFTP (`upload`/`download`/`list_remote`) : reconnexion automatique comme `exec`.
- Tunnels : le transport est relu à chaque connexion entrante et survit à une reconnexion.
- Keepalive SSH à 30s.
- `ssh_list_servers` reste utilisable sans paramiko et tolère un `servers.json` incomplet.

## [4.0.0] - 2026-05-31

### 🚀 Major Features

#### Smart Connection Mode
- **`ssh_connect` now accepts just an alias** to load credentials from `servers.json` automatically
- No need to provide `host`, `username`, `password` every time
- Example: `ssh_connect(alias='vps')` instead of providing all parameters
- Fixes Claude Code integration issues where it couldn't figure out how to use the tool

#### Rate Limiting
- Added 100ms minimum interval between network commands
- Prevents device saturation and CPU overload on switches/routers
- Protects against anti-DoS mechanisms on network equipment

### 🔒 Security Improvements

- **Timeout handling**: Now raises `TimeoutError` instead of silently returning incomplete buffers
  - Critical fix: prevents saving truncated configs that could cause outages during restore
  - Affects `read_until_prompt` in network device operations

### 🛠️ Code Quality

- **Magic numbers eliminated**: `width=220, height=50` replaced with named constants
  - `DEFAULT_SHELL_WIDTH = 220`
  - `DEFAULT_SHELL_HEIGHT = 50`
- Better error messages with actionable hints
- Improved logging for timeout events

### 📚 Documentation

- New `CLAUDE_CODE_USAGE.md` with complete usage examples
- Updated `README.md` with quick start guide
- Added examples for all device types (Cisco, MikroTik, FortiGate, Juniper)
- Pre-mortem analysis and risk assessment included

### 🧪 Testing

- All existing tests pass (secret migration, autoconnect)
- Rate limiter tested in production scenarios
- Timeout handling verified

### ⚠️ Breaking Changes

- `ssh_connect` now requires only `alias` (was: `alias`, `host`, `username`)
- Timeout errors now raise exceptions instead of returning partial data
- This is a **good** breaking change for safety

---

## [3.0.0] - Previous Release

### Features
- 18 MCP tools for SSH management
- Support for Linux/Unix and network devices
- Secure credential storage via Windows Credential Manager
- SFTP support
- SSH tunnels
- Config backup/restore/diff for network devices

### Security
- Secrets moved to Windows Credential Manager
- Automatic migration of plaintext credentials
- Strict host key verification by default
- Per-connection locking for thread safety

---

## Migration Guide: 3.0 → 4.0

### For Users

**Before (v3.0):**
```python
ssh_connect(
    alias='vps',
    host='192.168.10.1',
    username='sassogba',
    password='secret'
)
```

**After (v4.0):**
```python
# First time: save the server
ssh_save_server(
    alias='vps',
    host='192.168.10.1',
    username='sassogba',
    password='secret',
    auto_connect=True
)

# Every time after: just use the alias
ssh_connect(alias='vps')
```

### For Developers

**Timeout handling:**
```python
# Before: returned incomplete buffer silently
buf = read_until_prompt(...)  # Could be truncated

# After: raises exception
try:
    buf = read_until_prompt(...)
except TimeoutError as e:
    log.error(f"Timeout: {e}")
    # Handle properly
```

**Rate limiting:**
- Network commands now have automatic 100ms spacing
- No code changes needed, it's transparent
- Configurable via `self._min_cmd_interval` if needed

---

## Roadmap

### v4.1 (Next)
- [ ] Jump host / bastion support (`proxy_jump` parameter)
- [ ] Configurable `max_total_timeout` per device type
- [ ] Log rotation (RotatingFileHandler)
- [ ] Cross-platform keyring fallback (for non-Windows)

### v4.2 (Future)
- [ ] Integration tests with GNS3/EVE-NG
- [ ] Support for FIDO2/U2F SSH keys
- [ ] Async tunnels (trio/anyio) for better performance
- [ ] Prometheus metrics export

### v5.0 (Long-term)
- [ ] Multi-hop SSH (PC → bastion → device)
- [ ] Session recording and playback
- [ ] Ansible-style inventory support
- [ ] Web UI for connection management

---

## Known Issues

### Non-Critical
- Windows Credential Manager corruption (rare) has no fallback
  - Workaround: Re-save servers with `ssh_save_server`
- Very long device outputs (>10MB) may cause memory issues
  - Workaround: Use `ssh_download` to fetch large files instead

### Won't Fix
- Paramiko doesn't support FIDO2/U2F keys (upstream limitation)
- Interactive commands (like `top`, `vim`) not supported (MCP design limitation)

---

## Contributors

- Initial implementation: Stéphane A.
- Security review: Claude (Opus 4.7)
- Testing: Production NetOps team

---

## License

MIT License - See LICENSE file for details
