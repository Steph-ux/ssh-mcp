"""
SSH MCP Server v4.2.1 — Full NetOps Assistant
=============================================
Supporte : Linux/Unix, Cisco IOS/IOS-XE/XR, MikroTik RouterOS,
           FortiGate FortiOS, Juniper JunOS + tout device SSH générique.

18 outils :
  ssh_connect        ssh_disconnect     ssh_list          ssh_list_servers
  ssh_save_server    ssh_remove_server  ssh_exec          ssh_exec_sudo
  ssh_exec_network   ssh_push_config    ssh_backup_config ssh_restore_config
  ssh_diff_config    ssh_upload         ssh_download      ssh_list_remote
  ssh_tunnel         ssh_close_tunnel
"""
import asyncio
import difflib
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("ssh-mcp")

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from secret_store import SecretStore

try:
    from ssh_manager import get_ssh_pool, DEVICE_PROFILES, strip_config_noise
    _SSH_OK = True
except ImportError as e:
    _SSH_OK = False
    log.error(f"ERREUR {e}")
    DEVICE_PROFILES = {}
    def get_ssh_pool(): raise RuntimeError("pip install paramiko mcp")
    def strip_config_noise(text): return [l for l in text.splitlines() if l.strip()]

# ═══════════════════════════════════════════
# CONFIG PERSISTANTE
# ═══════════════════════════════════════════

SERVERS_FILE  = Path(__file__).parent / "servers.json"
BACKUPS_DIR   = Path(__file__).parent / "backups"
BACKUPS_DIR.mkdir(exist_ok=True)
SECRET_STORE  = SecretStore()
SECRET_FIELDS = ("password", "key_passphrase")

def _write_backup(alias: str, config: str, suffix: str = "") -> Path:
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    alias_dir = BACKUPS_DIR / alias
    alias_dir.mkdir(parents=True, exist_ok=True)
    tag = f"_{suffix}" if suffix else ""
    path = alias_dir / f"{alias}_{ts}{tag}.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write(config)
    return path

def _auth_label(cfg: dict) -> str:
    if cfg.get("key_path"):
        if cfg.get("key_passphrase_stored"):
            return f"key: {cfg['key_path']} (+ secure passphrase)"
        return f"key: {cfg['key_path']}"
    if cfg.get("password_stored"):
        return "secure password"
    return "agent/system key"

def _normalize_server_entry(alias: str, cfg: dict) -> tuple[dict, bool]:
    normalized = dict(cfg)
    changed = False

    if normalized.get("host_key_policy") not in ("strict", "auto_add"):
        normalized["host_key_policy"] = "strict"
        changed = True

    auto_connect = bool(normalized.get("auto_connect", False))
    if normalized.get("auto_connect") != auto_connect:
        normalized["auto_connect"] = auto_connect
        changed = True

    for field in SECRET_FIELDS:
        flag = f"{field}_stored"
        if normalized.get(field):
            SECRET_STORE.set_secret(alias, field, normalized.pop(field))
            normalized[flag] = True
            changed = True
        elif flag not in normalized:
            normalized[flag] = False
            changed = True

    return normalized, changed

def _resolve_server_entry(alias: str, cfg: dict) -> dict:
    resolved = dict(cfg)
    for field in SECRET_FIELDS:
        if resolved.get(f"{field}_stored"):
            secret_value = SECRET_STORE.get_secret(alias, field)
            if secret_value is None:
                raise RuntimeError(
                    f"Secret missing in Credential Manager for {alias}:{field}"
                )
            resolved[field] = secret_value
    return resolved

_SERVERS_LOCK = threading.Lock()


def load_servers() -> dict:
    if not SERVERS_FILE.exists(): return {}
    try:
        with _SERVERS_LOCK:
            with open(SERVERS_FILE, "r", encoding="utf-8") as f:
                raw_servers = json.load(f)
    except Exception as e:
        log.warning(f"servers.json illisible : {e}"); return {}
    servers = {}
    changed = False
    for alias, cfg in raw_servers.items():
        normalized, entry_changed = _normalize_server_entry(alias, cfg)
        servers[alias] = normalized
        changed = changed or entry_changed
    if changed:
        save_servers(servers)
    return servers


def save_servers(servers: dict):
    """Écriture atomique : tmp + os.replace élimine le JSON corrompu si le
    process meurt mid-write. Le lock sérialise les saves concurrents."""
    with _SERVERS_LOCK:
        tmp = SERVERS_FILE.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(servers, f, indent=2, ensure_ascii=False)
        os.replace(tmp, SERVERS_FILE)

DEVICE_TYPES = list(DEVICE_PROFILES.keys()) if DEVICE_PROFILES else \
               ["generic", "cisco", "cisco_xr", "mikrotik", "fortigate", "juniper"]

# ═══════════════════════════════════════════
# OUTILS (18)
# ═══════════════════════════════════════════

TOOLS = [

    # ── Gestion connexions ───────────────────────────────────────

    Tool(name="ssh_connect",
         description=(
             "Établit une connexion SSH persistante. Deux modes d'utilisation :\n"
             "1. CONNEXION RAPIDE (recommandé) : Fournir uniquement 'alias' d'un serveur déjà sauvegardé - charge automatiquement host, username, credentials depuis servers.json\n"
             "2. CONNEXION COMPLÈTE : Fournir alias + host + username + (password OU key_path)\n"
             "Auth par mot de passe ou clé privée (RSA, Ed25519, ECDSA). Pool de sessions nommées — la connexion reste active entre les appels.\n"
             "Exemples : ssh_connect(alias='vps') OU ssh_connect(alias='new-server', host='10.0.0.1', username='root', password='...')"
         ),
         inputSchema={"type": "object", "properties": {
             "alias":          {"type": "string",  "description": "Nom court (ex: 'vps', 'cisco-core', 'mikrotik-gw'). Si le serveur existe dans servers.json, les autres paramètres sont optionnels."},
             "host":           {"type": "string",  "description": "IP ou hostname (optionnel si alias existe dans servers.json)"},
             "username":       {"type": "string",  "description": "Utilisateur SSH (optionnel si alias existe dans servers.json)"},
             "password":       {"type": "string",  "description": "Mot de passe SSH"},
             "key_path":       {"type": "string",  "description": "Chemin clé privée (ex: 'C:\\\\Users\\\\...\\\\id_ed25519')"},
             "key_passphrase": {"type": "string",  "description": "Passphrase clé privée"},
             "known_hosts_path":{"type": "string", "description": "Chemin known_hosts optionnel"},
             "port":           {"type": "integer", "default": 22},
             "timeout":        {"type": "integer", "default": 15},
             "host_key_policy":{"type": "string", "enum": ["strict", "auto_add"], "default": "strict"},
         }, "required": ["alias"]}),

    Tool(name="ssh_disconnect",
         description="Ferme proprement une connexion SSH et tous ses tunnels.",
         inputSchema={"type": "object", "properties": {
             "alias": {"type": "string"},
         }, "required": ["alias"]}),

    Tool(name="ssh_list",
         description="Liste toutes les connexions SSH actives avec statut, uptime et tunnels ouverts.",
         inputSchema={"type": "object", "properties": {}}),

    # ── Config persistante ───────────────────────────────────────

    Tool(name="ssh_save_server",
         description="Sauvegarde un serveur dans servers.json sans y stocker les secrets en clair. Sur un alias existant, seuls les champs fournis sont modifiés (les autres sont conservés).",
         inputSchema={"type": "object", "properties": {
             "alias":          {"type": "string"},
             "host":           {"type": "string"},
             "username":       {"type": "string"},
             "password":       {"type": "string"},
             "key_path":       {"type": "string"},
             "key_passphrase": {"type": "string"},
             "known_hosts_path":{"type": "string"},
             "port":           {"type": "integer", "default": 22},
             "timeout":        {"type": "integer", "default": 15},
             "host_key_policy":{"type": "string", "enum": ["strict", "auto_add"], "default": "strict"},
             "auto_connect":   {"type": "boolean", "default": False},
             "device_type":    {"type": "string",  "description": f"Type de device : {', '.join(DEVICE_TYPES)}. Défaut: generic", "default": "generic"},
         }, "required": ["alias"]}),

    Tool(name="ssh_remove_server",
         description="Supprime un serveur de servers.json.",
         inputSchema={"type": "object", "properties": {
             "alias": {"type": "string"},
         }, "required": ["alias"]}),

    Tool(name="ssh_list_servers",
         description="Liste tous les serveurs sauvegardés dans servers.json avec leur statut (connecté/non connecté).",
         inputSchema={"type": "object", "properties": {}}),

    # ── Exécution Linux/Unix ─────────────────────────────────────

    Tool(name="ssh_exec",
         description="Exécute une commande shell sur un serveur Linux/Unix. Reconnexion automatique si la session expire.",
         inputSchema={"type": "object", "properties": {
             "alias":   {"type": "string"},
             "command": {"type": "string"},
             "timeout": {"type": "integer", "default": 30},
             "pty":     {"type": "boolean",  "default": False},
         }, "required": ["alias", "command"]}),

    Tool(name="ssh_exec_sudo",
         description="Exécute une commande avec sudo (injection mot de passe automatique).",
         inputSchema={"type": "object", "properties": {
             "alias":         {"type": "string"},
             "command":       {"type": "string", "description": "Commande sans 'sudo' devant"},
             "sudo_password": {"type": "string"},
             "timeout":       {"type": "integer", "default": 30},
         }, "required": ["alias", "command", "sudo_password"]}),

    # ── Exécution équipements réseau ─────────────────────────────

    Tool(name="ssh_exec_network",
         description=(
             "Exécute une liste de commandes sur un équipement réseau via shell interactif (invoke_shell). "
             "Gère automatiquement : pagination (--More--), mode enable (Cisco), prompts. "
             f"device_type : {', '.join(DEVICE_TYPES)}. "
             "Exemple Cisco : ['show version', 'show ip interface brief']. "
             "Exemple MikroTik : ['/ip address print', '/interface print']. "
             "Exemple FortiGate : ['get system status', 'show system interface']."
         ),
         inputSchema={"type": "object", "properties": {
              "alias":           {"type": "string"},
              "commands":        {"type": "array", "items": {"type": "string"}, "description": "Liste de commandes à envoyer en séquence"},
              "device_type":     {"type": "string", "default": "generic", "description": f"Type : {', '.join(DEVICE_TYPES)}"},
              "enable_password": {"type": "string", "description": "Mot de passe enable (Cisco uniquement)"},
              "config_mode":     {"type": "boolean", "default": False, "description": "Entrer en mode configuration avant les commandes"},
              "save_config":     {"type": "boolean", "default": False, "description": "Sauvegarder la config après (write memory / commit)"},
              "timeout":         {"type": "integer", "default": 30},
              "inter_cmd_delay": {"type": "number",  "default": 0.3, "description": "Délai entre chaque commande en secondes"},
              "max_total_timeout": {"type": "integer", "default": 120, "description": "Budget temps total pour tout le batch (secondes)"},
          }, "required": ["alias", "commands"]}),

    Tool(name="ssh_push_config",
         description=(
             "Déploie un bloc de configuration complet sur un équipement réseau. "
             "Envoie chaque ligne en séquence en mode config, vérifie les erreurs, sauvegarde si demandé. "
             "Idéal pour : configurer des interfaces, des routes, des VLANs, des ACLs, des politiques firewall, etc. "
             "Le paramètre 'config' peut être un texte multiligne — chaque ligne sera une commande."
         ),
         inputSchema={"type": "object", "properties": {
             "alias":           {"type": "string"},
             "config":          {"type": "string", "description": "Bloc de configuration (une commande par ligne)"},
             "device_type":     {"type": "string", "default": "generic"},
             "enable_password": {"type": "string"},
             "save_config":     {"type": "boolean", "default": True,  "description": "Sauvegarder après déploiement"},
             "backup_first":    {"type": "boolean", "default": True,  "description": "Backup automatique avant le push (point de rollback)"},
             "timeout":         {"type": "integer", "default": 60},
             "inter_cmd_delay": {"type": "number",  "default": 0.3},
         }, "required": ["alias", "config"]}),

    Tool(name="ssh_backup_config",
         description=(
             "Sauvegarde la configuration courante (running-config) dans un fichier local horodaté. "
             "Cisco : 'show running-config'. MikroTik : '/export compact'. "
             "FortiGate : 'show full-configuration'. Juniper : 'show configuration'. "
             "Fichier sauvegardé dans backups/<alias>/<alias>_YYYY-MM-DD_HH-MM-SS.txt"
         ),
         inputSchema={"type": "object", "properties": {
             "alias":       {"type": "string"},
             "device_type": {"type": "string", "default": "generic"},
             "timeout":     {"type": "integer", "default": 60},
         }, "required": ["alias"]}),

    Tool(name="ssh_restore_config",
         description=(
             "Restaure une configuration depuis un fichier de backup. "
             "Par défaut en DRY-RUN : affiche les commandes qui seraient envoyées sans rien exécuter. "
             "Passer confirm=true pour exécuter réellement. "
             "ATTENTION : peut remplacer la config existante."
         ),
         inputSchema={"type": "object", "properties": {
             "alias":           {"type": "string"},
             "backup_file":     {"type": "string", "description": "Chemin du fichier de backup à restaurer"},
             "device_type":     {"type": "string", "default": "generic"},
             "enable_password": {"type": "string"},
             "save_config":     {"type": "boolean", "default": True},
             "confirm":         {"type": "boolean", "default": False, "description": "false = dry-run (défaut). true = exécution réelle."},
             "timeout":         {"type": "integer", "default": 120},
         }, "required": ["alias", "backup_file"]}),

    Tool(name="ssh_diff_config",
         description=(
             "Compare deux configurations et affiche les différences (style git diff). "
             "Utilisation : comparer la config actuelle vs un backup, ou deux backups entre eux. "
             "Si backup_file_b est omis, compare avec la config actuelle du device."
         ),
         inputSchema={"type": "object", "properties": {
             "alias":         {"type": "string"},
             "backup_file_a": {"type": "string", "description": "Premier fichier de config"},
             "backup_file_b": {"type": "string", "description": "Deuxième fichier (optionnel — sinon config actuelle du device)"},
             "device_type":   {"type": "string", "default": "generic"},
             "timeout":       {"type": "integer", "default": 60},
         }, "required": ["alias", "backup_file_a"]}),

    # ── SFTP ─────────────────────────────────────────────────────

    Tool(name="ssh_upload",
         description="Envoie un fichier local vers le serveur via SFTP.",
         inputSchema={"type": "object", "properties": {
             "alias":       {"type": "string"},
             "local_path":  {"type": "string"},
             "remote_path": {"type": "string"},
         }, "required": ["alias", "local_path", "remote_path"]}),

    Tool(name="ssh_download",
         description="Télécharge un fichier du serveur vers le PC local via SFTP.",
         inputSchema={"type": "object", "properties": {
             "alias":       {"type": "string"},
             "remote_path": {"type": "string"},
             "local_path":  {"type": "string"},
         }, "required": ["alias", "remote_path", "local_path"]}),

    Tool(name="ssh_list_remote",
         description="Liste les fichiers d'un dossier distant via SFTP.",
         inputSchema={"type": "object", "properties": {
             "alias": {"type": "string"},
             "path":  {"type": "string", "default": "."},
         }, "required": ["alias"]}),

    # ── Tunnels ──────────────────────────────────────────────────

    Tool(name="ssh_tunnel",
         description="Crée un tunnel TCP local-distant via SSH (port forwarding). Ex: accès DB interne sur localhost:3307.",
         inputSchema={"type": "object", "properties": {
             "alias":       {"type": "string"},
             "label":       {"type": "string", "description": "Nom du tunnel (ex: 'mysql', 'redis')"},
             "local_port":  {"type": "integer"},
             "remote_host": {"type": "string"},
             "remote_port": {"type": "integer"},
         }, "required": ["alias", "label", "local_port", "remote_host", "remote_port"]}),

    Tool(name="ssh_close_tunnel",
         description="Ferme un tunnel SSH par son label.",
         inputSchema={"type": "object", "properties": {
             "alias": {"type": "string"},
             "label": {"type": "string"},
         }, "required": ["alias", "label"]}),
]

# ═══════════════════════════════════════════
# HANDLERS
# ═══════════════════════════════════════════

async def handle(name: str, args: dict) -> str:
    # Le pool n'est instancie que pour les outils qui en ont besoin : sans
    # paramiko, ssh_list_servers doit rester utilisable.
    if name in ("ssh_list_servers", "ssh_save_server", "ssh_remove_server"):
        pool = None
    else:
        pool = get_ssh_pool()

    # ── Connexions ───────────────────────────────────────────────

    if name == "ssh_connect":
        alias = args.get("alias")
        if not alias:
            return "ERREUR : 'alias' est requis"
        servers = load_servers()
        saved_cfg = servers.get(alias)

        # Fusion : les arguments explicites surchargent la config sauvegardée,
        # sans perdre les credentials du Credential Manager.
        if saved_cfg is not None:
            try:
                cfg = _resolve_server_entry(alias, saved_cfg)
            except RuntimeError as e:
                return f"ERREUR {e}"
        else:
            cfg = {}
        for field in ("host", "username", "password", "key_path", "key_passphrase",
                      "known_hosts_path", "port", "timeout", "host_key_policy"):
            if args.get(field) is not None:
                cfg[field] = args[field]

        if not cfg.get("host") or not cfg.get("username"):
            available = list(servers.keys()) if servers else []
            return (
                f"ERREUR : Pour une nouvelle connexion, 'host' et 'username' sont requis.\n"
                f"   Serveurs sauvegardés disponibles : {available or '(aucun)'}\n"
                f"   Usage : ssh_connect(alias='{alias}') pour un serveur sauvegardé\n"
                f"        OU ssh_connect(alias='{alias}', host='...', username='...', password='...')"
            )

        try:
            info = await pool.connect(
                alias=alias,
                host=cfg["host"],
                username=cfg["username"],
                password=cfg.get("password"),
                key_path=cfg.get("key_path"),
                key_passphrase=cfg.get("key_passphrase"),
                port=int(cfg.get("port", 22)),
                timeout=int(cfg.get("timeout", 15)),
                host_key_policy=cfg.get("host_key_policy", "strict"),
                known_hosts_path=cfg.get("known_hosts_path"),
            )
            if saved_cfg is not None:
                origin = " (depuis servers.json)"
                auth = _auth_label(saved_cfg)
                extra = f"   Device  : {saved_cfg.get('device_type', 'generic')}\n"
            else:
                origin = ""
                auth = f"clé: {cfg['key_path']}" if cfg.get("key_path") else "mot de passe de session"
                extra = f"   -> ssh_save_server(alias='{alias}', ...) pour le sauvegarder sans secret en clair\n"
            return (
                f"SSH connecté [{alias}]{origin}\n"
                f"   Hôte    : {cfg['username']}@{cfg['host']}:{cfg.get('port', 22)}\n"
                f"   Auth    : {auth}\n"
                f"{extra}"
                f"   HostKey : {cfg.get('host_key_policy', 'strict')}\n"
                f"   Info    : {info}"
            )
        except FileNotFoundError as e:
            return f"ERREUR {e}"
        except Exception as e:
            err = str(e)
            hint = ("\n-> pip install paramiko" if "paramiko" in err.lower()
                    else "\n-> Vérifie mot de passe / clé" if "authentication" in err.lower()
                    else "\n-> Ajoute la clé hôte à known_hosts ou utilise host_key_policy='auto_add' en labo" if "known hosts" in err.lower() or "host key" in err.lower()
                    else "\n-> Vérifie IP/port" if any(x in err.lower() for x in ("timed out", "refused"))
                    else "")
            return f"ERREUR Connexion [{alias}] : {err}{hint}"

    elif name == "ssh_disconnect":
        alias = args.get("alias")
        if not alias:
            return "ERREUR : 'alias' est requis"
        try:
            await pool.disconnect(alias)
            return f"[{alias}] déconnecté"
        except Exception as e: return f"ERREUR {e}"

    elif name == "ssh_list":
        statuses = pool.list_status()
        servers  = load_servers()
        if not statuses:
            saved = f" ({len(servers)} sauvegardé(s))" if servers else ""
            return f"Aucune connexion active{saved}.\n   -> ssh_connect(alias='...', host='...', username='...')"
        lines = [f"{len(statuses)} connexion(s) active(s) :"]
        for s in statuses: lines.append("  " + s)
        for alias in pool.list_aliases():
            try:
                tunnels = pool.get_tunnels(alias)
                if tunnels:
                    lines.append(f"  Tunnels [{alias}] :")
                    for t in tunnels:
                        lines.append(f"    [{'ALIVE' if t['alive'] else 'DOWN'}] [{t['label']}] "
                                     f"localhost:{t['local_port']} -> {t['remote']} ({t['uptime_s']}s)")
            except Exception: pass
        return "\n".join(lines)

    # ── Config persistante ───────────────────────────────────────

    elif name == "ssh_save_server":
        alias = args.get("alias")
        if not alias:
            return "ERREUR : 'alias' est requis"
        servers  = load_servers()
        is_update = alias in servers
        previous = servers.get(alias, {})

        # Merge : un ré-enregistrement partiel ne doit pas effacer key_path,
        # known_hosts_path ou device_type déjà connus.
        entry = dict(previous)
        for field in ("host", "username", "key_path", "known_hosts_path", "device_type"):
            if args.get(field):
                entry[field] = args[field]
        entry["port"] = int(args.get("port", previous.get("port", 22)))
        entry["timeout"] = int(args.get("timeout", previous.get("timeout", 15)))
        entry.setdefault("device_type", "generic")
        entry["host_key_policy"] = args.get("host_key_policy", previous.get("host_key_policy", "strict"))
        entry["auto_connect"] = bool(args["auto_connect"]) if "auto_connect" in args \
                                else bool(previous.get("auto_connect", False))
        entry.setdefault("password_stored", False)
        entry.setdefault("key_passphrase_stored", False)

        if not entry.get("host") or not entry.get("username"):
            return (
                f"ERREUR [{alias}] : 'host' et 'username' sont requis pour un nouveau serveur.\n"
                f"   Serveurs existants : {list(servers.keys()) or '(aucun)'}"
            )

        for field in SECRET_FIELDS:
            value = args.get(field)
            if value:
                SECRET_STORE.set_secret(alias, field, value)
                entry[f"{field}_stored"] = True
        servers[alias] = entry
        save_servers(servers)
        auth = _auth_label(entry)
        state = "mis a jour" if is_update else "ajoute"
        return (
            f"[{alias}] {state} dans servers.json\n"
            f"   {entry['username']}@{entry['host']}:{entry['port']} | {entry['device_type']} | auth: {auth}\n"
            f"   HostKey: {entry['host_key_policy']} | auto_connect: {entry['auto_connect']} | known_hosts: {entry.get('known_hosts_path', 'default')}\n"
            f"   -> Secrets stockes hors du JSON | Total : {len(servers)} serveur(s)"
        )

    elif name == "ssh_remove_server":
        alias = args.get("alias")
        if not alias:
            return "ERREUR : 'alias' est requis"
        servers = load_servers()
        if alias not in servers:
            return f"[{alias}] introuvable\nServeurs : {list(servers.keys()) or '(aucun)'}"
        del servers[alias]
        save_servers(servers)
        for field in SECRET_FIELDS: SECRET_STORE.delete_secret(alias, field)
        return f"[{alias}] supprime | Restants : {list(servers.keys()) or '(aucun)'}"

    elif name == "ssh_list_servers":
        servers = load_servers()
        if not servers:
            return "Aucun serveur sauvegarde.\n   -> ssh_save_server(alias='...')"
        try:
            actifs = get_ssh_pool().list_aliases()
        except Exception:
            actifs = []
        lines  = [f"{len(servers)} serveur(s) dans servers.json :"]
        for alias, cfg in servers.items():
            auth   = _auth_label(cfg)
            dtype  = cfg.get("device_type", "generic")
            status = "connecte" if alias in actifs else "non connecte"
            lines.append(
                f"  {status} [{alias}]  {cfg.get('username', '?')}@{cfg.get('host', '?')}:{cfg.get('port', 22)}"
                f"  |  {dtype}  |  {auth}  | hostkey={cfg.get('host_key_policy', 'strict')}"
                f"  | auto_connect={bool(cfg.get('auto_connect', False))}"
            )
        return "\n".join(lines)

    # ── Exec Linux ───────────────────────────────────────────────

    elif name == "ssh_exec":
        alias = args.get("alias")
        command = args.get("command")
        if not alias or not command:
            return "ERREUR : 'alias' et 'command' sont requis"
        try:
            r    = await pool.exec(alias, command,
                                   timeout=int(args.get("timeout",30)),
                                   get_pty=bool(args.get("pty",False)))
            icon = "OK" if r["exit_code"] == 0 else "ERR"
            lines = [f"{icon} [{alias}] $ {command}  |  exit={r['exit_code']}  |  {r['elapsed']}s"]
            if r["stdout"].rstrip(): lines.append(r["stdout"].rstrip())
            if r["stderr"].rstrip() and r["exit_code"] != 0: lines.append(f"[stderr]\n{r['stderr'].rstrip()}")
            return "\n".join(lines)
        except KeyError as e: return f"ERREUR {e}"
        except Exception as e: return f"ERREUR {e}"

    elif name == "ssh_exec_sudo":
        alias = args.get("alias")
        command = args.get("command")
        sudo_password = args.get("sudo_password")
        if not alias or not command or not sudo_password:
            return "ERREUR : 'alias', 'command' et 'sudo_password' sont requis"
        try:
            r    = await pool.exec_sudo(alias, command, sudo_password,
                                        timeout=int(args.get("timeout",30)))
            icon = "OK" if r["exit_code"] == 0 else "ERR"
            lines = [f"{icon} [{alias}] sudo {command}  |  exit={r['exit_code']}  |  {r['elapsed']}s"]
            if r["stdout"].rstrip(): lines.append(r["stdout"].rstrip())
            if r["stderr"].rstrip() and r["exit_code"] != 0: lines.append(f"[stderr]\n{r['stderr'].rstrip()}")
            return "\n".join(lines)
        except KeyError as e: return f"ERREUR {e}"
        except Exception as e: return f"ERREUR {e}"

    # ── Exec Network ─────────────────────────────────────────────

    elif name == "ssh_exec_network":
        alias = args.get("alias")
        commands = args.get("commands")
        if not alias or not commands:
            return "ERREUR : 'alias' et 'commands' sont requis"
        try:
            r = await pool.exec_network(
                alias           = alias,
                commands        = commands,
                device_type     = args.get("device_type", "generic"),
                enable_password = args.get("enable_password"),
                config_mode     = bool(args.get("config_mode", False)),
                save_config     = bool(args.get("save_config", False)),
                timeout         = int(args.get("timeout", 30)),
                inter_cmd_delay = float(args.get("inter_cmd_delay", 0.3)),
                max_total_timeout = int(args.get("max_total_timeout", 120)),
            )
            status = "OK" if not r["errors"] else "WARN"
            lines  = [f"{status} [{alias}] {r['commands_sent']} commande(s) | {r['elapsed']}s"]
            if r["errors"]:
                lines.append("Erreurs détectées :")
                lines.extend(f"  {e}" for e in r["errors"])
            lines.append("─" * 60)
            lines.append(r["output"])
            return "\n".join(lines)
        except KeyError as e: return f"ERREUR {e}"
        except Exception as e: return f"ERREUR ssh_exec_network : {e}"

    elif name == "ssh_push_config":
        alias = args.get("alias")
        config = args.get("config")
        if not alias or config is None:
            return "ERREUR : 'alias' et 'config' sont requis"
        try:
            commands = strip_config_noise(config)
            if not commands:
                return "WARN Aucune commande à envoyer (config vide)"

            device_type = args.get("device_type", "generic")
            safety_note = ""
            if bool(args.get("backup_first", True)):
                try:
                    pre = await pool.backup_config(alias, device_type=device_type, timeout=60)
                    if pre["config"].strip():
                        path = _write_backup(alias, pre["config"], suffix="pre-push")
                        safety_note = f"   Backup avant push : {path}\n"
                    else:
                        safety_note = "   WARN Backup avant push vide - pas de point de restauration\n"
                except Exception as exc:
                    safety_note = f"   WARN Backup avant push impossible : {exc}\n"

            r = await pool.exec_network(
                alias           = alias,
                commands        = commands,
                device_type     = device_type,
                enable_password = args.get("enable_password"),
                config_mode     = True,
                save_config     = bool(args.get("save_config", True)),
                timeout         = int(args.get("timeout", 60)),
                inter_cmd_delay = float(args.get("inter_cmd_delay", 0.3)),
                max_total_timeout = int(args.get("max_total_timeout", 300)),
            )
            status = "OK" if not r["errors"] else "WARN"
            lines  = [f"{status} [{alias}] Config poussée : {r['commands_sent']} commande(s) | {r['elapsed']}s"]
            if safety_note:
                lines.append(safety_note.rstrip())
            if r["errors"]:
                lines.append("WARN Erreurs :")
                lines.extend(f"  {e}" for e in r["errors"])
                if safety_note.startswith("   Backup"):
                    lines.append("   -> Rollback possible : ssh_restore_config(alias='%s', backup_file='...', confirm=true)" % alias)
            else:
                lines.append("OK Aucune erreur détectée")
            lines.append("─" * 60)
            lines.append(r["output"])
            return "\n".join(lines)
        except KeyError as e: return f"ERREUR {e}"
        except Exception as e: return f"ERREUR ssh_push_config : {e}"

    elif name == "ssh_backup_config":
        alias = args.get("alias")
        if not alias:
            return "ERREUR : 'alias' est requis"
        try:
            device_type = args.get("device_type", "generic")
            r = await pool.backup_config(alias, device_type=device_type,
                                         timeout=int(args.get("timeout", 60)))
            if not r["ok"] and not r["config"].strip():
                return f"ERREUR Backup [{alias}] échoué :\n" + "\n".join(r["errors"])

            filepath = _write_backup(alias, r["config"])

            size = len(r["config"])
            lines_count = r["config"].count("\n")
            return (
                f"OK Backup [{alias}] sauvegardé\n"
                f"   Fichier : {filepath}\n"
                f"   Taille  : {size} octets | {lines_count} lignes\n"
                f"   Device  : {device_type} | {r['elapsed']}s\n"
                + (f"   WARN Warnings : {'; '.join(r['errors'])}" if r["errors"] else "")
            )
        except KeyError as e: return f"ERREUR {e}"
        except Exception as e: return f"ERREUR ssh_backup_config : {e}"

    elif name == "ssh_restore_config":
        alias       = args.get("alias")
        backup_file = args.get("backup_file")
        if not alias or not backup_file:
            return "ERREUR : 'alias' et 'backup_file' sont requis"
        if not os.path.exists(backup_file):
            return f"ERREUR Fichier introuvable : {backup_file}"
        try:
            with open(backup_file, "r", encoding="utf-8") as f:
                content = f.read()
            commands = strip_config_noise(content)
            if not commands:
                return f"WARN Fichier vide ou aucune commande exploitable : {backup_file}"

            if not bool(args.get("confirm", False)):
                preview = "\n".join(f"  {i+1:>4}: {c}" for i, c in enumerate(commands[:40]))
                more = f"\n  ... et {len(commands)-40} ligne(s) supplementaire(s)" if len(commands) > 40 else ""
                return (
                    f"DRY-RUN [{alias}] - AUCUNE commande envoyee\n"
                    f"   Fichier : {backup_file}\n"
                    f"   {len(commands)} commande(s) seraient poussees en mode configuration :\n"
                    f"{'─'*60}\n{preview}{more}\n{'─'*60}\n"
                    f"   -> Relance avec confirm=true pour executer reellement."
                )

            r = await pool.exec_network(
                alias           = alias,
                commands        = commands,
                device_type     = args.get("device_type", "generic"),
                enable_password = args.get("enable_password"),
                config_mode     = True,
                save_config     = bool(args.get("save_config", True)),
                timeout         = int(args.get("timeout", 120)),
                inter_cmd_delay = 0.5,
                max_total_timeout = int(args.get("max_total_timeout", 600)),
            )
            status = "OK" if not r["errors"] else "WARN"
            lines  = [
                f"{status} [{alias}] Restauration terminée",
                f"   Fichier : {backup_file}",
                f"   Commandes envoyées : {r['commands_sent']} | {r['elapsed']}s",
            ]
            if r["errors"]:
                lines.append("WARN Erreurs :")
                lines.extend(f"  {e}" for e in r["errors"])
            return "\n".join(lines)
        except KeyError as e: return f"ERREUR {e}"
        except Exception as e: return f"ERREUR ssh_restore_config : {e}"

    elif name == "ssh_diff_config":
        alias = args.get("alias")
        file_a = args.get("backup_file_a")
        if not alias or not file_a:
            return "ERREUR : 'alias' et 'backup_file_a' sont requis"
        if not os.path.exists(file_a):
            return f"ERREUR Fichier A introuvable : {file_a}"
        with open(file_a, "r", encoding="utf-8") as f:
            lines_a = f.read().splitlines()
        label_a = os.path.basename(file_a)

        if args.get("backup_file_b"):
            file_b = args["backup_file_b"]
            if not os.path.exists(file_b):
                return f"ERREUR Fichier B introuvable : {file_b}"
            with open(file_b, "r", encoding="utf-8") as f:
                lines_b = f.read().splitlines()
            label_b = os.path.basename(file_b)
        else:
            try:
                r = await pool.backup_config(alias,
                    device_type=args.get("device_type","generic"),
                    timeout=int(args.get("timeout",60)))
                lines_b = r["config"].splitlines()
                label_b = f"{alias} (config actuelle)"
            except Exception as e:
                return f"ERREUR Impossible de récupérer la config actuelle : {e}"

        diff = list(difflib.unified_diff(
            [l.rstrip("\n") for l in lines_a],
            [l.rstrip("\n") for l in lines_b],
            fromfile=label_a, tofile=label_b, lineterm=""))
        if not diff:
            return f"OK Aucune différence entre {label_a} et {label_b}"
        added   = sum(1 for l in diff if l.startswith("+") and not l.startswith("+++"))
        removed = sum(1 for l in diff if l.startswith("-") and not l.startswith("---"))
        result  = "\n".join(diff[:200])
        truncated = "\n[... diff tronqué — trop long ...]" if len(diff) > 200 else ""
        return (
            f"Diff [{label_a}] -> [{label_b}]\n"
            f"   +{added} lignes ajoutées | -{removed} lignes supprimées\n"
            f"{'─'*60}\n{result}{truncated}"
        )

    # ── SFTP ─────────────────────────────────────────────────────

    elif name == "ssh_upload":
        alias = args.get("alias")
        local_path = args.get("local_path")
        remote_path = args.get("remote_path")
        if not alias or not local_path or not remote_path:
            return "ERREUR : 'alias', 'local_path' et 'remote_path' sont requis"
        try:
            r = await pool.upload(alias, local_path, remote_path)
            if r["ok"]: return f"OK Upload [{alias}]\n   {local_path} -> {remote_path}\n   {r['size']//1024} KB"
            return f"ERREUR Upload échoué : {r['error']}"
        except Exception as e: return f"ERREUR {e}"

    elif name == "ssh_download":
        alias = args.get("alias")
        local_path = args.get("local_path")
        remote_path = args.get("remote_path")
        if not alias or not local_path or not remote_path:
            return "ERREUR : 'alias', 'local_path' et 'remote_path' sont requis"
        try:
            r = await pool.download(alias, remote_path, local_path)
            if r["ok"]: return f"OK Download [{alias}]\n   {remote_path} -> {local_path}\n   {r['size']//1024} KB"
            return f"ERREUR Download échoué : {r['error']}"
        except Exception as e: return f"ERREUR {e}"

    elif name == "ssh_list_remote":
        alias = args.get("alias")
        if not alias:
            return "ERREUR : 'alias' est requis"
        try:
            items = await pool.list_remote(alias, args.get("path", "."))
            if not items: return f"[{alias}] {args.get('path','.')} - vide"
            lines = [f"[{alias}] {args.get('path','.')} ({len(items)} entrée(s)) :"]
            for it in items:
                icon = "[DIR]" if it["type"]=="dir" else "[FILE]"
                size = f"({it['size']//1024} KB)" if it["type"]=="file" and it["size"]>=1024 else f"({it['size']} B)" if it["type"]=="file" else ""
                lines.append(f"  {icon} {it['name']:<40} {size}  {it['mtime']}")
            return "\n".join(lines)
        except Exception as e: return f"ERREUR {e}"

    # ── Tunnels ──────────────────────────────────────────────────

    elif name == "ssh_tunnel":
        alias = args.get("alias")
        label = args.get("label")
        local_port = args.get("local_port")
        remote_host = args.get("remote_host")
        remote_port = args.get("remote_port")
        if not (alias and label and local_port and remote_host and remote_port):
            return "ERREUR : 'alias', 'label', 'local_port', 'remote_host' et 'remote_port' sont requis"
        try:
            r = await pool.start_tunnel(alias, label,
                int(local_port), remote_host, int(remote_port))
            if r["ok"]:
                return (f"OK Tunnel [{alias}:{label}]\n"
                        f"   localhost:{local_port} -> {remote_host}:{remote_port}\n"
                        f"   -> Ferme avec ssh_close_tunnel(alias='{alias}', label='{label}')")
            return f"ERREUR Tunnel échoué : {r['error']}"
        except Exception as e: return f"ERREUR {e}"

    elif name == "ssh_close_tunnel":
        alias = args.get("alias")
        label = args.get("label")
        if not alias or not label:
            return "ERREUR : 'alias' et 'label' sont requis"
        try:
            ok = await pool.stop_tunnel(alias, label)
            return f"OK Tunnel [{label}] fermé" if ok else f"WARN Tunnel [{label}] introuvable"
        except Exception as e: return f"ERREUR {e}"

    return f"ERREUR Outil inconnu : {name}"


# ═══════════════════════════════════════════
# AUTO-CONNEXION AU DÉMARRAGE
# ═══════════════════════════════════════════

async def autoconnect():
    servers = load_servers()
    if not servers:
        log.info("Aucun serveur dans servers.json")
        return
    auto_servers = {alias: cfg for alias, cfg in servers.items() if cfg.get("auto_connect", False)}
    if not auto_servers:
        log.info("Aucun serveur marque pour auto-connexion")
        return
    log.info(f"Auto-connexion de {len(auto_servers)} serveur(s)...")
    p = get_ssh_pool()
    for alias, cfg in auto_servers.items():
        try:
            resolved = _resolve_server_entry(alias, cfg)
            info = await p.connect(
                alias=alias, host=resolved["host"], username=resolved["username"],
                password=resolved.get("password"), key_path=resolved.get("key_path"),
                key_passphrase=resolved.get("key_passphrase"),
                known_hosts_path=resolved.get("known_hosts_path"),
                port=int(resolved.get("port",22)), timeout=int(resolved.get("timeout",15)),
                host_key_policy=resolved.get("host_key_policy", "strict"),
            )
            log.info(f"  OK [{alias}] {resolved['username']}@{resolved['host']} - {info}")
        except Exception as e:
            log.warning(f"  ERROR [{alias}] {cfg.get('username','?')}@{cfg.get('host','?')} - {e}")


# ═══════════════════════════════════════════
# MCP SERVER
# ═══════════════════════════════════════════

server = Server("ssh-mcp")

@server.list_tools()
async def list_tools() -> list[Tool]: return TOOLS

@server.call_tool()
async def call_tool(name: str, arguments: dict | None = None) -> list[TextContent]:
    log.info(f"-> {name}")
    try:
        result = await handle(name, arguments or {})
    except Exception as e:
        result = f"ERREUR Erreur inattendue '{name}' : {e}"
    if result is None:
        result = ""
    elif not isinstance(result, str):
        result = str(result)
    return [TextContent(type="text", text=result)]

async def main():
    log.info(f"SSH MCP Server v4.2.1 | {len(TOOLS)} outils | Paramiko: {'OK' if _SSH_OK else 'ERROR'}")
    log.info(f"Devices supportes : {', '.join(DEVICE_TYPES)}")
    log.info(f"Backups : {BACKUPS_DIR}")
    # Reference conservee : sans elle la task peut etre collectee par le GC.
    autoconnect_task = asyncio.create_task(autoconnect())
    autoconnect_task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())



