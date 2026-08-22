"""
SSH MCP Server v5.0.0 — Unified NetOps & Pentest Suite
======================================================
Supporte : Linux/Unix, Cisco IOS/IOS-XE/XR, MikroTik RouterOS,
           FortiGate FortiOS, Juniper JunOS + tout device SSH générique.

7 outils unifiés (100% de parité, économie ~70% de tokens de prompt) :
  1. ssh_session   : Connexions persistantes, déconnexion, status du pool (jump hosts, keepalive, compression)
  2. ssh_server    : Gestion de l'inventaire servers.json (save, remove, list)
  3. ssh_exec      : Exécution shell unifiée (standard, sudo sécurisé, background jobs)
  4. ssh_job       : Supervision des jobs en tâche de fond (status, tail, kill)
  5. ssh_sftp      : Transferts de fichiers & répertoires (upload, download, upload_dir, download_dir, list)
  6. ssh_network   : Automatisation réseau (exec interactif, push config, backup, restore dry-run/réel, diff)
  7. ssh_tunnel    : Tunnels TCP port-forwarding et proxies dynamiques SOCKS5
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
# 7 OUTILS UNIFIÉS
# ═══════════════════════════════════════════

TOOLS = [

    # ── 1. Sessions SSH ──────────────────────────────────────────
    Tool(
        name="ssh_session",
        description=(
            "Gère les sessions SSH persistantes dans le pool.\n"
            "- action='connect' : Établit ou réutilise une connexion persistante. Mode rapide : fournir uniquement 'alias' pour charger les paramètres depuis servers.json. Mode complet : alias + host + username + credentials. Supporte jump_alias (bastion), compression zlib et keepalive.\n"
            "- action='disconnect' : Ferme proprement la connexion et libère tunnels, SOCKS et jobs.\n"
            "- action='list' : Liste toutes les connexions actives, uptime, tunnels, proxies SOCKS5 et jobs en cours."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "action":             {"type": "string", "enum": ["connect", "disconnect", "list"], "default": "connect", "description": "Opération à effectuer (défaut: connect)"},
                "alias":              {"type": "string", "description": "Nom court du serveur (ex: 'vps', 'cisco-core', 'target'). Requis pour connect et disconnect."},
                "host":               {"type": "string", "description": "IP ou hostname (optionnel si alias existe dans servers.json)"},
                "username":           {"type": "string", "description": "Utilisateur SSH (optionnel si alias existe dans servers.json)"},
                "password":           {"type": "string", "description": "Mot de passe SSH"},
                "key_path":           {"type": "string", "description": "Chemin clé privée (ex: 'C:\\\\Users\\\\...\\\\id_ed25519')"},
                "key_passphrase":     {"type": "string", "description": "Passphrase clé privée"},
                "known_hosts_path":   {"type": "string", "description": "Chemin known_hosts optionnel"},
                "port":               {"type": "integer", "default": 22},
                "timeout":            {"type": "integer", "default": 15},
                "host_key_policy":    {"type": "string", "enum": ["strict", "auto_add"], "default": "strict"},
                "jump_alias":         {"type": "string", "description": "Alias du jump host / bastion dans le pool pour rebondir vers ce serveur"},
                "compress":           {"type": "boolean", "default": True, "description": "Active la compression zlib sur le transport SSH"},
                "keepalive_interval": {"type": "integer", "default": 30, "description": "Intervalle de keepalive en secondes (0 pour désactiver)"},
            },
        },
    ),

    # ── 2. Inventaire Serveurs ───────────────────────────────────
    Tool(
        name="ssh_server",
        description=(
            "Gère l'inventaire persistant des serveurs dans servers.json (secrets stockés de manière sécurisée hors du JSON).\n"
            "- action='save' : Ajoute ou modifie un serveur. Sur un alias existant, fusionne les champs fournis sans effacer les autres.\n"
            "- action='remove' : Supprime un serveur de servers.json et ses secrets associés.\n"
            "- action='list' : Liste tous les serveurs enregistrés avec leur statut (connecté/non connecté)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "action":             {"type": "string", "enum": ["save", "remove", "list"], "default": "save", "description": "Opération sur l'inventaire (défaut: save)"},
                "alias":              {"type": "string", "description": "Nom court du serveur (requis pour save et remove)"},
                "host":               {"type": "string"},
                "username":           {"type": "string"},
                "password":           {"type": "string"},
                "key_path":           {"type": "string"},
                "key_passphrase":     {"type": "string"},
                "known_hosts_path":   {"type": "string"},
                "port":               {"type": "integer", "default": 22},
                "timeout":            {"type": "integer", "default": 15},
                "host_key_policy":    {"type": "string", "enum": ["strict", "auto_add"], "default": "strict"},
                "auto_connect":       {"type": "boolean", "default": False},
                "device_type":        {"type": "string", "description": f"Type de device : {', '.join(DEVICE_TYPES)}. Défaut: generic", "default": "generic"},
                "jump_alias":         {"type": "string", "description": "Alias du bastion / jump host dans servers.json"},
                "compress":           {"type": "boolean", "default": True},
                "keepalive_interval": {"type": "integer", "default": 30},
            },
        },
    ),

    # ── 3. Exécution Shell Unifiée ───────────────────────────────
    Tool(
        name="ssh_exec",
        description=(
            "Exécute des commandes shell sur un serveur Linux/Unix.\n"
            "- Mode standard : exécution synchrone avec capture stdout/stderr.\n"
            "- Mode sudo : injection automatique sécurisée du mot de passe avec masquage ('***').\n"
            "- Mode background (background=true) : lance la commande en tâche de fond et retourne un job_id pour supervision via ssh_job."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "alias":         {"type": "string", "description": "Nom du serveur connecté"},
                "command":       {"type": "string", "description": "Commande shell à exécuter"},
                "sudo_password": {"type": "string", "description": "Mot de passe sudo pour exécuter via sudo -S (optionnel)"},
                "background":    {"type": "boolean", "default": False, "description": "Si true, exécute en tâche de fond et retourne un job_id"},
                "label":         {"type": "string", "description": "Libellé optionnel du job (mode background)"},
                "timeout":       {"type": "integer", "default": 30, "description": "Timeout en secondes"},
                "pty":           {"type": "boolean", "default": False, "description": "Alloue un pseudo-terminal PTY"},
            },
            "required": ["alias", "command"],
        },
    ),

    # ── 4. Gestion des Background Jobs ───────────────────────────
    Tool(
        name="ssh_job",
        description=(
            "Supervise et contrôle les tâches exécutées en arrière-plan.\n"
            "- action='status' : Affiche l'état d'un job spécifique ou la liste de tous les jobs de la session.\n"
            "- action='tail' : Affiche les dernières lignes de sortie (stdout/stderr) en temps réel.\n"
            "- action='kill' : Interrompt / tue un job en cours d'exécution."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "action":  {"type": "string", "enum": ["status", "tail", "kill"], "default": "status", "description": "Opération sur les jobs (défaut: status)"},
                "alias":   {"type": "string", "description": "Nom du serveur connecté"},
                "job_id":  {"type": "string", "description": "Identifiant du job (requis pour tail et kill, optionnel pour status)"},
                "lines":   {"type": "integer", "default": 50, "description": "Nombre de lignes à lire pour action='tail'"},
            },
            "required": ["alias"],
        },
    ),

    # ── 5. Transferts de Fichiers SFTP Unifiés ───────────────────
    Tool(
        name="ssh_sftp",
        description=(
            "Gère tous les transferts et opérations de fichiers via SFTP.\n"
            "- action='upload' : Envoie un fichier local vers le serveur.\n"
            "- action='download' : Télécharge un fichier distant vers le PC local.\n"
            "- action='upload_dir' : Envoie un dossier complet récursivement vers le serveur (sans zip préalable).\n"
            "- action='download_dir' : Télécharge un dossier distant complet récursivement (sans zip préalable).\n"
            "- action='list' : Liste les fichiers et dossiers d'un répertoire distant."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "action":      {"type": "string", "enum": ["upload", "download", "upload_dir", "download_dir", "list"], "default": "list", "description": "Action SFTP (défaut: list)"},
                "alias":       {"type": "string", "description": "Nom du serveur connecté"},
                "local_path":  {"type": "string", "description": "Chemin local (fichier ou dossier pour upload/download)"},
                "remote_path": {"type": "string", "description": "Chemin distant (fichier ou dossier pour upload/download)"},
                "path":        {"type": "string", "default": ".", "description": "Répertoire distant à lister (pour action='list')"},
                "timeout":     {"type": "integer", "default": 60, "description": "Timeout du transfert en secondes (défaut 60s, 120s pour dossiers)"},
            },
            "required": ["alias"],
        },
    ),

    # ── 6. NetOps & Automatisation Réseau ─────────────────────────
    Tool(
        name="ssh_network",
        description=(
            "Administration et automatisation d'équipements réseau (Cisco, MikroTik, FortiGate, Juniper, generic).\n"
            "- action='exec' : Exécute une séquence de commandes en shell interactif (gère pagination --More--, enable, prompts).\n"
            "- action='push' : Déploie un bloc de configuration multiligne en mode config avec backup automatique préalable.\n"
            "- action='backup' : Sauvegarde la running-config dans un fichier local horodaté.\n"
            "- action='restore' : Restaure une configuration (par défaut en DRY-RUN ; passer confirm=true pour exécuter).\n"
            "- action='diff' : Compare deux configurations (style git diff) ou la config actuelle vs un backup."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "action":            {"type": "string", "enum": ["exec", "push", "backup", "restore", "diff"], "default": "exec", "description": "Action réseau à exécuter"},
                "alias":             {"type": "string", "description": "Nom de l'équipement connecté"},
                "commands":          {"type": "array", "items": {"type": "string"}, "description": "Liste de commandes pour action='exec'"},
                "config":            {"type": "string", "description": "Bloc de configuration (multiligne) pour action='push'"},
                "backup_file":       {"type": "string", "description": "Fichier de backup pour action='restore'"},
                "backup_file_a":     {"type": "string", "description": "Premier fichier pour action='diff'"},
                "backup_file_b":     {"type": "string", "description": "Deuxième fichier pour action='diff' (optionnel : compare avec la running-config si omis)"},
                "device_type":       {"type": "string", "default": "generic", "description": f"Type d'équipement : {', '.join(DEVICE_TYPES)}"},
                "enable_password":   {"type": "string", "description": "Mot de passe enable (Cisco)"},
                "config_mode":       {"type": "boolean", "default": False, "description": "Entrer en mode config avant les commandes (pour action='exec')"},
                "save_config":       {"type": "boolean", "default": True, "description": "Sauvegarder la config après déploiement (write memory / commit)"},
                "backup_first":      {"type": "boolean", "default": True, "description": "Effectuer un backup avant le push de config"},
                "confirm":           {"type": "boolean", "default": False, "description": "false = DRY-RUN (défaut). true = exécution réelle pour action='restore'"},
                "timeout":           {"type": "integer", "default": 60, "description": "Timeout par commande en secondes"},
                "inter_cmd_delay":   {"type": "number", "default": 0.3, "description": "Délai entre chaque commande en secondes"},
                "max_total_timeout": {"type": "integer", "default": 120, "description": "Budget temps total pour tout le batch en secondes"},
            },
            "required": ["alias"],
        },
    ),

    # ── 7. Tunnels & Proxies SOCKS5 ──────────────────────────────
    Tool(
        name="ssh_tunnel",
        description=(
            "Gestion des tunnels TCP et proxies dynamiques SOCKS5.\n"
            "- action='start' : Crée un tunnel local port-forwarding (localhost:port -> remote_host:port).\n"
            "- action='stop' : Ferme un tunnel TCP par son label.\n"
            "- action='start_socks' : Démarre un proxy SOCKS5 dynamique local (127.0.0.1:local_port) routé à travers le serveur SSH.\n"
            "- action='stop_socks' : Ferme un proxy SOCKS5 par son label.\n"
            "- action='list' : Liste les tunnels et proxies actifs pour cet alias."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "action":      {"type": "string", "enum": ["start", "stop", "start_socks", "stop_socks", "list"], "default": "start", "description": "Action de tunneling (défaut: start)"},
                "alias":       {"type": "string", "description": "Nom du serveur connecté"},
                "label":       {"type": "string", "description": "Nom du tunnel ou proxy (requis pour start, stop, start_socks, stop_socks)"},
                "local_port":  {"type": "integer", "default": 1080, "description": "Port local d'écoute"},
                "remote_host": {"type": "string", "description": "Hôte distant cible (pour action='start')"},
                "remote_port": {"type": "integer", "description": "Port distant cible (pour action='start')"},
            },
            "required": ["alias"],
        },
    ),
]

# ═══════════════════════════════════════════
# HANDLERS UNIFIÉS
# ═══════════════════════════════════════════

async def handle(name: str, args: dict) -> str:
    # ── Normalisation des noms & rétrocompatibilité ───────────────
    action = args.get("action")

    # Détection de l'outil cible (supporte les nouveaux outils et anciens alias)
    if name in ("ssh_session", "ssh_connect", "ssh_disconnect", "ssh_list"):
        target_tool = "ssh_session"
        if name == "ssh_connect": action = "connect"
        elif name == "ssh_disconnect": action = "disconnect"
        elif name == "ssh_list": action = "list"
        elif not action: action = "connect"

    elif name in ("ssh_server", "ssh_save_server", "ssh_remove_server", "ssh_list_servers"):
        target_tool = "ssh_server"
        if name == "ssh_save_server": action = "save"
        elif name == "ssh_remove_server": action = "remove"
        elif name == "ssh_list_servers": action = "list"
        elif not action: action = "save"

    elif name in ("ssh_exec", "ssh_exec_sudo", "ssh_exec_background"):
        target_tool = "ssh_exec"
        if name == "ssh_exec_background": args["background"] = True
        elif name == "ssh_exec_sudo": pass

    elif name in ("ssh_job", "ssh_job_status", "ssh_job_tail", "ssh_job_kill"):
        target_tool = "ssh_job"
        if name == "ssh_job_status": action = "status"
        elif name == "ssh_job_tail": action = "tail"
        elif name == "ssh_job_kill": action = "kill"
        elif not action: action = "status"

    elif name in ("ssh_sftp", "ssh_upload", "ssh_download", "ssh_upload_dir", "ssh_download_dir", "ssh_list_remote"):
        target_tool = "ssh_sftp"
        if name == "ssh_upload": action = "upload"
        elif name == "ssh_download": action = "download"
        elif name == "ssh_upload_dir": action = "upload_dir"
        elif name == "ssh_download_dir": action = "download_dir"
        elif name == "ssh_list_remote": action = "list"
        elif not action: action = "list"

    elif name in ("ssh_network", "ssh_exec_network", "ssh_push_config", "ssh_backup_config", "ssh_restore_config", "ssh_diff_config"):
        target_tool = "ssh_network"
        if name == "ssh_exec_network": action = "exec"
        elif name == "ssh_push_config": action = "push"
        elif name == "ssh_backup_config": action = "backup"
        elif name == "ssh_restore_config": action = "restore"
        elif name == "ssh_diff_config": action = "diff"
        elif not action: action = "exec"

    elif name in ("ssh_tunnel", "ssh_close_tunnel", "ssh_socks", "ssh_close_socks"):
        target_tool = "ssh_tunnel"
        if name == "ssh_close_tunnel": action = "stop"
        elif name == "ssh_socks": action = "start_socks"
        elif name == "ssh_close_socks": action = "stop_socks"
        elif not action: action = "start"

    else:
        return f"ERREUR Outil inconnu : {name}"

    # Pool conditionnel
    if target_tool == "ssh_server" and action in ("list", "save", "remove"):
        pool = None
    else:
        pool = get_ssh_pool()

    # ═════════════════════════════════════════════
    # 1. SSH_SESSION
    # ═════════════════════════════════════════════
    if target_tool == "ssh_session":
        if action == "list":
            statuses = pool.list_status()
            servers  = load_servers()
            if not statuses:
                saved = f" ({len(servers)} sauvegardé(s))" if servers else ""
                return f"Aucune connexion active{saved}.\n   -> ssh_session(action='connect', alias='...', host='...', username='...')"
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
                    socks = pool.get_socks(alias)
                    if socks:
                        lines.append(f"  SOCKS5 [{alias}] :")
                        for s in socks:
                            lines.append(f"    [{'ALIVE' if s['alive'] else 'DOWN'}] [{s['label']}] "
                                         f"127.0.0.1:{s['local_port']} ({s['uptime_s']}s)")
                    jobs = pool.get_jobs(alias)
                    if jobs:
                        lines.append(f"  Jobs [{alias}] :")
                        for j in jobs:
                            lines.append(f"    [{j['status'].upper()}] [{j['job_id']}] {j['label']} ({j['runtime_s']}s)")
                except Exception: pass
            return "\n".join(lines)

        alias = args.get("alias")
        if not alias:
            return f"ERREUR : 'alias' est requis pour action='{action}'"

        if action == "disconnect":
            try:
                await pool.disconnect(alias)
                return f"[{alias}] déconnecté"
            except Exception as e: return f"ERREUR {e}"

        # Action: connect
        servers = load_servers()
        saved_cfg = servers.get(alias)
        if saved_cfg is not None:
            try:
                cfg = _resolve_server_entry(alias, saved_cfg)
            except RuntimeError as e:
                return f"ERREUR {e}"
        else:
            cfg = {}
        for field in ("host", "username", "password", "key_path", "key_passphrase",
                      "known_hosts_path", "port", "timeout", "host_key_policy",
                      "jump_alias", "compress", "keepalive_interval"):
            if args.get(field) is not None:
                cfg[field] = args[field]

        if not cfg.get("host") or not cfg.get("username"):
            available = list(servers.keys()) if servers else []
            return (
                f"ERREUR : Pour une nouvelle connexion, 'host' et 'username' sont requis.\n"
                f"   Serveurs sauvegardés disponibles : {available or '(aucun)'}\n"
                f"   Usage : ssh_session(action='connect', alias='{alias}') pour un serveur sauvegardé\n"
                f"        OU ssh_session(action='connect', alias='{alias}', host='...', username='...', password='...')"
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
                jump_alias=cfg.get("jump_alias"),
                compress=bool(cfg.get("compress", True)),
                keepalive_interval=int(cfg.get("keepalive_interval", 30)),
            )
            if saved_cfg is not None:
                origin = " (depuis servers.json)"
                auth = _auth_label(saved_cfg)
                extra = f"   Device  : {saved_cfg.get('device_type', 'generic')}\n"
            else:
                origin = ""
                auth = f"clé: {cfg['key_path']}" if cfg.get("key_path") else "mot de passe de session"
                extra = f"   -> ssh_server(action='save', alias='{alias}', ...) pour le sauvegarder sans secret en clair\n"
            jump_info = f"   JumpHost: {cfg['jump_alias']}\n" if cfg.get("jump_alias") else ""
            return (
                f"SSH connecté [{alias}]{origin}\n"
                f"   Hôte    : {cfg['username']}@{cfg['host']}:{cfg.get('port', 22)}\n"
                f"{jump_info}"
                f"   Auth    : {auth}\n"
                f"{extra}"
                f"   HostKey : {cfg.get('host_key_policy', 'strict')} | Compress: {cfg.get('compress', True)} | Keepalive: {cfg.get('keepalive_interval', 30)}s\n"
                f"   Info    : {info}"
            )
        except FileNotFoundError as e:
            return f"ERREUR {e}"
        except Exception as e:
            err = str(e)
            hint = ("\n-> pip install paramiko" if "paramiko" in err.lower()
                    else "\n-> Vérifie mot de passe / clé" if "authentication" in err.lower()
                    else "\n-> Ajoute la clé hôte à known_hosts ou utilise host_key_policy='auto_add' en labo" if "known hosts" in err.lower() or "host key" in err.lower()
                    else "\n-> Vérifie IP/port ou l'accessibilité du jump host" if any(x in err.lower() for x in ("timed out", "refused", "jump"))
                    else "")
            return f"ERREUR Connexion [{alias}] : {err}{hint}"

    # ═════════════════════════════════════════════
    # 2. SSH_SERVER
    # ═════════════════════════════════════════════
    elif target_tool == "ssh_server":
        if action == "list":
            servers = load_servers()
            if not servers:
                return "Aucun serveur sauvegarde.\n   -> ssh_server(action='save', alias='...')"
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

        alias = args.get("alias")
        if not alias:
            return f"ERREUR : 'alias' est requis pour action='{action}'"

        if action == "remove":
            servers = load_servers()
            if alias not in servers:
                return f"[{alias}] introuvable\nServeurs : {list(servers.keys()) or '(aucun)'}"
            del servers[alias]
            save_servers(servers)
            for field in SECRET_FIELDS: SECRET_STORE.delete_secret(alias, field)
            return f"[{alias}] supprime | Restants : {list(servers.keys()) or '(aucun)'}"

        # Action: save
        servers  = load_servers()
        is_update = alias in servers
        previous = servers.get(alias, {})
        entry = dict(previous)
        for field in ("host", "username", "key_path", "known_hosts_path", "device_type", "jump_alias"):
            if args.get(field):
                entry[field] = args[field]
        entry["port"] = int(args.get("port", previous.get("port", 22)))
        entry["timeout"] = int(args.get("timeout", previous.get("timeout", 15)))
        entry.setdefault("device_type", "generic")
        entry["host_key_policy"] = args.get("host_key_policy", previous.get("host_key_policy", "strict"))
        entry["auto_connect"] = bool(args["auto_connect"]) if "auto_connect" in args \
                                else bool(previous.get("auto_connect", False))
        entry["compress"] = bool(args["compress"]) if "compress" in args \
                            else bool(previous.get("compress", True))
        entry["keepalive_interval"] = int(args.get("keepalive_interval", previous.get("keepalive_interval", 30)))
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

    # ═════════════════════════════════════════════
    # 3. SSH_EXEC
    # ═════════════════════════════════════════════
    elif target_tool == "ssh_exec":
        alias = args.get("alias")
        command = args.get("command")
        if not alias or not command:
            return "ERREUR : 'alias' et 'command' sont requis"

        # Background mode
        if bool(args.get("background", False)):
            try:
                r = await pool.exec_background(alias, command, label=args.get("label"))
                if not r["ok"]:
                    return f"ERREUR Échec lancement background job : {r.get('error', 'inconnu')}"
                return (
                    f"OK Background Job lancé [{alias}:{r['job_id']}]\n"
                    f"   Libellé : {r['label']}\n"
                    f"   Démarré : {r['started_at']}\n"
                    f"   -> Vérifie l'état : ssh_job(action='status', alias='{alias}', job_id='{r['job_id']}')\n"
                    f"   -> Lis la sortie  : ssh_job(action='tail', alias='{alias}', job_id='{r['job_id']}')\n"
                    f"   -> Arrête le job  : ssh_job(action='kill', alias='{alias}', job_id='{r['job_id']}')"
                )
            except KeyError as e: return f"ERREUR {e}"
            except Exception as e: return f"ERREUR {e}"

        # Sudo mode
        if args.get("sudo_password"):
            try:
                r = await pool.exec_sudo(alias, command, args["sudo_password"],
                                         timeout=int(args.get("timeout", 30)))
                icon = "OK" if r["exit_code"] == 0 else "ERR"
                lines = [f"{icon} [{alias}] sudo {command}  |  exit={r['exit_code']}  |  {r['elapsed']}s"]
                if r["stdout"].rstrip(): lines.append(r["stdout"].rstrip())
                if r["stderr"].rstrip() and r["exit_code"] != 0: lines.append(f"[stderr]\n{r['stderr'].rstrip()}")
                return "\n".join(lines)
            except KeyError as e: return f"ERREUR {e}"
            except Exception as e: return f"ERREUR {e}"

        # Standard synchronous exec
        try:
            r = await pool.exec(alias, command,
                                timeout=int(args.get("timeout", 30)),
                                get_pty=bool(args.get("pty", False)))
            icon = "OK" if r["exit_code"] == 0 else "ERR"
            lines = [f"{icon} [{alias}] $ {command}  |  exit={r['exit_code']}  |  {r['elapsed']}s"]
            if r["stdout"].rstrip(): lines.append(r["stdout"].rstrip())
            if r["stderr"].rstrip() and r["exit_code"] != 0: lines.append(f"[stderr]\n{r['stderr'].rstrip()}")
            return "\n".join(lines)
        except KeyError as e: return f"ERREUR {e}"
        except Exception as e: return f"ERREUR {e}"

    # ═════════════════════════════════════════════
    # 4. SSH_JOB
    # ═════════════════════════════════════════════
    elif target_tool == "ssh_job":
        alias = args.get("alias")
        if not alias:
            return "ERREUR : 'alias' est requis"
        job_id = args.get("job_id")

        if action == "tail":
            if not job_id:
                return "ERREUR : 'job_id' est requis pour action='tail'"
            lines_count = int(args.get("lines", 50))
            try:
                r = await pool.job_tail(alias, job_id, lines=lines_count)
                if not r["ok"]:
                    return f"ERREUR {r.get('error', 'Job introuvable')}"
                exit_str = f"exit={r['exit_code']}" if r['exit_code'] is not None else "running"
                lines = [f"Tail [{alias}:{job_id}] — {r['status'].upper()} ({exit_str} | {r['runtime_s']}s) :"]
                if r["stdout"].strip(): lines.append(r["stdout"].rstrip())
                if r["stderr"].strip(): lines.append(f"[stderr]\n{r['stderr'].rstrip()}")
                if not r["stdout"].strip() and not r["stderr"].strip():
                    lines.append("  (aucune sortie pour le moment)")
                return "\n".join(lines)
            except KeyError as e: return f"ERREUR {e}"
            except Exception as e: return f"ERREUR {e}"

        elif action == "kill":
            if not job_id:
                return "ERREUR : 'job_id' est requis pour action='kill'"
            try:
                r = await pool.job_kill(alias, job_id)
                if not r["ok"]:
                    return f"ERREUR {r.get('error', 'Impossible de stopper le job')}"
                return f"OK Job [{alias}:{job_id}] arrêté (KILLED)"
            except KeyError as e: return f"ERREUR {e}"
            except Exception as e: return f"ERREUR {e}"

        # Action: status
        try:
            res = await pool.job_status(alias, job_id=job_id)
            if isinstance(res, dict):
                if not res.get("ok", True):
                    return f"ERREUR {res.get('error', 'Job introuvable')}"
                exit_str = f"exit={res['exit_code']}" if res['exit_code'] is not None else "en cours"
                return (
                    f"Job [{alias}:{res['job_id']}] — {res['status'].upper()} ({exit_str}) | {res['runtime_s']}s\n"
                    f"   Libellé : {res['label']}\n"
                    f"   Commande: {res['command']}\n"
                    f"   Lignes  : stdout={res['stdout_count']} | stderr={res['stderr_count']}\n"
                    f"   -> Lis avec ssh_job(action='tail', alias='{alias}', job_id='{res['job_id']}')"
                )
            if not res:
                return f"[{alias}] Aucun job en arrière-plan"
            lines = [f"[{alias}] {len(res)} job(s) :"]
            for j in res:
                exit_str = f"exit={j['exit_code']}" if j['exit_code'] is not None else "running"
                lines.append(f"  [{j['status'].upper():<9}] [{j['job_id']}] {j['label']} ({exit_str} | {j['runtime_s']}s)")
            return "\n".join(lines)
        except KeyError as e: return f"ERREUR {e}"
        except Exception as e: return f"ERREUR {e}"

    # ═════════════════════════════════════════════
    # 5. SSH_SFTP
    # ═════════════════════════════════════════════
    elif target_tool == "ssh_sftp":
        alias = args.get("alias")
        if not alias:
            return "ERREUR : 'alias' est requis"

        if action == "list":
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

        local_path = args.get("local_path")
        remote_path = args.get("remote_path")
        if not local_path or not remote_path:
            return f"ERREUR : 'local_path' et 'remote_path' sont requis pour action='{action}'"

        if action == "upload":
            timeout = int(args.get("timeout", 60))
            try:
                r = await pool.upload(alias, local_path, remote_path, timeout=timeout)
                if r["ok"]: return f"OK Upload [{alias}]\n   {local_path} -> {remote_path}\n   {r['size']//1024} KB"
                return f"ERREUR Upload échoué : {r['error']}"
            except Exception as e: return f"ERREUR {e}"

        elif action == "download":
            timeout = int(args.get("timeout", 60))
            try:
                r = await pool.download(alias, remote_path, local_path, timeout=timeout)
                if r["ok"]: return f"OK Download [{alias}]\n   {remote_path} -> {local_path}\n   {r['size']//1024} KB"
                return f"ERREUR Download échoué : {r['error']}"
            except Exception as e: return f"ERREUR {e}"

        elif action == "upload_dir":
            timeout = int(args.get("timeout", 120))
            try:
                r = await pool.upload_dir(alias, local_path, remote_path, timeout=timeout)
                if r["ok"]:
                    return (
                        f"OK Upload Dossier [{alias}]\n"
                        f"   {local_path} -> {r['remote_path']}\n"
                        f"   {r['files_count']} fichier(s) transféré(s) | {r['total_size']//1024} KB"
                    )
                return f"ERREUR Upload Dossier échoué : {r['error']}"
            except Exception as e: return f"ERREUR {e}"

        elif action == "download_dir":
            timeout = int(args.get("timeout", 120))
            try:
                r = await pool.download_dir(alias, remote_path, local_path, timeout=timeout)
                if r["ok"]:
                    return (
                        f"OK Download Dossier [{alias}]\n"
                        f"   {remote_path} -> {r['local_path']}\n"
                        f"   {r['files_count']} fichier(s) téléchargé(s) | {r['total_size']//1024} KB"
                    )
                return f"ERREUR Download Dossier échoué : {r['error']}"
            except Exception as e: return f"ERREUR {e}"

    # ═════════════════════════════════════════════
    # 6. SSH_NETWORK
    # ═════════════════════════════════════════════
    elif target_tool == "ssh_network":
        alias = args.get("alias")
        if not alias:
            return "ERREUR : 'alias' est requis"

        if action == "exec":
            commands = args.get("commands")
            if not commands:
                return "ERREUR : 'commands' est requis pour action='exec'"
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
            except Exception as e: return f"ERREUR {e}"

        elif action == "push":
            config = args.get("config")
            if not config:
                return "ERREUR : 'config' est requis pour action='push'"
            device_type = args.get("device_type", "generic")
            timeout     = int(args.get("timeout", 60))
            backup_msg  = ""

            if bool(args.get("backup_first", True)):
                try:
                    bk = await pool.backup_config(alias, device_type=device_type, timeout=timeout)
                    if bk["ok"]:
                        bk_path = _write_backup(alias, bk["config"], suffix="pre-push")
                        backup_msg = f"   Backup auto : {bk_path}\n"
                    else:
                        backup_msg = f"   WARN Backup auto échoué : {bk['errors']}\n"
                except Exception as e:
                    backup_msg = f"   WARN Backup auto impossible : {e}\n"

            commands = [l for l in config.splitlines() if l.strip() and not l.strip().startswith("!")]
            try:
                r = await pool.exec_network(
                    alias           = alias,
                    commands        = commands,
                    device_type     = device_type,
                    enable_password = args.get("enable_password"),
                    config_mode     = True,
                    save_config     = bool(args.get("save_config", True)),
                    timeout         = timeout,
                    inter_cmd_delay = float(args.get("inter_cmd_delay", 0.3)),
                )
                status = "OK" if not r["errors"] else "WARN"
                lines  = [
                    f"{status} [{alias}] Déploiement configuration",
                    backup_msg.rstrip("\n") if backup_msg else "",
                    f"   Lignes envoyées : {r['commands_sent']}/{len(commands)} | {r['elapsed']}s",
                ]
                lines = [l for l in lines if l]
                if r["errors"]:
                    lines.append("WARN Erreurs :")
                    lines.extend(f"  {e}" for e in r["errors"])
                else:
                    lines.append("OK Aucune erreur détectée")
                return "\n".join(lines)
            except KeyError as e: return f"ERREUR {e}"
            except Exception as e: return f"ERREUR {e}"

        elif action == "backup":
            try:
                r = await pool.backup_config(alias,
                    device_type = args.get("device_type", "generic"),
                    timeout     = int(args.get("timeout", 60)))
                if not r["ok"]:
                    err = ", ".join(r["errors"]) if r["errors"] else "Sortie vide"
                    return f"ERREUR Backup [{alias}] échoué : {err}"
                path = _write_backup(alias, r["config"])
                lines_count = len(r["config"].splitlines())
                size_kb = len(r["config"].encode()) // 1024
                return (
                    f"OK Backup [{alias}] sauvegardé\n"
                    f"   Fichier : {path}\n"
                    f"   Taille  : {lines_count} lignes | {size_kb} KB | {r['elapsed']}s"
                )
            except KeyError as e: return f"ERREUR {e}"
            except Exception as e: return f"ERREUR {e}"

        elif action == "restore":
            backup_file = args.get("backup_file")
            if not backup_file:
                return "ERREUR : 'backup_file' est requis pour action='restore'"
            if not os.path.exists(backup_file):
                return f"ERREUR Fichier de backup introuvable : {backup_file}"
            try:
                with open(backup_file, "r", encoding="utf-8", errors="replace") as f:
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

        elif action == "diff":
            file_a = args.get("backup_file_a")
            if not file_a:
                return "ERREUR : 'backup_file_a' est requis pour action='diff'"
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

    # ═════════════════════════════════════════════
    # 7. SSH_TUNNEL
    # ═════════════════════════════════════════════
    elif target_tool == "ssh_tunnel":
        alias = args.get("alias")
        if not alias:
            return "ERREUR : 'alias' est requis"

        if action == "list":
            tunnels = pool.get_tunnels(alias)
            socks = pool.get_socks(alias)
            lines = [f"Tunnels & Proxies [{alias}] :"]
            if tunnels:
                lines.append("  Tunnels TCP :")
                for t in tunnels:
                    lines.append(f"    [{'ALIVE' if t['alive'] else 'DOWN'}] [{t['label']}] localhost:{t['local_port']} -> {t['remote']} ({t['uptime_s']}s)")
            if socks:
                lines.append("  Proxies SOCKS5 :")
                for s in socks:
                    lines.append(f"    [{'ALIVE' if s['alive'] else 'DOWN'}] [{s['label']}] 127.0.0.1:{s['local_port']} ({s['uptime_s']}s)")
            if not tunnels and not socks:
                lines.append("  (aucun tunnel ni proxy actif)")
            return "\n".join(lines)

        label = args.get("label")
        if not label:
            return f"ERREUR : 'label' est requis pour action='{action}'"

        if action == "stop":
            try:
                ok = await pool.stop_tunnel(alias, label)
                return f"OK Tunnel [{label}] fermé" if ok else f"WARN Tunnel [{label}] introuvable"
            except Exception as e: return f"ERREUR {e}"

        elif action == "start_socks":
            local_port = int(args.get("local_port", 1080))
            try:
                r = await pool.start_socks(alias, label, local_port=local_port)
                if r["ok"]:
                    return (
                        f"OK SOCKS5 Proxy [{alias}:{label}]\n"
                        f"   127.0.0.1:{local_port} -> tout le trafic routé via {alias}\n"
                        f"   -> Configure ton navigateur/curl/Burp avec SOCKS5 proxy: 127.0.0.1:{local_port}\n"
                        f"   -> Ferme avec ssh_tunnel(action='stop_socks', alias='{alias}', label='{label}')"
                    )
                return f"ERREUR SOCKS5 échoué : {r['error']}"
            except Exception as e: return f"ERREUR {e}"

        elif action == "stop_socks":
            try:
                ok = await pool.stop_socks(alias, label)
                return f"OK SOCKS5 [{label}] fermé" if ok else f"WARN SOCKS5 [{label}] introuvable"
            except Exception as e: return f"ERREUR {e}"

        # Action: start TCP tunnel
        local_port = args.get("local_port")
        remote_host = args.get("remote_host")
        remote_port = args.get("remote_port")
        if not (local_port and remote_host and remote_port):
            return "ERREUR : 'local_port', 'remote_host' et 'remote_port' sont requis pour action='start'"
        try:
            r = await pool.start_tunnel(alias, label, int(local_port), remote_host, int(remote_port))
            if r["ok"]:
                return (
                    f"OK Tunnel [{alias}:{label}]\n"
                    f"   localhost:{local_port} -> {remote_host}:{remote_port}\n"
                    f"   -> Ferme avec ssh_tunnel(action='stop', alias='{alias}', label='{label}')"
                )
            return f"ERREUR Tunnel échoué : {r['error']}"
        except Exception as e: return f"ERREUR {e}"

    return f"ERREUR Outil ou action non géré : {name}/{action}"


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
    # Ordonner : les serveurs sans jump_alias d'abord, puis ceux avec jump_alias
    sorted_aliases = sorted(auto_servers.keys(), key=lambda a: 1 if auto_servers[a].get("jump_alias") else 0)
    for alias in sorted_aliases:
        cfg = auto_servers[alias]
        try:
            resolved = _resolve_server_entry(alias, cfg)
            info = await p.connect(
                alias=alias, host=resolved["host"], username=resolved["username"],
                password=resolved.get("password"), key_path=resolved.get("key_path"),
                key_passphrase=resolved.get("key_passphrase"),
                known_hosts_path=resolved.get("known_hosts_path"),
                port=int(resolved.get("port",22)), timeout=int(resolved.get("timeout",15)),
                host_key_policy=resolved.get("host_key_policy", "strict"),
                jump_alias=resolved.get("jump_alias"),
                compress=bool(resolved.get("compress", True)),
                keepalive_interval=int(resolved.get("keepalive_interval", 30)),
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
    log.info(f"SSH MCP Server v5.0.0 | {len(TOOLS)} outils unifiés | Paramiko: {'OK' if _SSH_OK else 'ERROR'}")
    log.info(f"Devices supportes : {', '.join(DEVICE_TYPES)}")
    log.info(f"Backups : {BACKUPS_DIR}")
    # Reference conservee : sans elle la task peut etre collectee par le GC.
    autoconnect_task = asyncio.create_task(autoconnect())
    autoconnect_task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
