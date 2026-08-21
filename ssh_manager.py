"""
SSH Manager v4.0 - persistent SSH connections via Paramiko.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger("ssh-manager")

# Shell dimensions for network devices
DEFAULT_SHELL_WIDTH = 220  # Largeur pour éviter le wrap sur les configs Cisco
DEFAULT_SHELL_HEIGHT = 50  # Hauteur pour la pagination

DEVICE_PROFILES = {
    "cisco": {
        "prompt_pattern": r"[#>]\s*$",
        "disable_pager": "terminal length 0",
        "enable_cmd": "enable",
        "config_enter": "configure terminal",
        "config_exit": "end",
        "config_save": "write memory",
        "backup_cmd": "show running-config",
        "more_pattern": r"--More--|<--- More --->",
        "more_send": " ",
        "error_patterns": [r"% Invalid", r"% Ambiguous", r"% Incomplete", r"Error:"],
    },
    "cisco_xr": {
        "prompt_pattern": r"[#]\s*$",
        "disable_pager": "terminal length 0",
        "enable_cmd": None,
        "config_enter": "configure",
        "config_exit": "end",
        "config_save": "commit",
        "backup_cmd": "show running-config",
        "more_pattern": r"--More--",
        "more_send": " ",
        "error_patterns": [r"% Invalid", r"syntax error", r"Error:"],
    },
    "mikrotik": {
        "prompt_pattern": r"\]\s*>\s*$",
        "disable_pager": None,
        "enable_cmd": None,
        "config_enter": None,
        "config_exit": None,
        "config_save": None,
        "backup_cmd": "/export compact",
        "more_pattern": None,
        "more_send": None,
        "error_patterns": [r"bad command name", r"no such item", r"input does not match"],
    },
    "fortigate": {
        "prompt_pattern": r"[#$]\s*$",
        "disable_pager": "config system console\nset output standard\nend",
        "enable_cmd": None,
        "config_enter": None,
        "config_exit": "end",
        "config_save": None,
        "backup_cmd": "show full-configuration",
        "more_pattern": r"--More--|\[Q\]",
        "more_send": " ",
        "error_patterns": [r"Command fail\.", r"Unknown action", r"object not found"],
    },
    "juniper": {
        "prompt_pattern": r"[#>%]\s*$",
        "disable_pager": "set cli screen-length 0",
        "enable_cmd": None,
        "config_enter": "configure exclusive",
        "config_exit": "exit",
        "config_save": "commit and-quit",
        "backup_cmd": "show configuration",
        "more_pattern": None,
        "more_send": None,
        "error_patterns": [r"syntax error", r"unknown command", r"error:"],
    },
    "generic": {
        "prompt_pattern": r"[\$#>]\s*$",
        "disable_pager": None,
        "enable_cmd": None,
        "config_enter": None,
        "config_exit": None,
        "config_save": None,
        "backup_cmd": None,
        "more_pattern": None,
        "more_send": None,
        "error_patterns": [],
    },
}

# Séquences ANSI/VT100 émises par les équipements réseau lors de la pagination
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_BACKSPACE_RE = re.compile(r"[^\x08]\x08")

# Limite dure de sortie par commande (anti-OOM : cat /dev/urandom, logs géants...).
# Configurable via SSH_MCP_MAX_OUTPUT_BYTES.
MAX_OUTPUT_BYTES = int(os.environ.get("SSH_MCP_MAX_OUTPUT_BYTES", str(10 * 1024 * 1024)))


def _read_bounded(fileobj, max_bytes: int = MAX_OUTPUT_BYTES) -> bytes:
    """Lit un file-like paramiko avec une limite dure d'octets.

    Lève ValueError si la sortie dépasse max_bytes — au lieu d'aspirer
    des gigaoctets en mémoire. Le message invite à affiner la commande.
    """
    data = bytearray()
    while len(data) < max_bytes:
        chunk = fileobj.read(65536)
        if not chunk:
            break
        data.extend(chunk)
    if len(data) >= max_bytes:
        extra = fileobj.read(1)
        if extra:
            raise ValueError(
                f"Sortie > {max_bytes // (1024 * 1024)} Mo — "
                "affine la commande (head/tail/grep/wc) pour réduire le volume."
            )
    return bytes(data)

# Bannières émises avant la config elle-même, sans valeur pour un restore/diff
_BANNER_RE = re.compile(
    r"^(Building configuration|Current configuration\s*:|# \w+ script|# model =|# software id =)",
    re.IGNORECASE,
)


def clean_device_output(raw: str, command: str = "", prompt_re: str = r"[\$#>]\s*$") -> str:
    """Retire ANSI, écho de commande, marqueurs de pagination et prompt final.

    La sortie brute d'un invoke_shell contient l'écho de la commande envoyée puis
    le prompt suivant. Les réinjecter dans un restore reviendrait à exécuter des
    lignes qui ne font pas partie de la configuration.
    """
    text = _ANSI_RE.sub("", raw).replace("\r\n", "\n").replace("\r", "\n")
    while _BACKSPACE_RE.search(text):
        text = _BACKSPACE_RE.sub("", text)
    text = text.replace("\x08", "")

    lines = text.split("\n")
    cmd = command.strip()
    if cmd:
        for index, line in enumerate(lines[:3]):
            if line.strip().endswith(cmd):
                lines = lines[index + 1:]
                break

    while lines and (not lines[-1].strip() or re.search(prompt_re, lines[-1])):
        lines.pop()
    while lines and not lines[0].strip():
        lines.pop(0)
    return "\n".join(lines)


def strip_config_noise(text: str) -> list:
    """Ne conserve que les lignes réellement exécutables d'un fichier de config."""
    kept = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped[0] in "!#;":
            continue
        if stripped.startswith("[") and "] # " in stripped:
            continue
        if _BANNER_RE.match(stripped):
            continue
        kept.append(line.rstrip())
    return kept


_POOL_INSTANCE = None
_POOL_LOCK = threading.Lock()


def get_ssh_pool():
    global _POOL_INSTANCE
    with _POOL_LOCK:
        if _POOL_INSTANCE is None:
            _POOL_INSTANCE = SSHPool()
        return _POOL_INSTANCE


class SSHConnection:
    def __init__(
        self,
        alias,
        host,
        port,
        username,
        password=None,
        key_path=None,
        key_passphrase=None,
        timeout=15,
        host_key_policy="strict",
        known_hosts_path=None,
    ):
        self.alias = alias
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_path = key_path
        self.key_passphrase = key_passphrase
        self.timeout = timeout
        self.host_key_policy = host_key_policy or "strict"
        self.known_hosts_path = known_hosts_path
        self.connected_at = None
        self.last_used_at = None
        self._client = None
        self._sftp = None
        self._tunnels = {}
        self._op_lock = threading.RLock()
        self._last_cmd_time = 0
        self._min_cmd_interval = 0.1  # 100ms minimum entre commandes réseau

    def connect(self) -> str:
        with self._op_lock:
            try:
                import paramiko
            except ImportError as exc:
                raise RuntimeError("Paramiko non installe - pip install paramiko") from exc

            client = paramiko.SSHClient()
            client.load_system_host_keys()

            known_hosts = (
                os.path.expandvars(os.path.expanduser(self.known_hosts_path))
                if self.known_hosts_path
                else os.path.join(os.path.expanduser("~"), ".ssh", "known_hosts")
            )
            if os.path.exists(known_hosts):
                try:
                    client.load_host_keys(known_hosts)
                except Exception as exc:
                    log.warning("[%s] known_hosts illisible: %s", self.alias, exc)

            if self.host_key_policy == "auto_add":
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            else:
                client.set_missing_host_key_policy(paramiko.RejectPolicy())

            kwargs = {
                "hostname": self.host,
                "port": self.port,
                "username": self.username,
                "timeout": self.timeout,
                "allow_agent": True,
                "look_for_keys": True,
            }

            if self.key_path:
                expanded = os.path.expandvars(os.path.expanduser(self.key_path))
                if not os.path.exists(expanded):
                    raise FileNotFoundError(f"Cle SSH introuvable: {expanded}")

                key_order = [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey]
                try:
                    with open(expanded, "r", errors="replace") as key_file:
                        header = key_file.readline().strip().upper()
                    if "ED25519" in header:
                        key_order = [paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey]
                    elif "ECDSA" in header or "EC PRIVATE" in header:
                        key_order = [paramiko.ECDSAKey, paramiko.RSAKey, paramiko.Ed25519Key]
                except Exception:
                    pass

                pkey = None
                last_error = None
                for key_cls in key_order:
                    try:
                        pkey = key_cls.from_private_key_file(
                            expanded,
                            password=self.key_passphrase or None,
                        )
                        break
                    except Exception as exc:
                        last_error = exc
                if pkey is None:
                    raise ValueError(
                        f"Impossible de charger la cle SSH '{expanded}'. "
                        f"Erreur: {last_error}"
                    )
                kwargs["pkey"] = pkey
                kwargs["look_for_keys"] = False
            elif self.password:
                kwargs["password"] = self.password
                kwargs["look_for_keys"] = False
                kwargs["allow_agent"] = False

            client.connect(**kwargs)
            self._client = client
            transport = client.get_transport()
            if transport:
                # Evite la majorite des reconnexions dues aux coupures NAT/idle.
                transport.set_keepalive(30)
            self.connected_at = self.last_used_at = time.time()

            try:
                _, stdout, _ = client.exec_command(
                    "uname -a 2>/dev/null || ver 2>/dev/null || echo connected",
                    timeout=5,
                )
                first_line = stdout.read().decode(errors="replace").strip().splitlines()
                return first_line[0] if first_line else "connected"
            except Exception:
                return "connected"

    def is_alive(self) -> bool:
        with self._op_lock:
            if not self._client:
                return False
            try:
                transport = self._client.get_transport()
                if not transport or not transport.is_active():
                    return False
                transport.send_ignore()
                return True
            except Exception:
                return False

    def reconnect(self, max_attempts: int = 3) -> bool:
        with self._op_lock:
            for attempt in range(max_attempts):
                try:
                    # keep_tunnels : les sockets d'ecoute locaux restent valides,
                    # seul le transport change et il est relu a chaque connexion.
                    self.disconnect(keep_tunnels=True)
                    self.connect()
                    if attempt > 0:
                        log.info("[%s] Reconnexion réussie après %d tentative(s)", self.alias, attempt + 1)
                    return True
                except Exception as exc:
                    log.warning("[%s] Reconnexion échouée (tentative %d/%d): %s", self.alias, attempt + 1, max_attempts, exc)
                    if attempt < max_attempts - 1:
                        # Délai exponentiel : 1s, 2s, 4s
                        delay = 2 ** attempt
                        time.sleep(delay)
            log.error("[%s] Reconnexion définitivement échouée après %d tentatives", self.alias, max_attempts)
            return False

    def exec(self, command: str, timeout: int = 30, get_pty: bool = False) -> dict:
        with self._op_lock:
            if not self.is_alive() and not self.reconnect():
                return {"stdout": "", "stderr": "Connexion perdue", "exit_code": -1, "elapsed": 0}
            self.last_used_at = time.time()
            t0 = time.time()
            try:
                _, out, err = self._client.exec_command(command, timeout=timeout, get_pty=get_pty)
                out.channel.settimeout(timeout)
                err.channel.settimeout(timeout)
                stdout_data = _read_bounded(out).decode(errors="replace")
                stderr_data = "" if get_pty else _read_bounded(err).decode(errors="replace")
                exit_code = out.channel.recv_exit_status()
                return {
                    "stdout": stdout_data,
                    "stderr": stderr_data,
                    "exit_code": exit_code,
                    "elapsed": round(time.time() - t0, 2),
                }
            except socket.timeout:
                return {
                    "stdout": "",
                    "stderr": f"Timeout {timeout}s",
                    "exit_code": -1,
                    "elapsed": round(time.time() - t0, 2),
                }
            except Exception as exc:
                return {
                    "stdout": "",
                    "stderr": str(exc),
                    "exit_code": -1,
                    "elapsed": round(time.time() - t0, 2),
                }

    def exec_sudo(self, command: str, sudo_password: str, timeout: int = 30) -> dict:
        """Exécute une commande via sudo -S.

        Sécurité :
        - Le mot de passe n'est écrit sur stdin QUE lorsqu'un prompt
          '[sudo] password:' / 'Password:' est réellement détecté. Sur un hôte
          NOPASSWD, rien n'est envoyé (le password ne peut pas fuiter dans le
          stdin de la commande elle-même).
        - Avec get_pty=True, stdout et stderr sont fusionnés dans un seul flux ;
          le mot de passe est donc masqué dans la sortie COMBINÉE, pas seulement
          dans stderr.
        """
        with self._op_lock:
            if not self.is_alive() and not self.reconnect():
                return {"stdout": "", "stderr": "Connexion perdue", "exit_code": -1, "elapsed": 0}
            self.last_used_at = time.time()
            t0 = time.time()
            try:
                stdin, out, err = self._client.exec_command(
                    f"sudo -S -p '[sudo] password: ' {command}",
                    timeout=timeout,
                    get_pty=True,
                )
                channel = out.channel

                # Lecture incrémentale : on attend le prompt sudo avant d'écrire.
                # Si aucun prompt n'apparaît (NOPASSWD), la commande s'exécute
                # sans qu'aucun secret ne soit transmis.
                buf = ""
                password_sent = False
                deadline = time.time() + timeout
                prompt_re = re.compile(r"\[sudo\]\s*password|[Pp]assword\s*:")

                while True:
                    if time.time() > deadline:
                        raise socket.timeout(f"Timeout {timeout}s en attente du prompt sudo")
                    if channel.recv_ready():
                        chunk = channel.recv(16384).decode(errors="replace")
                        buf += chunk
                        if not password_sent and prompt_re.search(buf):
                            time.sleep(0.05)  # laisse le prompt se rendre completement
                            stdin.write(sudo_password + "\n")
                            stdin.flush()
                            password_sent = True
                            # Retire la ligne du prompt de la sortie finale.
                            nl = buf.rfind("\n")
                            buf = buf[:nl] if nl != -1 else ""
                    elif channel.exit_status_ready():
                        # Draine ce qui reste avant de sortir.
                        while channel.recv_ready():
                            buf += channel.recv(16384).decode(errors="replace")
                        break
                    else:
                        time.sleep(0.02)
                        if channel.exit_status_ready():
                            while channel.recv_ready():
                                buf += channel.recv(16384).decode(errors="replace")
                            break

                exit_code = channel.recv_exit_status()

                # Le mot de passe ne doit JAMAIS apparaitre dans la sortie,
                # quel que soit le flux (PTY fusionne stdout+stderr).
                combined = buf.replace(sudo_password, "***")
                lines = [
                    line for line in combined.splitlines()
                    if "[sudo] password" not in line.lower()
                ]

                return {
                    "stdout": "\n".join(lines),
                    "stderr": "",
                    "exit_code": exit_code,
                    "elapsed": round(time.time() - t0, 2),
                }
            except socket.timeout:
                return {
                    "stdout": "",
                    "stderr": f"Timeout {timeout}s",
                    "exit_code": -1,
                    "elapsed": round(time.time() - t0, 2),
                }
            except Exception as exc:
                return {
                    "stdout": "",
                    "stderr": str(exc).replace(sudo_password, "***"),
                    "exit_code": -1,
                    "elapsed": round(time.time() - t0, 2),
                }

    MAX_PAGES = 5000

    def _read_until_prompt(
        self,
        shell,
        prompt_re,
        idle_timeout=10,
        more_re=None,
        more_send=None,
        hard_deadline=None,
    ) -> str:
        """Lit jusqu'au prompt.

        idle_timeout borne le silence entre deux chunks (pas la durée totale) :
        un 'show running-config' de 10 000 lignes reste valide tant que les
        données arrivent. hard_deadline borne la durée absolue.
        """
        buf = ""
        idle_until = time.time() + idle_timeout
        pages = 0
        while True:
            now = time.time()
            if hard_deadline is not None and now >= hard_deadline:
                raise TimeoutError(f"Timeout absolu atteint - {len(buf)} octets recus")
            if now >= idle_until:
                raise TimeoutError(f"Aucune donnee depuis {idle_timeout}s - prompt non atteint")

            if not shell.recv_ready():
                time.sleep(0.02)
                continue

            buf += shell.recv(16384).decode(errors="replace")
            idle_until = time.time() + idle_timeout

            if more_re:
                consumed = False
                match = re.search(more_re, buf)
                while match:
                    shell.send(more_send or " ")
                    pages += 1
                    if pages > self.MAX_PAGES:
                        raise TimeoutError(f"Pagination anormale ({pages} pages) - abandon")
                    # Le marqueur est retire du buffer, sinon il re-matche
                    # indefiniment et on envoie des espaces en boucle.
                    buf = buf[: match.start()] + buf[match.end():]
                    consumed = True
                    match = re.search(more_re, buf)
                if consumed:
                    continue

            tail = buf.rsplit("\n", 1)[-1]
            if re.search(prompt_re, tail):
                return buf

    def exec_network(
        self,
        commands: list,
        device_type: str = "generic",
        enable_password: str | None = None,
        config_mode: bool = False,
        save_config: bool = False,
        timeout: int = 30,
        inter_cmd_delay: float = 0.3,
        max_total_timeout: int = 120,
    ) -> dict:
        with self._op_lock:
            if not self.is_alive() and not self.reconnect():
                return {
                    "output": "",
                    "clean_output": "",
                    "results": [],
                    "errors": ["Connexion perdue"],
                    "commands_sent": 0,
                    "elapsed": 0,
                }

            profile = DEVICE_PROFILES.get(device_type, DEVICE_PROFILES["generic"])
            t0 = time.time()
            deadline = t0 + max(max_total_timeout, timeout)
            prompt_re = profile["prompt_pattern"]
            more_re = profile.get("more_pattern")
            more_send = profile.get("more_send")

            output = []
            results = []
            errors = []
            sent = 0
            shell = None

            def read(idle, use_pager=True):
                return self._read_until_prompt(
                    shell,
                    prompt_re,
                    idle_timeout=idle,
                    more_re=more_re if use_pager else None,
                    more_send=more_send if use_pager else None,
                    hard_deadline=deadline,
                )

            try:
                shell = self._client.invoke_shell(width=DEFAULT_SHELL_WIDTH, height=DEFAULT_SHELL_HEIGHT)
                shell.settimeout(timeout)
                time.sleep(0.2)

                read(min(5, max(1, deadline - time.time())))

                if profile.get("disable_pager"):
                    for line in profile["disable_pager"].splitlines():
                        shell.send(line + "\n")
                        time.sleep(inter_cmd_delay)
                    read(5)

                if profile.get("enable_cmd") and enable_password:
                    shell.send(profile["enable_cmd"] + "\n")
                    time.sleep(inter_cmd_delay)
                    buf = self._read_until_prompt(
                        shell, r"[Pp]assword:|[#>]\s*$", idle_timeout=5, hard_deadline=deadline
                    )
                    if re.search(r"[Pp]assword:", buf):
                        shell.send(enable_password + "\n")
                        time.sleep(inter_cmd_delay)
                        read(5)

                if config_mode and profile.get("config_enter"):
                    shell.send(profile["config_enter"] + "\n")
                    time.sleep(inter_cmd_delay)
                    read(5)

                for cmd in commands:
                    cmd = cmd.strip()
                    if not cmd or cmd.startswith("#"):
                        continue
                    if time.time() >= deadline:
                        errors.append(f"Timeout total ({max_total_timeout}s) - commandes restantes ignorees a partir de: {cmd}")
                        break

                    elapsed = time.time() - self._last_cmd_time
                    if elapsed < self._min_cmd_interval:
                        time.sleep(self._min_cmd_interval - elapsed)

                    shell.send(cmd + "\n")
                    self._last_cmd_time = time.time()
                    sent += 1
                    time.sleep(inter_cmd_delay)

                    try:
                        buf = read(timeout)
                    except TimeoutError as exc:
                        # Une commande lente ne doit pas annuler tout le batch.
                        errors.append(f"Timeout sur '{cmd}': {exc}")
                        log.warning("[%s] exec_network: timeout sur '%s'", self.alias, cmd)
                        continue

                    clean = clean_device_output(buf, cmd, prompt_re)
                    results.append({"command": cmd, "output": clean})
                    output.append(f"[{self.alias}] # {cmd}")
                    output.append(clean)
                    for err_pat in profile.get("error_patterns", []):
                        if re.search(err_pat, clean, re.IGNORECASE):
                            errors.append(f"Erreur sur '{cmd}': {clean.strip()[:200]}")
                            break

                if config_mode and profile.get("config_exit"):
                    shell.send(profile["config_exit"] + "\n")
                    time.sleep(inter_cmd_delay)
                    read(5)

                if save_config and profile.get("config_save"):
                    shell.send(profile["config_save"] + "\n")
                    time.sleep(inter_cmd_delay)
                    buf = read(15)
                    clean = clean_device_output(buf, profile["config_save"], prompt_re)
                    output.append(f"[{self.alias}] # {profile['config_save']}")
                    output.append(clean)
            except Exception as exc:
                errors.append(f"Erreur shell interactif: {exc}")
                log.error("[%s] exec_network: shell execution failed: %s", self.alias, exc)
            finally:
                if shell is not None:
                    try:
                        shell.close()
                    except Exception:
                        pass

            self.last_used_at = time.time()
            return {
                "output": "\n".join(output),
                "clean_output": "\n".join(r["output"] for r in results),
                "results": results,
                "errors": errors,
                "commands_sent": sent,
                "elapsed": round(time.time() - t0, 2),
            }

    def backup_config(self, device_type: str = "generic", timeout: int = 60) -> dict:
        profile = DEVICE_PROFILES.get(device_type, DEVICE_PROFILES["generic"])
        backup_cmd = profile.get("backup_cmd")
        if not backup_cmd:
            backup_cmd = "cat /etc/network/interfaces 2>/dev/null; ip addr show; ip route show"

        if device_type in ("cisco", "cisco_xr", "mikrotik", "fortigate", "juniper"):
            result = self.exec_network(commands=[backup_cmd], device_type=device_type, timeout=timeout)
            return {
                "ok": len(result["errors"]) == 0 and bool(result["clean_output"].strip()),
                "config": result["clean_output"],
                "raw": result["output"],
                "errors": result["errors"],
                "elapsed": result["elapsed"],
            }

        result = self.exec(backup_cmd, timeout=timeout)
        return {
            "ok": result["exit_code"] == 0,
            "config": result["stdout"],
            "raw": result["stdout"],
            "errors": [result["stderr"]] if result["stderr"] else [],
            "elapsed": result["elapsed"],
        }

    def _ensure_alive(self):
        if not self.is_alive() and not self.reconnect():
            raise ConnectionError(f"[{self.alias}] connexion perdue et reconnexion impossible")

    def _get_sftp(self):
        self._ensure_alive()
        if not self._sftp:
            self._sftp = self._client.open_sftp()
        return self._sftp

    def upload(self, local_path: str, remote_path: str) -> dict:
        with self._op_lock:
            local_path = os.path.expandvars(os.path.expanduser(local_path))
            if not os.path.exists(local_path):
                return {"ok": False, "error": f"Fichier introuvable: {local_path}"}
            try:
                self._get_sftp().put(local_path, remote_path)
                return {"ok": True, "size": os.path.getsize(local_path)}
            except Exception as exc:
                self._sftp = None
                return {"ok": False, "error": str(exc)}

    def download(self, remote_path: str, local_path: str) -> dict:
        with self._op_lock:
            local_path = os.path.expandvars(os.path.expanduser(local_path))
            os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
            try:
                self._get_sftp().get(remote_path, local_path)
                return {"ok": True, "size": os.path.getsize(local_path)}
            except Exception as exc:
                self._sftp = None
                return {"ok": False, "error": str(exc)}

    def list_remote(self, remote_path: str = ".") -> list:
        with self._op_lock:
            try:
                items = self._get_sftp().listdir_attr(remote_path)
                result = []
                for item in sorted(items, key=lambda value: value.filename):
                    import stat as stat_module

                    result.append(
                        {
                            "name": item.filename,
                            "type": "dir" if stat_module.S_ISDIR(item.st_mode) else "file",
                            "size": item.st_size,
                            "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(item.st_mtime)),
                        }
                    )
                return result
            except Exception as exc:
                self._sftp = None
                raise exc

    def start_tunnel(self, label: str, local_port: int, remote_host: str, remote_port: int) -> dict:
        with self._op_lock:
            if label in self._tunnels:
                return {"ok": False, "error": f"Tunnel '{label}' deja actif"}
            try:
                self._ensure_alive()

                server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_sock.bind(("127.0.0.1", local_port))
                server_sock.listen(10)
                server_sock.settimeout(1.0)
                stop_event = threading.Event()

                def tunnel_loop():
                    while not stop_event.is_set():
                        try:
                            client_sock, _ = server_sock.accept()
                        except socket.timeout:
                            continue
                        except Exception:
                            break
                        try:
                            # Le transport est relu a chaque connexion : apres un
                            # reconnect, celui capture a la creation serait mort.
                            transport = self._client.get_transport() if self._client else None
                            if not transport or not transport.is_active():
                                raise ConnectionError("transport SSH inactif")
                            channel = transport.open_channel(
                                "direct-tcpip",
                                (remote_host, remote_port),
                                client_sock.getpeername(),
                            )
                        except Exception as exc:
                            log.warning("[tunnel:%s] %s", label, exc)
                            client_sock.close()
                            continue

                        def forward(src, dst):
                            try:
                                while True:
                                    data = src.recv(4096)
                                    if not data:
                                        break
                                    dst.sendall(data)
                            except Exception:
                                pass
                            finally:
                                for sock_obj in (src, dst):
                                    try:
                                        sock_obj.close()
                                    except Exception:
                                        pass

                        threading.Thread(target=forward, args=(client_sock, channel), daemon=True).start()
                        threading.Thread(target=forward, args=(channel, client_sock), daemon=True).start()
                    server_sock.close()

                thread = threading.Thread(target=tunnel_loop, name=f"tunnel-{label}", daemon=True)
                thread.start()
                self._tunnels[label] = {
                    "thread": thread,
                    "stop_event": stop_event,
                    "server_sock": server_sock,
                    "local_port": local_port,
                    "remote_host": remote_host,
                    "remote_port": remote_port,
                    "started_at": time.time(),
                }
                return {"ok": True, "local_port": local_port}
            except Exception as exc:
                return {"ok": False, "error": str(exc)}

    def stop_tunnel(self, label: str) -> bool:
        with self._op_lock:
            tunnel = self._tunnels.pop(label, None)
            if not tunnel:
                return False
            try:
                tunnel["stop_event"].set()
                tunnel["server_sock"].close()
            except Exception:
                pass
            return True

    def list_tunnels(self) -> list:
        with self._op_lock:
            return [
                {
                    "label": label,
                    "local_port": tunnel["local_port"],
                    "remote": f"{tunnel['remote_host']}:{tunnel['remote_port']}",
                    "alive": tunnel["thread"].is_alive(),
                    "uptime_s": int(time.time() - tunnel["started_at"]),
                }
                for label, tunnel in self._tunnels.items()
            ]

    def disconnect(self, keep_tunnels: bool = False):
        with self._op_lock:
            if not keep_tunnels:
                for label in list(self._tunnels):
                    self.stop_tunnel(label)
            for obj in (self._sftp, self._client):
                try:
                    if obj:
                        obj.close()
                except Exception:
                    pass
            self._sftp = None
            self._client = None

    def status_line(self) -> str:
        with self._op_lock:
            alive = self.is_alive()
            uptime = int(time.time() - self.connected_at) if self.connected_at else 0
            last_use = int(time.time() - self.last_used_at) if self.last_used_at else 0
            state = "connected" if alive else "down"
            return (
                f"{state} [{self.alias}] {self.username}@{self.host}:{self.port} "
                f"| uptime={uptime}s | last_used={last_use}s ago | tunnels={len(self._tunnels)}"
            )


class SSHPool:
    def __init__(self):
        self._conns = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="ssh-mcp")

    def _get(self, alias: str) -> SSHConnection:
        with self._lock:
            conn = self._conns.get(alias)
        if not conn:
            raise KeyError(
                f"Connexion '{alias}' introuvable. Lance ssh_connect(alias='{alias}', ...). "
                f"Actives: {self.list_aliases() or '(aucune)'}"
            )
        return conn

    async def connect(
        self,
        alias,
        host,
        username,
        password=None,
        key_path=None,
        key_passphrase=None,
        port=22,
        timeout=15,
        host_key_policy="strict",
        known_hosts_path=None,
    ) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            self._connect_sync,
            alias,
            host,
            username,
            password,
            key_path,
            key_passphrase,
            port,
            timeout,
            host_key_policy,
            known_hosts_path,
        )

    def _connect_sync(
        self,
        alias,
        host,
        username,
        password,
        key_path,
        key_passphrase,
        port,
        timeout,
        host_key_policy,
        known_hosts_path,
    ) -> str:
        with self._lock:
            old_conn = self._conns.get(alias)
        if old_conn:
            try:
                old_conn.disconnect()
            except Exception:
                pass

        conn = SSHConnection(
            alias=alias,
            host=host,
            port=port,
            username=username,
            password=password,
            key_path=key_path,
            key_passphrase=key_passphrase,
            timeout=timeout,
            host_key_policy=host_key_policy,
            known_hosts_path=known_hosts_path,
        )
        info = conn.connect()
        with self._lock:
            self._conns[alias] = conn
        log.info("[SSH] %s -> %s@%s:%s connected", alias, username, host, port)
        return info

    async def exec(self, alias, command, timeout=30, get_pty=False) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._get(alias).exec, command, timeout, get_pty)

    async def exec_sudo(self, alias, command, sudo_password, timeout=30) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._get(alias).exec_sudo, command, sudo_password, timeout)

    async def exec_network(
        self,
        alias,
        commands,
        device_type="generic",
        enable_password=None,
        config_mode=False,
        save_config=False,
        timeout=30,
        inter_cmd_delay=0.3,
        max_total_timeout=120,
    ) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            self._get(alias).exec_network,
            commands,
            device_type,
            enable_password,
            config_mode,
            save_config,
            timeout,
            inter_cmd_delay,
            max_total_timeout,
        )

    async def backup_config(self, alias, device_type="generic", timeout=60) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._get(alias).backup_config, device_type, timeout)

    async def upload(self, alias, local_path, remote_path) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._get(alias).upload, local_path, remote_path)

    async def download(self, alias, remote_path, local_path) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._get(alias).download, remote_path, local_path)

    async def list_remote(self, alias, remote_path=".") -> list:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._get(alias).list_remote, remote_path)

    async def start_tunnel(self, alias, label, local_port, remote_host, remote_port) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            self._get(alias).start_tunnel,
            label,
            local_port,
            remote_host,
            remote_port,
        )

    async def stop_tunnel(self, alias, label) -> bool:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._get(alias).stop_tunnel, label)

    async def disconnect(self, alias: str):
        with self._lock:
            conn = self._conns.pop(alias, None)
        if conn:
            await asyncio.get_event_loop().run_in_executor(self._executor, conn.disconnect)

    def list_aliases(self) -> list:
        with self._lock:
            return list(self._conns.keys())

    def list_status(self) -> list:
        with self._lock:
            return [conn.status_line() for conn in self._conns.values()]

    def get_tunnels(self, alias) -> list:
        return self._get(alias).list_tunnels()

    def count(self) -> int:
        with self._lock:
            return len(self._conns)
