"""Tests du fix exec_sudo — le mot de passe ne doit JAMAIS fuiter.

Scénarios couverts :
1. Hôte NOPASSWD : aucun prompt → le password n'est PAS écrit sur stdin.
2. Prompt sudo détecté : le password est écrit, puis masqué dans la sortie.
3. Le password qui s'échoverait dans l'output (PTY fusionne stdout/stderr)
   est remplacé par ***.
"""

import re
import socket
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ssh_manager import SSHConnection


class FakeChannel:
    """Canal paramiko simulé. Séquence de chunks programmable."""

    def __init__(self, chunks, exit_code=0):
        self._chunks = list(chunks)
        self._written = []
        self._exit = exit_code
        self._status_ready = False

    def recv_ready(self):
        return bool(self._chunks)

    def recv(self, n):
        return self._chunks.pop(0).encode()

    def exit_status_ready(self):
        # Statut prêt seulement quand tous les chunks sont consommés
        return not self._chunks and self._status_done()

    def _status_done(self):
        return getattr(self, "_drained", False) or True

    def recv_exit_status(self):
        return self._exit

    def settimeout(self, t):
        pass

    @property
    def written_stdin(self):
        return b"".join(self._written)


class FakeStdin:
    def __init__(self, channel):
        self._channel = channel

    def write(self, data):
        self._channel._written.append(data.encode())

    def flush(self):
        pass


class FakeFile:
    """file-like retourné par exec_command (out/err)."""

    def __init__(self, channel):
        self._channel = channel

    def read(self, n=-1):
        if self._channel.recv_ready():
            return self._channel.recv(n if n > 0 else 65536).encode()
        return b""

    @property
    def channel(self):
        return self._channel


def _make_conn_with(chunks):
    conn = SSHConnection("t", "127.0.0.1", 22, "u", password="x")
    channel = FakeChannel(chunks)
    client = type("C", (), {})()
    client.exec_command = lambda cmd, timeout=None, get_pty=False: (
        FakeStdin(channel),
        FakeFile(channel),
        FakeFile(FakeChannel([])),
    )
    conn._client = client
    conn.is_alive = lambda: True
    return conn, channel


def test_sudo_nopasswd_never_sends_password():
    """Sans prompt sudo, le mot de passe ne part pas sur stdin."""
    conn, channel = _make_conn_with(["command output\n"])
    r = conn.exec_sudo("whoami", "SUPERSECRET", timeout=5)
    assert r["exit_code"] == 0
    assert "command output" in r["stdout"]
    assert channel.written_stdin == b"", (
        f"password envoyé sans prompt ! écrit: {channel.written_stdin!r}"
    )


def test_sudo_prompt_triggers_password_then_masks_it():
    """Prompt détecté → password envoyé une fois, puis masqué dans l'output."""
    # Le PTY écho le password tapé (comportement réel observé sur certains hôtes)
    conn, channel = _make_conn_with([
        "[sudo] password for u: SUPERSECRET\nroot\n",
    ])
    r = conn.exec_sudo("id", "SUPERSECRET", timeout=5)
    assert channel.written_stdin == b"SUPERSECRET\n"
    assert "SUPERSECRET" not in r["stdout"], f"fuite: {r['stdout']!r}"
    assert "***" in r["stdout"] or "root" in r["stdout"]
    assert r["exit_code"] == 0


def test_sudo_password_masked_even_in_error_path():
    """Si une exception contient le password (traceback réseau), il est masqué."""
    conn = SSHConnection("t", "127.0.0.1", 22, "u", password="x")

    class Boom:
        def exec_command(self, *a, **k):
            raise RuntimeError("channel broke with SUPERSECRET inside")

    conn._client = Boom()
    conn.is_alive = lambda: True
    r = conn.exec_sudo("id", "SUPERSECRET", timeout=5)
    assert "SUPERSECRET" not in r["stderr"], f"fuite stderr: {r['stderr']!r}"