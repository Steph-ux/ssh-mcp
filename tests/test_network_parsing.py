import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ssh_manager import SSHConnection, clean_device_output, strip_config_noise


class FakeShell:
    """Simule un canal paramiko : rejoue des chunks, capte ce qui est envoye."""

    def __init__(self, chunks, on_send=None):
        self._chunks = list(chunks)
        self.sent = []
        self._on_send = on_send

    def recv_ready(self):
        return bool(self._chunks)

    def recv(self, _size):
        return self._chunks.pop(0).encode()

    def send(self, data):
        self.sent.append(data)
        if self._on_send:
            extra = self._on_send(data)
            if extra:
                self._chunks.extend(extra)

    def close(self):
        pass


def _conn():
    return SSHConnection(alias="test", host="h", port=22, username="u")


# ── C2 : pagination ──────────────────────────────────────────────


def test_pagination_consumes_marker_and_keeps_content():
    """Le marqueur --More-- doit etre retire du buffer, sinon boucle infinie."""
    pages = iter([" ligne2\n --More-- ", " ligne3\nrouter#"])

    def on_send(_data):
        return [next(pages, "")]

    shell = FakeShell([" ligne1\n --More-- "], on_send=on_send)
    buf = _conn()._read_until_prompt(
        shell, r"[#>]\s*$", idle_timeout=2, more_re=r"--More--", more_send=" "
    )

    assert shell.sent == [" ", " "]
    assert "--More--" not in buf
    for expected in ("ligne1", "ligne2", "ligne3"):
        assert expected in buf, f"{expected} perdue par la pagination"


def test_pagination_does_not_loop_forever_without_progress():
    shell = FakeShell(["--More--"] * 20)
    conn = _conn()
    conn.MAX_PAGES = 5
    with pytest.raises(TimeoutError):
        conn._read_until_prompt(
            shell, r"[#>]\s*$", idle_timeout=1, more_re=r"--More--", more_send=" "
        )


# ── C3 : timeouts ────────────────────────────────────────────────


def test_idle_timeout_raises_when_no_prompt():
    shell = FakeShell(["du texte sans prompt"])
    start = time.time()
    with pytest.raises(TimeoutError):
        _conn()._read_until_prompt(shell, r"[#>]\s*$", idle_timeout=1)
    assert time.time() - start < 3


def test_hard_deadline_wins_over_idle_timeout():
    shell = FakeShell([])
    with pytest.raises(TimeoutError, match="absolu"):
        _conn()._read_until_prompt(
            shell, r"[#>]\s*$", idle_timeout=30, hard_deadline=time.time() + 0.3
        )


def test_prompt_detected_returns_buffer():
    shell = FakeShell(["show version\nIOS 15.2\nrouter#"])
    buf = _conn()._read_until_prompt(shell, r"[#>]\s*$", idle_timeout=2)
    assert "IOS 15.2" in buf


# ── C1 : nettoyage de sortie ─────────────────────────────────────


def test_clean_output_strips_echo_and_prompt():
    raw = "show running-config\r\nhostname R1\r\ninterface Gi0/0\r\nR1#"
    clean = clean_device_output(raw, "show running-config", r"[#>]\s*$")
    assert clean == "hostname R1\ninterface Gi0/0"


def test_clean_output_strips_ansi_sequences():
    raw = "\x1b[2Kshow ver\r\n\x1b[0mVersion 1.0\r\nR1#"
    clean = clean_device_output(raw, "show ver", r"[#>]\s*$")
    assert "\x1b" not in clean
    assert clean == "Version 1.0"


def test_strip_config_noise_removes_backup_headers():
    """Regression C1 : ces lignes etaient poussees comme commandes au restore."""
    content = (
        "[core-sw] # show running-config\n"
        "Building configuration...\n"
        "!\n"
        "Current configuration : 1234 bytes\n"
        "hostname R1\n"
        "# commentaire\n"
        "\n"
        "interface Gi0/0\n"
    )
    assert strip_config_noise(content) == ["hostname R1", "interface Gi0/0"]
