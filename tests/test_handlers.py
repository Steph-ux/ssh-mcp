import asyncio
import json
import shutil
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import server
from secret_store import SecretStore
from test_server_security import FakeCredBackend


@pytest.fixture
def isolated(monkeypatch):
    tmp_dir = ROOT / "tests" / f".tmp-{uuid.uuid4().hex}"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    servers_file = tmp_dir / "servers.json"
    servers_file.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(server, "SERVERS_FILE", servers_file)
    monkeypatch.setattr(server, "BACKUPS_DIR", tmp_dir / "backups")
    monkeypatch.setattr(server, "SECRET_STORE", SecretStore(backend=FakeCredBackend()))
    yield servers_file
    shutil.rmtree(tmp_dir, ignore_errors=True)


def call(name, **args):
    return asyncio.run(server.handle(name, args))


# ── H1 : merge sur save_server ───────────────────────────────────


def test_save_server_partial_update_preserves_fields(isolated):
    call(
        "ssh_save_server",
        alias="core",
        host="10.0.0.1",
        username="admin",
        key_path="C:\\keys\\id_ed25519",
        device_type="cisco",
        known_hosts_path="C:\\kh",
    )
    call("ssh_save_server", alias="core", port=2222)

    entry = json.loads(isolated.read_text(encoding="utf-8"))["core"]
    assert entry["port"] == 2222
    assert entry["key_path"] == "C:\\keys\\id_ed25519"
    assert entry["device_type"] == "cisco"
    assert entry["known_hosts_path"] == "C:\\kh"


def test_save_server_requires_host_for_new_alias(isolated):
    result = call("ssh_save_server", alias="inconnu", port=22)
    assert "ERREUR" in result
    assert json.loads(isolated.read_text(encoding="utf-8")) == {}


# ── H2 : override sur connect ────────────────────────────────────


def test_connect_merges_saved_credentials_with_explicit_host(isolated, monkeypatch):
    captured = {}

    class FakePool:
        async def connect(self, **kwargs):
            captured.update(kwargs)
            return "ok"

    monkeypatch.setattr(server, "get_ssh_pool", lambda: FakePool())
    call("ssh_save_server", alias="box", host="10.0.0.1", username="root", password="s3cret")

    call("ssh_connect", alias="box", host="10.0.0.99")

    assert captured["host"] == "10.0.0.99", "l'override explicite doit gagner"
    assert captured["username"] == "root", "username sauvegarde doit etre conserve"
    assert captured["password"] == "s3cret", "le secret du store doit etre utilise"


# ── C1 : dry-run sur restore ─────────────────────────────────────


def test_restore_is_dry_run_by_default(isolated, monkeypatch, tmp_path):
    called = []

    class FakePool:
        async def exec_network(self, **kwargs):
            called.append(kwargs)
            return {"output": "", "errors": [], "commands_sent": 0, "elapsed": 0}

    monkeypatch.setattr(server, "get_ssh_pool", lambda: FakePool())
    backup = tmp_path / "cfg.txt"
    backup.write_text("[core] # show running-config\n!\nhostname R1\n", encoding="utf-8")

    result = call("ssh_restore_config", alias="core", backup_file=str(backup))

    assert called == [], "aucune commande ne doit partir en dry-run"
    assert "DRY-RUN" in result
    assert "hostname R1" in result
    assert "] # show running-config" not in result


def test_restore_with_confirm_sends_only_clean_lines(isolated, monkeypatch, tmp_path):
    called = []

    class FakePool:
        async def exec_network(self, **kwargs):
            called.append(kwargs)
            return {"output": "", "errors": [], "commands_sent": 2, "elapsed": 1}

    monkeypatch.setattr(server, "get_ssh_pool", lambda: FakePool())
    backup = tmp_path / "cfg.txt"
    backup.write_text(
        "[core] # show running-config\nBuilding configuration...\n!\nhostname R1\ninterface Gi0/0\n",
        encoding="utf-8",
    )

    call("ssh_restore_config", alias="core", backup_file=str(backup), confirm=True)

    assert called[0]["commands"] == ["hostname R1", "interface Gi0/0"]


# ── MCP Protocol : call_tool safety & robust return types ────────


def test_all_tools_return_valid_text_content_on_empty_args(isolated):
    assert len(server.TOOLS) == 7
    for t in server.TOOLS:
        res = asyncio.run(server.call_tool(t.name, {}))
        assert isinstance(res, list), f"{t.name} did not return a list"
        assert len(res) == 1, f"{t.name} returned list of length {len(res)}"
        item = res[0]
        assert item.type == "text", f"{t.name} type is not text"
        assert isinstance(item.text, str), f"{t.name} text is not str: {type(item.text)}"
        assert len(item.text) > 0, f"{t.name} text is empty"


def test_all_tools_return_valid_text_content_on_none_args(isolated):
    for t in server.TOOLS:
        res = asyncio.run(server.call_tool(t.name, None))
        assert isinstance(res, list)
        assert len(res) == 1
        item = res[0]
        assert item.type == "text"
        assert isinstance(item.text, str)
        assert len(item.text) > 0


def test_unified_handlers_and_legacy_compatibility(isolated, monkeypatch):
    captured = []

    class FakePool:
        async def connect(self, **kwargs):
            captured.append(("connect", kwargs))
            return "connected"

        async def upload(self, *args, **kwargs):
            captured.append(("upload", args, kwargs))
            return {"ok": True, "size": 1024}

        async def start_socks(self, alias, label, local_port=1080):
            captured.append(("start_socks", alias, label, local_port))
            return {"ok": True, "local_port": local_port}

    monkeypatch.setattr(server, "get_ssh_pool", lambda: FakePool())

    # 1. Unified call
    res1 = call("ssh_session", action="connect", alias="vps", host="1.1.1.1", username="root")
    assert "SSH connecté" in res1
    assert captured[0][0] == "connect"

    # 2. Legacy call mapped to unified
    res2 = call("ssh_connect", alias="vps2", host="2.2.2.2", username="root")
    assert "SSH connecté" in res2
    assert captured[1][0] == "connect"

    # 3. SFTP unified vs legacy
    call("ssh_sftp", action="upload", alias="vps", local_path="a", remote_path="b")
    call("ssh_upload", alias="vps", local_path="a", remote_path="b")
    assert len([c for c in captured if c[0] == "upload"]) == 2

    # 4. SOCKS5 unified vs legacy
    call("ssh_tunnel", action="start_socks", alias="vps", label="p1", local_port=1080)
    call("ssh_socks", alias="vps", label="p2", local_port=1081)
    assert len([c for c in captured if c[0] == "start_socks"]) == 2


def test_unknown_tool_returns_clean_error_text_content():
    res = asyncio.run(server.call_tool("invalid_tool_name", {}))
    assert isinstance(res, list)
    assert len(res) == 1
    assert res[0].type == "text"
    assert "ERREUR" in res[0].text

