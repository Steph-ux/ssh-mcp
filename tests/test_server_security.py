import asyncio
import json
import shutil
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import server
from secret_store import SecretStore


class FakeCredBackend:
    CRED_TYPE_GENERIC = 1
    CRED_PERSIST_LOCAL_MACHINE = 2

    def __init__(self):
        self.store = {}

    def CredWrite(self, cred, flags):
        self.store[(cred["TargetName"], cred["Type"])] = cred

    def CredRead(self, Type, TargetName):
        key = (TargetName, Type)
        if key not in self.store:
            raise RuntimeError("missing")
        return self.store[key]

    def CredDelete(self, TargetName, Type, Flags):
        self.store.pop((TargetName, Type), None)


def test_secret_store_round_trip():
    secrets = SecretStore(backend=FakeCredBackend())
    secrets.set_secret("dns1", "password", "secret-value")

    assert secrets.has_secret("dns1", "password") is True
    assert secrets.get_secret("dns1", "password") == "secret-value"

    secrets.delete_secret("dns1", "password")
    assert secrets.get_secret("dns1", "password") is None


def test_load_servers_migrates_plaintext_credentials(monkeypatch):
    tmp_dir = ROOT / "tests" / f".tmp-{uuid.uuid4().hex}"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    servers_file = tmp_dir / "servers.json"
    servers_file.write_text(
        json.dumps(
            {
                "dns1": {
                    "host": "192.168.1.10",
                    "username": "root",
                    "password": "plaintext",
                    "key_passphrase": "pp",
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(server, "SERVERS_FILE", servers_file)
    monkeypatch.setattr(server, "SECRET_STORE", SecretStore(backend=FakeCredBackend()))
    try:
        loaded = server.load_servers()

        assert loaded["dns1"]["password_stored"] is True
        assert loaded["dns1"]["key_passphrase_stored"] is True
        assert "password" not in loaded["dns1"]
        assert "key_passphrase" not in loaded["dns1"]

        persisted = json.loads(servers_file.read_text(encoding="utf-8"))
        assert "password" not in persisted["dns1"]
        assert "key_passphrase" not in persisted["dns1"]
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_autoconnect_only_uses_opted_in_servers(monkeypatch):
    calls = []

    class FakePool:
        async def connect(self, **kwargs):
            calls.append(kwargs)
            return "ok"

    fake_secrets = SecretStore(backend=FakeCredBackend())
    fake_secrets.set_secret("auto-box", "password", "stored-secret")

    monkeypatch.setattr(
        server,
        "load_servers",
        lambda: {
            "auto-box": {
                "host": "10.0.0.10",
                "username": "root",
                "password_stored": True,
                "host_key_policy": "strict",
                "known_hosts_path": "C:\\Users\\test\\.ssh\\known_hosts_lab",
                "auto_connect": True,
            },
            "manual-box": {
                "host": "10.0.0.11",
                "username": "root",
                "password_stored": True,
                "auto_connect": False,
            },
        },
    )
    monkeypatch.setattr(server, "SECRET_STORE", fake_secrets)
    monkeypatch.setattr(server, "get_ssh_pool", lambda: FakePool())

    asyncio.run(server.autoconnect())

    assert len(calls) == 1
    assert calls[0]["alias"] == "auto-box"
    assert calls[0]["password"] == "stored-secret"
    assert calls[0]["host_key_policy"] == "strict"
    assert calls[0]["known_hosts_path"] == "C:\\Users\\test\\.ssh\\known_hosts_lab"
