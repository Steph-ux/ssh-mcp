import asyncio
import io
import socket
import stat
import threading
import time
from unittest.mock import MagicMock, patch

import pytest
import server
from ssh_manager import SSHConnection, SSHPool


def test_ssh_connection_init_and_kwargs():
    conn = SSHConnection(
        alias="test",
        host="1.2.3.4",
        port=22,
        username="user",
        compress=True,
        keepalive_interval=45,
        jump_alias="bastion",
    )
    assert conn.compress is True
    assert conn.keepalive_interval == 45
    assert conn.jump_alias == "bastion"
    assert "via [bastion]" in conn.status_line()


def test_sftp_upload_dir_and_download_dir(tmp_path):
    # Setup local source dir
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "file1.txt").write_text("hello 1", encoding="utf-8")
    sub = src_dir / "sub"
    sub.mkdir()
    (sub / "file2.txt").write_text("hello 2", encoding="utf-8")

    conn = SSHConnection("test", "1.2.3.4", 22, "user")
    fake_sftp = MagicMock()
    conn._sftp = fake_sftp
    conn.is_alive = MagicMock(return_value=True)

    # Test upload_dir
    res = conn.upload_dir(str(src_dir), "/remote/dir")
    assert res["ok"] is True
    assert res["files_count"] == 2
    assert fake_sftp.put.call_count == 2

    # Test download_dir
    fake_item1 = MagicMock()
    fake_item1.filename = "file1.txt"
    fake_item1.st_mode = stat.S_IFREG
    fake_item1.st_size = 100

    fake_sftp.listdir_attr.return_value = [fake_item1]
    dst_dir = tmp_path / "dst"

    res_dl = conn.download_dir("/remote/dir", str(dst_dir))
    assert res_dl["ok"] is True
    assert res_dl["files_count"] == 1
    assert fake_sftp.get.call_count == 1


def test_socks5_handshake_and_connect():
    conn = SSHConnection("test", "1.2.3.4", 22, "user")
    conn.is_alive = MagicMock(return_value=True)

    fake_transport = MagicMock()
    fake_channel = MagicMock()
    fake_transport.is_active.return_value = True
    fake_transport.open_channel.return_value = fake_channel

    fake_client = MagicMock()
    fake_client.get_transport.return_value = fake_transport
    conn._client = fake_client

    # Bind on an ephemeral free port
    sock_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_test.bind(("127.0.0.1", 0))
    free_port = sock_test.getsockname()[1]
    sock_test.close()

    res = conn.start_socks("test-socks", local_port=free_port)
    assert res["ok"] is True
    assert len(conn.list_socks()) == 1

    try:
        # Client connects to SOCKS5 server
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.connect(("127.0.0.1", free_port))
        # 1. Send SOCKS5 handshake (no auth)
        c.sendall(b"\x05\x01\x00")
        resp = c.recv(2)
        assert resp == b"\x05\x00"

        # 2. Send CONNECT to 127.0.0.1:80 (IPv4)
        c.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
        resp2 = c.recv(10)
        assert resp2 == b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        c.close()
    finally:
        conn.stop_socks("test-socks")
        assert len(conn.list_socks()) == 0


def test_background_jobs_lifecycle():
    conn = SSHConnection("test", "1.2.3.4", 22, "user")
    conn.is_alive = MagicMock(return_value=True)

    fake_client = MagicMock()
    fake_stdout = MagicMock()
    fake_stderr = MagicMock()
    fake_channel = MagicMock()

    # Fake stdout streams a few lines then EOF
    fake_stdout.read.side_effect = [b"line 1\nline 2\n", b"line 3\n", b""]
    fake_stderr.read.side_effect = [b""]
    fake_stdout.channel = fake_channel
    fake_channel.recv_exit_status.return_value = 0

    fake_client.exec_command.return_value = (MagicMock(), fake_stdout, fake_stderr)
    conn._client = fake_client

    res = conn.exec_background("ping -c 3 8.8.8.8", label="test-ping")
    assert res["ok"] is True
    job_id = res["job_id"]

    # Wait briefly for thread to finish
    time.sleep(0.2)

    status = conn.job_status(job_id)
    assert status["ok"] is True
    assert status["status"] == "completed"
    assert status["exit_code"] == 0

    tail = conn.job_tail(job_id, lines=10)
    assert tail["ok"] is True
    assert "line 1" in tail["stdout"]
    assert "line 3" in tail["stdout"]

    all_jobs = conn.job_status()
    assert len(all_jobs) == 1
    assert all_jobs[0]["job_id"] == job_id


def test_jump_host_pool_chaining(monkeypatch):
    pool = SSHPool()
    jump_conn = MagicMock()
    jump_conn.is_alive.return_value = True
    fake_transport = MagicMock()
    fake_transport.is_active.return_value = True
    fake_channel = MagicMock()
    fake_transport.open_channel.return_value = fake_channel
    jump_conn._client.get_transport.return_value = fake_transport

    pool._conns["bastion"] = jump_conn

    created_conn = None

    class MockSSHConnection(SSHConnection):
        def connect(self):
            nonlocal created_conn
            created_conn = self
            return "connected via jump"

    monkeypatch.setattr("ssh_manager.SSHConnection", MockSSHConnection)

    info = pool._connect_sync(
        alias="target",
        host="10.0.0.99",
        username="admin",
        password="secretpassword",
        key_path=None,
        key_passphrase=None,
        port=22,
        timeout=15,
        host_key_policy="auto_add",
        known_hosts_path=None,
        jump_alias="bastion",
    )

    assert info == "connected via jump"
    assert created_conn.jump_alias == "bastion"
    assert created_conn.sock == fake_channel
    fake_transport.open_channel.assert_called_once_with("direct-tcpip", ("10.0.0.99", 22), ("127.0.0.1", 0))
