"""端到端不变量测试。

覆盖：
1. 上传/下载往返一致，密文与密钥分目录、原件明文与 DEK 永不落盘；
2. 8 MiB 上限；
3. 轮换只重封装 DEK、原件密文字节不变、旧 KEK 文件删除后才报完成；
4. 上传待登记暂停：收尾后不留下旧钥引用；
5. 下载待解封暂停：已受理下载必须读完原件；
6. 轮换中重启自动续办，已归档文件始终可解密；
7. 同期只允许一次轮换。
"""

from __future__ import annotations

import hashlib
import os
import threading
import time

import pytest

from app.main import app
from app.service import MAX_FILE_SIZE
from fastapi.testclient import TestClient


def make_tiff(size: int, seed: int = 1) -> bytes:
    """生成带 II 字节序魔数的最小 TIFF 风格字节串（内容可任意）。"""
    header = b"II\x2a\x00" + size.to_bytes(4, "little")
    body = bytes(((i * 37 + seed) & 0xFF) for i in range(size - len(header)))
    return header + body


def wait_until(predicate, timeout: float = 10.0, interval: float = 0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError("等待条件超时")


@pytest.fixture()
def tmp_data(tmp_path):
    return str(tmp_path / "data")


@pytest.fixture()
def svc(tmp_data, monkeypatch):
    monkeypatch.setenv("ARCHIVE_DATA_DIR", tmp_data)
    with TestClient(app) as client:
        from app.main import service as current
        yield client, current


def _upload(client: TestClient, content: bytes, name: str = "image.tif") -> str:
    r = client.post("/api/uploads", json={"filename": name, "size": len(content)})
    assert r.status_code == 201, r.text
    upload_id = r.json()["upload_id"]
    r = client.put(f"/api/uploads/{upload_id}/content", content=content)
    assert r.status_code == 200, r.text
    r = client.post(f"/api/uploads/{upload_id}/complete")
    assert r.status_code == 200, r.text
    return r.json()["file_id"]


def _download(client: TestClient, file_id: str) -> bytes:
    r = client.post(f"/api/files/{file_id}/downloads")
    assert r.status_code == 201, r.text
    dl = r.json()["download_id"]
    r = client.get(f"/api/downloads/{dl}/content")
    assert r.status_code == 200, r.text
    return r.content


class TestArchive:
    def test_roundtrip_and_plaintext_never_on_disk(self, svc, tmp_data):
        client, service = svc
        payload = make_tiff(4096, seed=7)
        digest = hashlib.sha256(payload).hexdigest()

        file_id = _upload(client, payload)
        got = _download(client, file_id)
        assert got == payload
        assert client.get("/api/files").json()[0]["sha256"] == digest

        # 不变量：vault/staging 下任何文件都不含 TIFF 明文魔数；keys 与 vault 分目录。
        for root, _dirs, files in os.walk(tmp_data):
            for name in files:
                path = os.path.join(root, name)
                with open(path, "rb") as f:
                    data = f.read()
                if "vault" in path or "staging" in path:
                    assert payload not in data
                    assert b"II\x2a\x00" not in data, f"密文文件中出现明文魔数: {path}"
                if "vault" in path:
                    assert "keys" not in path
        assert os.path.isdir(os.path.join(tmp_data, "keys"))
        assert os.path.isdir(os.path.join(tmp_data, "vault"))
        assert os.path.isdir(os.path.join(tmp_data, "staging"))

        # DEK 明文不落盘：数据库内只允许出现封装后的 BLOB；KEK 字节本身只在 keys/*.kek。
        import sqlite3

        conn = sqlite3.connect(os.path.join(tmp_data, "archive.db"))
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert {"project_keys", "files", "uploads", "downloads", "rotations"} <= tables
        kek_path = service.list_keys()[0]["key_id"]
        with open(os.path.join(tmp_data, "keys", kek_path + ".kek"), "rb") as f:
            kek_bytes = f.read()
        for (blob,) in conn.execute("SELECT wrapped_dek FROM files WHERE wrapped_dek IS NOT NULL"):
            assert blob != kek_bytes
        # 已完成下载的受理快照封装材料必须已清空，不残留可解封的旧钥引用。
        assert conn.execute(
            "SELECT COUNT(*) FROM downloads WHERE state='completed' AND wrapped_dek IS NOT NULL"
        ).fetchone()[0] == 0
        conn.close()

    def test_size_limit_enforced(self, svc):
        client, _ = svc
        r = client.post("/api/uploads", json={"filename": "big.tif", "size": MAX_FILE_SIZE + 1})
        assert r.status_code == 413
        payload = make_tiff(MAX_FILE_SIZE + 1)
        r = client.post("/api/uploads", json={"filename": "big.tif", "size": len(payload)})
        assert r.status_code == 413

    def test_rotation_rewraps_dek_only_and_deletes_old_kek(self, svc, tmp_data):
        client, service = svc
        f1 = _upload(client, make_tiff(1024, 1), "a.tif")
        f2 = _upload(client, make_tiff(2048, 2), "b.tif")

        keys_before = {k["id"]: k for k in client.get("/api/keys").json()}
        old_kek = next(k for k in keys_before.values() if k["status"] == "active")
        blob_before = {}
        for f in client.get("/api/files").json():
            with open(os.path.join(tmp_data, "vault", f["file_id"] + ".blob"), "rb") as fh:
                blob_before[f["file_id"]] = fh.read()

        r = client.post("/api/rotations")
        assert r.status_code == 201
        wait_until(lambda: not client.get("/api/rotations/current").json()["active"])
        status = client.get("/api/rotations/current").json()
        assert status["last"]["rewrapped"] == 2

        # 旧 KEK 文件实际删除，新 KEK 接管；密文原件逐字节未变。
        old_path = os.path.join(tmp_data, "keys", old_kek["key_id"] + ".kek")
        assert not os.path.exists(old_path)
        for f in client.get("/api/files").json():
            assert f["kek_id"] != old_kek["id"]
            with open(os.path.join(tmp_data, "vault", f["file_id"] + ".blob"), "rb") as fh:
                assert fh.read() == blob_before[f["file_id"]]

        # 所有已归档文件仍可解密且内容一致。
        assert _download(client, f1) == make_tiff(1024, 1)
        assert _download(client, f2) == make_tiff(2048, 2)

        keys_after = {k["id"]: k for k in client.get("/api/keys").json()}
        assert keys_after[old_kek["id"]]["status"] == "deleted"
        assert keys_after[old_kek["id"]]["file_exists"] is False

    def test_concurrent_rotation_rejected(self, svc):
        client, service = svc
        _upload(client, make_tiff(512))
        client.post("/api/demo/gates/upload_register", json={"paused": True})
        try:
            # 造一个卡在待登记的上传，使轮换收尾保持 running。
            r = client.post("/api/uploads", json={"filename": "hold.tif", "size": 8})
            uid = r.json()["upload_id"]
            client.put(f"/api/uploads/{uid}/content", content=make_tiff(8, 3))
            t = threading.Thread(target=lambda: client.post(f"/api/uploads/{uid}/complete"))
            t.start()
            wait_until(lambda: service.upload_gate.waiting == 1)

            assert client.post("/api/rotations").status_code == 201
            wait_until(lambda: client.get("/api/rotations/current").json()["active"])
            r2 = client.post("/api/rotations")
            assert r2.status_code == 409

            client.post("/api/demo/gates/upload_register", json={"paused": False})
            t.join(timeout=10)
            wait_until(lambda: not client.get("/api/rotations/current").json()["active"])
        finally:
            client.post("/api/demo/gates/upload_register", json={"paused": False})

    def test_upload_paused_at_register_leaves_no_old_key_reference(self, svc):
        client, service = svc
        _upload(client, make_tiff(700), "before.tif")
        old_kek_id = client.get("/api/rotations/current").json()["active_kek"]["id"]

        client.post("/api/demo/gates/upload_register", json={"paused": True})
        payload = make_tiff(900, 9)
        r = client.post("/api/uploads", json={"filename": "during.tif", "size": len(payload)})
        uid = r.json()["upload_id"]
        assert client.put(f"/api/uploads/{uid}/content", content=payload).status_code == 200

        done = {}
        t = threading.Thread(target=lambda: done.update(
            client.post(f"/api/uploads/{uid}/complete").json()))
        t.start()
        wait_until(lambda: service.upload_gate.waiting == 1)

        # 轮换发起并完成全部重封装，但因待登记上传而停在收尾。
        assert client.post("/api/rotations").status_code == 201
        wait_until(lambda: (
            (s := client.get("/api/rotations/current").json())["active"]
            and s["state"] == "completing"))
        st = client.get("/api/rotations/current").json()
        assert st["blocking_uploads"] == 1

        # 恢复上传：用新 active KEK 封装 DEK 并登记。
        client.post("/api/demo/gates/upload_register", json={"paused": False})
        t.join(timeout=10)
        assert done["state"] == "completed"
        wait_until(lambda: not client.get("/api/rotations/current").json()["active"])

        files = {f["filename"]: f for f in client.get("/api/files").json()}
        assert files["during.tif"]["kek_id"] != old_kek_id
        assert files["before.tif"]["kek_id"] != old_kek_id
        assert _download(client, files["during.tif"]["file_id"]) == payload
        # 旧钥文件已删除，且没有任何 files 行引用它。
        old = next(k for k in client.get("/api/keys").json() if k["id"] == old_kek_id)
        assert old["status"] == "deleted" and old["file_exists"] is False

    def test_download_paused_at_unwrap_must_finish_reading(self, svc, tmp_data):
        client, service = svc
        payload = make_tiff(1500, 5)
        file_id = _upload(client, payload)
        old_kek_id = client.get("/api/rotations/current").json()["active_kek"]["id"]

        client.post("/api/demo/gates/download_unwrap", json={"paused": True})
        r = client.post(f"/api/files/{file_id}/downloads")
        dl_id = r.json()["download_id"]
        result = {}
        t = threading.Thread(target=lambda: result.update(
            client.get(f"/api/downloads/{dl_id}/content").json() if False else
            {"resp": client.get(f"/api/downloads/{dl_id}/content")}))
        t.start()
        wait_until(lambda: service.download_gate.waiting == 1)

        # 轮换期间下载照常受理；收尾必须等这个在途下载。
        assert client.post("/api/rotations").status_code == 201
        wait_until(lambda: (
            (s := client.get("/api/rotations/current").json())["active"]
            and s["state"] == "completing"))
        st = client.get("/api/rotations/current").json()
        assert st["blocking_downloads"] == 1
        old_path = os.path.join(
            tmp_data, "keys",
            next(k["key_id"] for k in client.get("/api/keys").json() if k["id"] == old_kek_id) + ".kek")
        assert os.path.exists(old_path), "在途下载结束前旧钥文件不得删除"

        client.post("/api/demo/gates/download_unwrap", json={"paused": False})
        t.join(timeout=10)
        resp = result["resp"]
        assert resp.status_code == 200
        assert resp.content == payload  # 已受理下载读完原件
        wait_until(lambda: not client.get("/api/rotations/current").json()["active"])
        assert not os.path.exists(old_path)

    def test_uploads_and_downloads_continue_during_rotation(self, svc):
        client, _ = svc
        first = make_tiff(800, 1)
        fid = _upload(client, first)

        errors: list[str] = []
        uploaded: list[str] = []

        def do_uploads():
            try:
                for i in range(3):
                    p = make_tiff(400 + i, 100 + i)
                    uploaded.append(_upload(client, p, f"during{i}.tif"))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"upload: {exc}")

        def do_downloads():
            try:
                for _ in range(3):
                    assert _download(client, fid) == first
            except Exception as exc:  # noqa: BLE001
                errors.append(f"download: {exc}")

        tu = threading.Thread(target=do_uploads)
        td = threading.Thread(target=do_downloads)
        tu.start(); td.start()
        assert client.post("/api/rotations").status_code == 201
        tu.join(timeout=15); td.join(timeout=15)
        assert not errors, errors
        wait_until(lambda: not client.get("/api/rotations/current").json()["active"])
        status = client.get("/api/rotations/current").json()
        # 轮换期间新上传的文件也都封装在新 KEK 上且可解密。
        active_kek = status["active_kek"]["id"]
        for f in client.get("/api/files").json():
            assert f["kek_id"] == active_kek
        for new_id in uploaded:
            assert _download(client, new_id) is not None

    def test_restart_mid_rotation_resumes_and_files_remain_decodable(self, tmp_data, monkeypatch):
        monkeypatch.setenv("ARCHIVE_DATA_DIR", tmp_data)
        payloads = {f"img{i}.tif": make_tiff(300 + i * 17, i) for i in range(4)}
        with TestClient(app) as client:
            ids = {name: _upload(client, p) for name, p in payloads.items()}

        # 第二次启动：发起轮换，并留一个“待登记”上传使收尾阶段无法结束，
        # 然后干净退出进程（不依赖阻塞线程），数据库停在轮换未完成状态。
        with TestClient(app) as client:
            client.post("/api/demo/gates/upload_register", json={"paused": True})
            r = client.post("/api/uploads", json={"filename": "hold.tif", "size": 8})
            uid = r.json()["upload_id"]
            client.put(f"/api/uploads/{uid}/content", content=make_tiff(8, 44))
            assert client.get("/api/uploads").json()[0]["state"] == "pending_register"

            assert client.post("/api/rotations").status_code == 201
            wait_until(lambda: (
                (s := client.get("/api/rotations/current").json())["active"]
                and s["state"] == "completing"))
            st = client.get("/api/rotations/current").json()
            assert st["blocking_uploads"] == 1
            client.post("/api/demo/gates/upload_register", json={"paused": False})
        # 进程退出：待登记上传的内存 DEK 随进程消失，轮换停在未完成状态。

        # 第三次启动：自动续办至完成。
        with TestClient(app) as client:
            wait_until(lambda: (
                (s := client.get("/api/rotations/current").json())["active"] is False
                and s["last"] is not None and s["last"]["state"] == "completed"))
            st = client.get("/api/rotations/current").json()
            assert st["last"]["rewrapped"] == st["last"]["total"] == 4
            for name, p in payloads.items():
                assert _download(client, ids[name]) == p
            # 所有 KEK 文件中只剩当前 active 的一个。
            keys = client.get("/api/keys").json()
            existing = [k for k in keys if k["file_exists"]]
            assert len(existing) == 1 and existing[0]["status"] == "active"

    def test_restart_recovers_pending_upload_and_staging(self, tmp_data, monkeypatch):
        monkeypatch.setenv("ARCHIVE_DATA_DIR", tmp_data)
        payload = make_tiff(600, 11)
        with TestClient(app) as client:
            r = client.post("/api/uploads", json={"filename": "orphan.tif", "size": len(payload)})
            uid = r.json()["upload_id"]
            client.put(f"/api/uploads/{uid}/content", content=payload)
            assert client.get("/api/uploads").json()[0]["state"] == "pending_register"

        with TestClient(app) as client:
            up = client.get("/api/uploads").json()[0]
            assert up["state"] == "failed"
            # 暂存密文已清理，目录无孤儿。
            staging = os.path.join(tmp_data, "staging")
            assert os.listdir(staging) == []
            # 重新上传仍然成功。
            new_id = _upload(client, payload, "orphan.tif")
            assert _download(client, new_id) == payload
