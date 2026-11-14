"""SQLite schema 与连接初始化。"""

from __future__ import annotations

import sqlite3

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=FULL;

-- 课题密钥（KEK）。密钥字节本身保存在独立目录 keys/ 的文件中，
-- 数据库只记录元数据与路径，密文目录 vault/ 中不出现任何密钥材料。
CREATE TABLE IF NOT EXISTS project_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id     TEXT UNIQUE NOT NULL,
    path       TEXT NOT NULL,
    status     TEXT NOT NULL CHECK (status IN ('active', 'rotating', 'deleted')),
    created_at TEXT NOT NULL,
    deleted_at TEXT
);

-- 已归档影像。blob_path 指向 vault/ 下的密文文件（nonce || ciphertext||tag）；
-- wrapped_dek 是被当前 KEK 封装的 DEK，轮换只改这两列，密文原件不动。
CREATE TABLE IF NOT EXISTS files (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id       TEXT UNIQUE NOT NULL,
    filename      TEXT NOT NULL,
    size          INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    blob_path     TEXT NOT NULL,
    nonce         BLOB NOT NULL,
    current_kek_id INTEGER NOT NULL REFERENCES project_keys(id),
    wrapped_dek   BLOB NOT NULL,
    dek_nonce     BLOB NOT NULL,
    created_at    TEXT NOT NULL
);

-- 上传会话：created -> pending_register -> completed
-- 暂停点“上传待登记”即 pending_register，此时 DEK 仅在内存，密文在 staging/。
CREATE TABLE IF NOT EXISTS uploads (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    upload_id     TEXT UNIQUE NOT NULL,
    filename      TEXT NOT NULL,
    declared_size INTEGER NOT NULL,
    sha256        TEXT,
    staging_path  TEXT,
    nonce         BLOB,
    state         TEXT NOT NULL CHECK (state IN (
                      'created', 'pending_register', 'completed', 'aborted', 'failed')),
    file_id       INTEGER REFERENCES files(id),
    error         TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

-- 下载会话：accepted -> unwrapping -> completed
-- 受理时快照该文件当时的 KEK 标识与封装 DEK，保证轮换重封装后在途下载仍可读完；
-- 到达终态后立即清空封装材料，避免已删除 KEK 留下可审计的旧钥引用。
CREATE TABLE IF NOT EXISTS downloads (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    download_id  TEXT UNIQUE NOT NULL,
    file_id      INTEGER NOT NULL REFERENCES files(id),
    kek_id       INTEGER NOT NULL REFERENCES project_keys(id),
    wrapped_dek  BLOB,
    dek_nonce    BLOB,
    nonce        BLOB,
    state        TEXT NOT NULL CHECK (state IN (
                     'accepted', 'unwrapping', 'completed', 'interrupted', 'aborted')),
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

-- 密钥轮换：running（重封装中）-> completing（等待在途会话收尾）-> completed。
CREATE TABLE IF NOT EXISTS rotations (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    rotation_id         TEXT UNIQUE NOT NULL,
    old_kek_id          INTEGER NOT NULL REFERENCES project_keys(id),
    new_kek_id          INTEGER NOT NULL REFERENCES project_keys(id),
    state               TEXT NOT NULL CHECK (state IN (
                            'running', 'completing', 'completed')),
    total               INTEGER NOT NULL,
    rewrapped           INTEGER NOT NULL,
    blocking_uploads    INTEGER NOT NULL DEFAULT 0,
    blocking_downloads  INTEGER NOT NULL DEFAULT 0,
    started_at          TEXT NOT NULL,
    completed_at        TEXT,
    message             TEXT
);
"""


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.executescript(SCHEMA)
    return conn
