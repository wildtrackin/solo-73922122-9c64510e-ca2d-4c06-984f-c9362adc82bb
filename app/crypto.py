"""加密原语：AES-256-GCM。

- 每件影像使用独立随机数据密钥 DEK 加密原件；
- DEK 由课题密钥 KEK 以 AES-GCM 封装后落库；
- KEK 明文只存在于内存与 keys/ 目录的独立密钥文件中，
  与 vault/ 下的密文分目录持久保存。
"""

from __future__ import annotations

import os
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEK_SIZE = 32
DEK_SIZE = 32
NONCE_SIZE = 12

# 带版本号的固定 AAD，区分“封装 DEK”和“加密原件”两类 GCM 消息。
WRAP_AAD = b"tiff-archive:wrap-dek:v1"
BLOB_AAD = b"tiff-archive:blob:v1"

KEK_MAGIC = b"TIFFARCHIVE-KEK-v1\n"


def new_kek() -> bytes:
    return os.urandom(KEK_SIZE)


def new_dek() -> bytes:
    """每件影像独立的随机数据密钥。"""
    return os.urandom(DEK_SIZE)


def new_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)


def encrypt_blob(dek: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """用 DEK 加密原件明文，返回含 GCM 认证标签的密文。"""
    if len(nonce) != NONCE_SIZE:
        raise ValueError("nonce 长度必须为 12 字节")
    return AESGCM(dek).encrypt(nonce, plaintext, BLOB_AAD)


def decrypt_blob(dek: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """用 DEK 解密密文，标签校验失败会抛 InvalidTag。"""
    return AESGCM(dek).decrypt(nonce, ciphertext, BLOB_AAD)


def wrap_dek(kek: bytes, nonce: bytes, dek: bytes) -> bytes:
    """用课题密钥封装数据密钥。"""
    if len(dek) != DEK_SIZE:
        raise ValueError("DEK 长度必须为 32 字节")
    return AESGCM(kek).encrypt(nonce, dek, WRAP_AAD)


def unwrap_dek(kek: bytes, nonce: bytes, wrapped_dek: bytes) -> bytes:
    """用课题密钥解封数据密钥。"""
    dek = AESGCM(kek).decrypt(nonce, wrapped_dek, WRAP_AAD)
    if len(dek) != DEK_SIZE:
        raise ValueError("解封得到的 DEK 长度异常")
    return dek


def save_kek_file(path: str, kek: bytes) -> None:
    """原子写入课题密钥文件，权限 600；明文密钥只允许出现在这里和内存。"""
    if len(kek) != KEK_SIZE:
        raise ValueError("KEK 长度必须为 32 字节")
    tmp = f"{path}.tmp-{uuid.uuid4().hex}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(KEK_MAGIC)
            f.write(kek)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _fsync_dir(os.path.dirname(path))
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_kek_file(path: str) -> bytes:
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(KEK_MAGIC) or len(data) != len(KEK_MAGIC) + KEK_SIZE:
        raise ValueError(f"课题密钥文件格式错误: {path}")
    return data[len(KEK_MAGIC):]


def _fsync_dir(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
