"""FastAPI 路由层与应用入口。

单课题、单进程；所有写操作在 Service 的锁内串行执行。
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Body, FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from . import __version__
from .service import MAX_FILE_SIZE, Service, ServiceError

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

service: Service | None = None


class UploadInit(BaseModel):
    filename: str = Field(..., max_length=200)
    size: int = Field(..., gt=0)


class GateBody(BaseModel):
    paused: bool


@asynccontextmanager
async def lifespan(app: FastAPI):
    global service
    data_dir = os.environ.get("ARCHIVE_DATA_DIR", "/data")
    service = Service(data_dir)
    try:
        yield
    finally:
        service.close()


app = FastAPI(
    title="科研影像加密归档（单课题）",
    version=__version__,
    description="FastAPI + SQLite + cryptography，单进程 TIFF 加密归档与课题密钥轮换",
    lifespan=lifespan,
)


def svc() -> Service:
    assert service is not None, "服务尚未初始化"
    return service


@app.exception_handler(ServiceError)
async def service_error_handler(request: Request, exc: ServiceError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": str(exc)})


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


# --------------------------- 上传（两阶段，含待登记暂停点） --------------------------- #
@app.post("/api/uploads", status_code=201)
def create_upload(body: UploadInit) -> dict[str, Any]:
    return svc().create_upload(body.filename, body.size)


@app.put("/api/uploads/{upload_id}/content")
async def put_upload_content(upload_id: str, request: Request) -> dict[str, Any]:
    content = await request.body()
    return svc().save_upload_content(upload_id, content)


@app.post("/api/uploads/{upload_id}/complete")
def complete_upload(upload_id: str) -> dict[str, Any]:
    return svc().complete_upload(upload_id)


@app.post("/api/uploads/{upload_id}/abort")
def abort_upload(upload_id: str) -> dict[str, Any]:
    return svc().abort_upload(upload_id)


@app.get("/api/uploads")
def list_uploads() -> list[dict[str, Any]]:
    return svc().list_uploads()


# --------------------------- 下载（受理 -> 待解封暂停点 -> 读完原件） --------------------------- #
@app.post("/api/files/{file_id}/downloads", status_code=201)
def accept_download(file_id: str) -> dict[str, Any]:
    return svc().accept_download(file_id)


@app.get("/api/downloads/{download_id}/content")
def open_download(download_id: str) -> Response:
    result = svc().open_download(download_id)
    headers = {
        "Content-Disposition": f'attachment; filename="{result["filename"]}"',
        "X-SHA256": result["sha256"],
    }
    return Response(content=result["content"], media_type="image/tiff", headers=headers)


@app.post("/api/downloads/{download_id}/abort")
def abort_download(download_id: str) -> dict[str, Any]:
    return svc().abort_download(download_id)


@app.get("/api/downloads")
def list_downloads() -> list[dict[str, Any]]:
    return svc().list_downloads()


# --------------------------- 文件与课题密钥 --------------------------- #
@app.get("/api/files")
def list_files() -> list[dict[str, Any]]:
    return svc().list_files()


@app.get("/api/keys")
def list_keys() -> list[dict[str, Any]]:
    return svc().list_keys()


@app.get("/api/config")
def get_config() -> dict[str, Any]:
    return {"max_file_size": MAX_FILE_SIZE, "max_file_size_mib": 8}


# --------------------------- 轮换与进度 --------------------------- #
@app.post("/api/rotations", status_code=201)
def start_rotation() -> dict[str, Any]:
    return svc().start_rotation()


@app.get("/api/rotations/current")
def rotation_status() -> dict[str, Any]:
    return svc().rotation_status()


# --------------------------- 演示暂停门 --------------------------- #
@app.post("/api/demo/gates/{name}")
def set_gate(name: str, body: GateBody = Body(...)) -> dict[str, Any]:
    return svc().set_gate(name, body.paused)
