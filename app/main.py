"""DLP Engine - FastAPI 入口（端口 5037）"""

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from . import init_db
from .api.routes import router as api_router

ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT / "static"

app = FastAPI(
    title="Enterprise DLP Policy Simulation & Data Classification Engine",
    version="0.1.0",
    description="4 级分类分级 + 多通道 DLP 检测 + ServiceNow + SIEM CEF",
)


@app.on_event("startup")
def _startup():
    init_db()


@app.get("/health")
async def health():
    return {"status": "ok", "service": "dlp-engine", "version": "0.1.0"}


app.include_router(api_router, prefix="/api")


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/")
    async def index():
        idx = STATIC_DIR / "index.html"
        if idx.exists():
            return FileResponse(str(idx))
        return {"msg": "static/index.html not found"}
else:
    @app.get("/")
    async def index():
        return {"msg": "static dir not built", "docs": "/docs"}


def run():
    import uvicorn
    port = int(os.environ.get("WEB_PORT", "5037"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    run()
