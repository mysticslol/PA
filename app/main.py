from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.database import init_db
from app.routers import analyse, rapports


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="CodeShield",
    description="Analyse statique de code C et Python avec détection de vulnérabilités",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyse.router, prefix="/api/analyse", tags=["Analyse"])
app.include_router(rapports.router, prefix="/api/rapports", tags=["Rapports"])


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
