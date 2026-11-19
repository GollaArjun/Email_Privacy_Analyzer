import logging
import asyncio
import httpx
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database.mongo import db_manager, get_reports_col
from app.middleware.rate_limiter import RateLimitMiddleware
from app.routes import auth, analyze, reports, gmail, dashboard, settings as settings_routes, threats
from app.services.threat_intel.source_manager import threat_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("epa.main")

async def _background_threat_sync_worker():
    """Periodic worker executing automated threat synchronization every 15 minutes."""
    while True:
        try:
            await asyncio.sleep(900)  # 15 minutes
            logger.info("Executing periodic automated threat intelligence synchronization...")
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, threat_manager.sync_all)
            logger.info("Periodic automated threat synchronization complete.")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in periodic threat sync worker: {e}")
            await asyncio.sleep(60)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Email Security & Cyber Threat Intelligence Platform...")
    # Synchronize real-world threat feeds on startup (CISA KEV, OpenPhish, CERT-In, Incidents)
    try:
        logger.info("Synchronizing live cyber threat intelligence feeds...")
        threat_manager.sync_all()
        logger.info("Live threat intelligence feeds synchronized successfully.")
    except Exception as e:
        logger.warning(f"Initial threat intelligence feed sync notice: {e}")

    # Launch periodic background threat sync worker
    sync_worker_task = asyncio.create_task(_background_threat_sync_worker())

    yield

    sync_worker_task.cancel()
    try:
        await sync_worker_task
    except asyncio.CancelledError:
        pass
    logger.info("Threat Intelligence Platform shutting down.")

app = FastAPI(
    title="Email Security & Cyber Threat Intelligence Platform",
    version=settings.APP_VERSION,
    description="Enterprise Cybersecurity, Privacy Analyzer, and Real-Time Threat Intelligence Platform",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate Limiter
app.add_middleware(RateLimitMiddleware, requests_per_minute=settings.RATE_LIMIT_PER_MINUTE)

# Include Routers
app.include_router(auth.router)
app.include_router(analyze.router)
app.include_router(reports.router)
app.include_router(gmail.router)
app.include_router(dashboard.router)
app.include_router(settings_routes.router)
app.include_router(threats.router)

@app.get("/api/health", tags=["System"])
async def health_check():
    """System health check and connected security services telemetry."""
    # Check Ollama status
    ollama_online = False
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            res = await client.get(f"{settings.OLLAMA_HOST}/api/tags")
            if res.status_code == 200:
                ollama_online = True
    except Exception:
        ollama_online = False

    return {
        "status": "healthy",
        "app_name": "Email Security & Cyber Threat Intelligence Platform",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": {
            "connected": True,
            "mode": "in-memory-mock" if db_manager.is_mock else "mongodb-live"
        },
        "services": {
            "presidio_analyzer": "active",
            "ollama_llm": "online" if ollama_online else "offline (heuristic security engine active)",
            "google_oauth": "configured" if bool(settings.GOOGLE_CLIENT_ID) else "simulation-demo-mode",
            "threat_intelligence": {
                "sources_registered": len(threat_manager.sources),
                "last_sync": threat_manager.last_full_sync
            }
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
