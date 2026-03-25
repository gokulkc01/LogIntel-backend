from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv
import os

load_dotenv()

from routers.analyze import router

limiter = Limiter(key_func=get_remote_address, default_limits=["30/minute"])

_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173")

if _raw_origins.strip() == "*":
    _origins = ["*"]
    _allow_credentials = False
else:
    _origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]
    _allow_credentials = True


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[startup] CORS origins: {_origins}")
    print(f"[startup] Docs at /api/docs")
    yield
    print("[shutdown] Cleaning up...")


app = FastAPI(
    title="AI Secure Data Intelligence Platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

MAX_CONTENT_BYTES = 10 * 1024 * 1024

@app.middleware("http")
async def limit_upload_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_CONTENT_BYTES:
        return JSONResponse(
            status_code=413,
            content={
                "error": "Payload too large",
                "max_size_mb": 10,
                "detail": "Log file exceeds 10MB limit. Split into smaller files."
            }
        )
    return await call_next(request)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)

app.include_router(router, prefix="/api")

@app.get("/", include_in_schema=False)
async def root():
    return {"status": "ok", "service": "AI Secure Data Intelligence Platform"}