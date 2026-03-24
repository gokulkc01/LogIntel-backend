from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from routers.analyze import router

limiter = Limiter(key_func=get_remote_address, default_limits=["30/minute"])

app = FastAPI(title="AI Secure Data Intelligence Platform", version="1.0.0")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# File size guard — reject anything over 10MB before it hits a route
MAX_CONTENT_BYTES = 10 * 1024 * 1024  # 10 MB

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
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")