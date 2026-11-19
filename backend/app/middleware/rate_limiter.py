import time
from typing import Dict, Tuple
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from app.config import settings

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_minute: int = 120):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.client_records: Dict[str, Tuple[int, float]] = {}

    async def dispatch(self, request: Request, call_next):
        # Exempt health checks and documentation
        path = request.url.path
        if path in ["/api/health", "/docs", "/openapi.json", "/redoc"]:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        current_time = time.time()

        if client_ip in self.client_records:
            count, start_time = self.client_records[client_ip]
            if current_time - start_time < 60:
                if count >= self.requests_per_minute:
                    return JSONResponse(
                        status_code=429,
                        content={"detail": "Rate limit exceeded. Please wait before making more requests."}
                    )
                self.client_records[client_ip] = (count + 1, start_time)
            else:
                self.client_records[client_ip] = (1, current_time)
        else:
            self.client_records[client_ip] = (1, current_time)

        # Periodic cleanup of old keys
        if len(self.client_records) > 2000:
            self.client_records = {
                ip: rec for ip, rec in self.client_records.items()
                if current_time - rec[1] < 120
            }

        response = await call_next(request)
        return response
