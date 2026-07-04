import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import router
from db import init_db

app = FastAPI(title="Kryx API", version="0.4.0")

# CORS - restrict to configured origins instead of a wildcard.
# Set CORS_ORIGINS as a comma-separated list in prod (e.g. https://app.kryx.io).
_origins_env = os.getenv("CORS_ORIGINS") or os.getenv("FRONTEND_URL") or "http://localhost:3000"
ALLOWED_ORIGINS = [o.strip() for o in _origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(router, prefix="/api")


@app.on_event("startup")
async def startup():
    await init_db()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
