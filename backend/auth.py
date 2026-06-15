"""
Kryx Auth — JWT регистрация, логин, middleware
"""
import os
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db import User, get_db

def _load_secret_key() -> str:
    """Load JWT secret. Never fall back to a shared hardcoded default — a known
    key lets anyone forge tokens. Require a strong key in prod; in dev, mint a
    random ephemeral one (tokens won't survive a restart, which is fine)."""
    key = os.getenv("SECRET_KEY")
    weak_defaults = {
        "change-me",
        "change-me-in-production-use-32-chars-min",
        "change-me-to-random-32-char-string",
    }
    if key and key not in weak_defaults and len(key) >= 32:
        return key
    if os.getenv("ENV", "dev").lower() in ("prod", "production"):
        raise RuntimeError(
            "SECRET_KEY is missing, weak, or a known default. Set a strong "
            "(>=32 char) SECRET_KEY env var. Generate: python -c "
            "'import secrets; print(secrets.token_urlsafe(48))'"
        )
    import secrets as _secrets
    print("[auth] WARNING: SECRET_KEY not set — using a random ephemeral key "
          "(dev only; tokens reset on restart).")
    return _secrets.token_urlsafe(48)


SECRET_KEY = _load_secret_key()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))  # 24h

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer()


# ── Schemas ────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: int
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


# ── Helpers ────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


def create_token(user_id: int) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": str(user_id), "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


# ── Dependency: current user ───────────────────────────────

async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise exc

    user = await db.get(User, user_id)
    if not user:
        raise exc
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


# ── Route handlers (imported into routes.py) ──────────────

async def register(req: RegisterRequest, db: AsyncSession) -> TokenResponse:
    existing = await db.scalar(select(User).where(User.email == req.email))
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    user = User(email=req.email, hashed_password=hash_password(req.password))
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return TokenResponse(access_token=create_token(user.id))


async def login(req: LoginRequest, db: AsyncSession) -> TokenResponse:
    user = await db.scalar(select(User).where(User.email == req.email))
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return TokenResponse(access_token=create_token(user.id))
