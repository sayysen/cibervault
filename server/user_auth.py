"""
Cibervault EDR — User Authentication & Authorization
JWT-based auth with bcrypt passwords and RBAC roles.
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import aiosqlite
from jose import JWTError, jwt
from fastapi import HTTPException, Header, Depends

from database import DB

log = logging.getLogger("cibervault.user_auth")

# ─── JWT config ───────────────────────────────────────────────────────────────
JWT_SECRET    = os.getenv("JWT_SECRET", "cibervault-jwt-secret-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_H  = int(os.getenv("JWT_EXPIRE_HOURS", "12"))

ROLES = ["admin", "analyst", "responder", "viewer"]


# ─── Password helpers ─────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# ─── JWT helpers ──────────────────────────────────────────────────────────────

def create_jwt(user_id: int, username: str, role: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRE_H)
    return jwt.encode(
        {"sub": str(user_id), "username": username, "role": role, "exp": expire},
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )

def decode_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

def get_current_user(authorization: str = Header(...)) -> dict:
    """FastAPI dependency — extracts current user from Bearer token."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    return decode_jwt(authorization[7:])

def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user

def require_analyst(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") not in ("admin", "analyst", "responder"):
        raise HTTPException(status_code=403, detail="Analyst role required")
    return user


# ─── User DB operations ───────────────────────────────────────────────────────

async def create_default_admin():
    """Create default admin user on first run if no users exist."""
    async with aiosqlite.connect(DB) as db:
        cur = await db.execute("SELECT COUNT(*) FROM users")
        count = (await cur.fetchone())[0]
        if count == 0:
            default_pass = os.getenv("ADMIN_PASSWORD", "Cibervault@2025!")
            hashed = hash_password(default_pass)
            await db.execute("""
                INSERT INTO users (username, email, password_hash, role,
                                   full_name, active, created_at, last_login)
                VALUES (?,?,?,?,?,1,?,NULL)
            """, ("admin", "admin@cibervault.local", hashed, "admin",
                  "System Administrator", datetime.utcnow().isoformat()))
            await db.commit()
            log.info(f"Default admin created — username: admin, password: {default_pass}")
            log.warning("CHANGE THE DEFAULT PASSWORD IMMEDIATELY via Settings → Users")

async def authenticate_user(username: str, password: str) -> Optional[dict]:
    """Verify credentials and return user dict or None."""
    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM users WHERE username=? AND active=1", (username,)
        )
        user = await cur.fetchone()
    if not user:
        return None
    user = dict(user)
    if not verify_password(password, user["password_hash"]):
        return None
    # Update last_login
    async with aiosqlite.connect(DB) as db:
        await db.execute(
            "UPDATE users SET last_login=? WHERE id=?",
            (datetime.utcnow().isoformat(), user["id"])
        )
        await db.commit()
    return user

async def get_all_users() -> list[dict]:
    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT id, username, email, role, full_name, active, created_at, last_login FROM users ORDER BY id"
        )
        rows = await cur.fetchall()
    return [dict(r) for r in rows]

async def create_user(username: str, email: str, password: str,
                      role: str, full_name: str) -> int:
    if role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {ROLES}")
    hashed = hash_password(password)
    async with aiosqlite.connect(DB) as db:
        try:
            cur = await db.execute("""
                INSERT INTO users (username, email, password_hash, role,
                                   full_name, active, created_at)
                VALUES (?,?,?,?,?,1,?)
            """, (username, email, hashed, role, full_name,
                  datetime.utcnow().isoformat()))
            await db.commit()
            return cur.lastrowid
        except Exception as e:
            if "UNIQUE" in str(e):
                raise HTTPException(status_code=409, detail="Username or email already exists")
            raise

async def update_user(user_id: int, data: dict) -> bool:
    fields, values = [], []
    allowed = {"email", "role", "full_name", "active"}
    for k, v in data.items():
        if k in allowed:
            fields.append(f"{k}=?")
            values.append(v)
    if "password" in data and data["password"]:
        fields.append("password_hash=?")
        values.append(hash_password(data["password"]))
    if not fields:
        return False
    values.append(user_id)
    async with aiosqlite.connect(DB) as db:
        await db.execute(f"UPDATE users SET {','.join(fields)} WHERE id=?", values)
        await db.commit()
    return True

async def delete_user(user_id: int, requesting_user_id: int):
    if user_id == requesting_user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    async with aiosqlite.connect(DB) as db:
        await db.execute("UPDATE users SET active=0 WHERE id=?", (user_id,))
        await db.commit()
