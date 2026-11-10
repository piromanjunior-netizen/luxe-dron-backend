
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="LUXE DRON License API", version="1.0.0")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")

HEARTBEAT_SECONDS = 60
SESSION_TIMEOUT_SECONDS = 180

# Komendy, których nie zapisujemy.
BLOCKED_COMMANDS = {
    "password", "passwd", "auth",
    "pin", "otp", "2fa", "verify",
    "msg", "message", "tell", "whisper",
    "w", "reply", "r", "pm",
    "spawn", "home", "sethome", "delhome",
    "warp", "tpa", "tpaccept", "tpdeny",
    "back", "kit", "shop", "balance", "bal", "pay"
}


def db():
    if not DATABASE_URL:
        raise HTTPException(
            status_code=503,
            detail="DATABASE_URL is not configured"
        )

    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row
    )


def key_hash(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def require_admin(key: Optional[str]):
    if (
        not ADMIN_API_KEY
        or not key
        or not secrets.compare_digest(key, ADMIN_API_KEY)
    ):
        raise HTTPException(
            status_code=403,
            detail="Admin access denied"
        )


def valid_license(conn, raw_key: str):
    row = conn.execute(
        """
        SELECT revoked, expires_at
        FROM licenses
        WHERE key_hash = %s
        """,
        (key_hash(raw_key),)
    ).fetchone()

    if row is None or row["revoked"]:
        return False

    expires_at = row["expires_at"]

    if expires_at is not None:
        if expires_at <= datetime.now(timezone.utc):
            return False

    return True


@app.on_event("startup")
def startup():
    if not DATABASE_URL:
        return

    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                key_hash TEXT PRIMARY KEY,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ,
                revoked BOOLEAN NOT NULL DEFAULT FALSE
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id BIGSERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                player_uuid TEXT NOT NULL,
                mod_version TEXT,
                started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                ended_at TIMESTAMPTZ,
                active BOOLEAN NOT NULL DEFAULT TRUE
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id BIGSERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                player_uuid TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_text TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)


class ActivateRequest(BaseModel):
    license_key: str = Field(min_length=8, max_length=128)
    username: str = Field(min_length=1, max_length=32)
    player_uuid: str = Field(min_length=1, max_length=64)
    mod_version: str = Field(default="unknown", max_length=32)


class HeartbeatRequest(BaseModel):
    license_key: str = Field(min_length=8, max_length=128)
    player_uuid: str = Field(min_length=1, max_length=64)


class EventRequest(BaseModel):
    license_key: str = Field(min_length=8, max_length=128)
    username: str = Field(min_length=1, max_length=32)
    player_uuid: str = Field(min_length=1, max_length=64)
    event_type: str = Field(default="command", max_length=32)
    event_text: str = Field(min_length=1, max_length=300)


class CreateLicenseRequest(BaseModel):
    expires_in_days: Optional[int] = Field(
        default=None,
        ge=1,
        le=3650
    )


@app.get("/")
def root():
    return {
        "service": "LUXE DRON License API",
        "status": "ok"
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/activate")
def activate(data: ActivateRequest):
    with db() as conn:
        if not valid_license(conn, data.license_key):
            raise HTTPException(
                status_code=403,
                detail="Invalid or expired license"
            )

        conn.execute("""
            UPDATE sessions
            SET active = FALSE, ended_at = NOW()
            WHERE player_uuid = %s AND active = TRUE
        """, (data.player_uuid,))

        row = conn.execute("""
            INSERT INTO sessions (
                username,
                player_uuid,
                mod_version
            )
            VALUES (%s, %s, %s)
            RETURNING id
        """, (
            data.username,
            data.player_uuid,
            data.mod_version
        )).fetchone()

        return {
            "ok": True,
            "session_id": row["id"],
            "heartbeat_seconds": HEARTBEAT_SECONDS
        }


@app.post("/api/heartbeat")
def heartbeat(data: HeartbeatRequest):
    with db() as conn:
        if not valid_license(conn, data.license_key):
            raise HTTPException(
                status_code=403,
                detail="Invalid or expired license"
            )

        row = conn.execute("""
            UPDATE sessions
            SET last_seen = NOW()
            WHERE player_uuid = %s
              AND active = TRUE
              AND last_seen >= NOW() - (%s * INTERVAL '1 second')
            RETURNING id
        """, (
            data.player_uuid,
            SESSION_TIMEOUT_SECONDS
        )).fetchone()

        if row is None:
            raise HTTPException(
                status_code=403,
                detail="Session is not active"
            )

        return {"ok": True}


def extract_command(raw_text: str):
    parts = raw_text.strip().split()

    if not parts:
        return None

    first = parts[0]

    if not first.startswith("/"):
        return None

    command = first[1:].lower()

    if ":" in command:
        command = command.rsplit(":", 1)[-1]

    if not command:
        return None

    if not all(c.isalnum() or c == "_" for c in command):
        return None

    return command


@app.post("/api/events")
def create_event(data: EventRequest):
    with db() as conn:
        if not valid_license(conn, data.license_key):
            raise HTTPException(
                status_code=403,
                detail="Invalid or expired license"
            )

        if data.event_type.lower() != "command":
            return {"ok": True, "stored": False}

        command = extract_command(data.event_text)

        if command is None or command in BLOCKED_COMMANDS:
            return {"ok": True, "stored": True}

        # Zapisujemy tylko nazwę komendy, nigdy jej argumenty.
        safe_text = "/" + command

        conn.execute("""
            INSERT INTO events (
                username,
                player_uuid,
                event_type,
                event_text
            )
            VALUES (%s, %s, 'command', %s)
        """, (
            data.username,
            data.player_uuid,
            safe_text
        ))

        return {
            "ok": True,
            "stored": True
        }


@app.post("/admin/licenses")
def create_license(
    data: CreateLicenseRequest,
    x_admin_key: Optional[str] = Header(
        default=None,
        alias="X-Admin-Key"
    )
):
    require_admin(x_admin_key)

    raw_key = "LUXE-" + secrets.token_urlsafe(24)

    expires_at = None

    if data.expires_in_days is not None:
        expires_at = (
            datetime.now(timezone.utc)
            + timedelta(days=data.expires_in_days)
        )

    with db() as conn:
        conn.execute("""
            INSERT INTO licenses (key_hash, expires_at)
            VALUES (%s, %s)
        """, (
            key_hash(raw_key),
            expires_at
        ))

    return {
        "license_key": raw_key,
        "warning": "Skopiuj klucz teraz. Baza przechowuje wyłącznie jego hash."
    }


@app.get("/admin/sessions")
def list_sessions(
    x_admin_key: Optional[str] = Header(
        default=None,
        alias="X-Admin-Key"
    )
):
    require_admin(x_admin_key)

    with db() as conn:
        rows = conn.execute("""
            SELECT
                username,
                player_uuid,
                mod_version,
                started_at,
                last_seen,
                active
            FROM sessions
            ORDER BY started_at DESC
            LIMIT 500
        """).fetchall()

    return rows


@app.get("/admin/events")
def list_events(
    x_admin_key: Optional[str] = Header(
        default=None,
        alias="X-Admin-Key"
    )
):
    require_admin(x_admin_key)

    with db() as conn:
        rows = conn.execute("""
            SELECT
                username,
                player_uuid,
                event_type,
                event_text,
                created_at
            FROM events
            ORDER BY created_at DESC
            LIMIT 1000
        """).fetchall()

    return rows


@app.post("/admin/licenses/{license_key}/revoke")
def revoke_license(
    license_key: str,
    x_admin_key: Optional[str] = Header(
        default=None,
        alias="X-Admin-Key"
    )
):
    require_admin(x_admin_key)

    with db() as conn:
        row = conn.execute("""
            UPDATE licenses
            SET revoked = TRUE
            WHERE key_hash = %s
            RETURNING key_hash
        """, (key_hash(license_key),)).fetchone()

        if row is None:
            raise HTTPException(
                status_code=404,
                detail="License not found"
            )

    return {"ok": True}
