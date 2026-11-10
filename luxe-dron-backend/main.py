
import hashlib
import os
import secrets
from datetime import datetime, timezone

import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="LUXE DRON License API", version="1.0.0")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")


def db():
    if not DATABASE_URL:
        raise HTTPException(503, "DATABASE_URL is not configured")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def require_admin(key: str | None):
    if not ADMIN_API_KEY or not key or not secrets.compare_digest(key, ADMIN_API_KEY):
        raise HTTPException(403, "Admin access denied")


def key_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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


def valid_license(conn, raw_key: str):
    row = conn.execute(
        "SELECT revoked, expires_at FROM licenses WHERE key_hash = %s",
        (key_hash(raw_key),),
    ).fetchone()

    if not row or row["revoked"]:
        return False

    return (
        row["expires_at"] is None
        or row["expires_at"] > datetime.now(timezone.utc)
    )


@app.get("/")
def root():
    return {"service": "LUXE DRON License API", "status": "ok"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/activate")
def activate(data: ActivateRequest):
    with db() as conn:
        if not valid_license(conn, data.license_key):
            raise HTTPException(403, "Invalid or expired license")

        conn.execute(
            """
            UPDATE sessions
            SET active = FALSE, ended_at = NOW()
            WHERE player_uuid = %s AND active = TRUE
            """,
            (data.player_uuid,),
        )

        row = conn.execute(
            """
            INSERT INTO sessions (username, player_uuid, mod_version)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (data.username, data.player_uuid, data.mod_version),
        ).fetchone()

        return {
            "ok": True,
            "session_id": row["id"],
            "heartbeat_seconds": 60,
        }


@app.post("/api/heartbeat")
def heartbeat(data: HeartbeatRequest):
    with db() as conn:
        if not valid_license(conn, data.license_key):
            raise HTTPException(403, "Invalid or expired license")

        row = conn.execute(
            """
            UPDATE sessions
            SET last_seen = NOW()
            WHERE player_uuid = %s AND active = TRUE
            RETURNING id
            """,
            (data.player_uuid,),
        ).fetchone()

        if not row:
            raise HTTPException(404, "Session not found")

        return {"ok": True}


@app.post("/api/events")
def create_event(data: EventRequest):
    with db() as conn:
        if not valid_license(conn, data.license_key):
            raise HTTPException(403, "Invalid or expired license")

        if data.event_type.lower() != "command":
            return {"ok": True, "stored": False}

        raw_text = data.event_text.strip()

        if not raw_text.startswith("/"):
            return {"ok": True, "stored": False}

        parts = raw_text.split()
        if not parts:
            return {"ok": True, "stored": False}

        command = parts[0].lower().split("@", 1)[0]
        command = command.rsplit(":", 1)[-1].lstrip("/")

        blocked = {
"spawn", "home", "sethome", "delhome", "homes",
"warp", "warps", "setwarp",
"tpa", "tpaccept", "tpdeny", "tpahere", "back",
"balance", "bal", "pay", "baltop", "money",
"kit", "kits", "rtp", "wild",
"help", "rules", "list", "who", "ping",
"spawner", "shop", "sell", "ah", "auction"
            
        }

        if command in blocked:
            return {"ok": True, "stored": False}

        sensitive_commands = {
    "changepassword", "setpassword"
}

if command in sensitive_commands:
    safe_text = "/" + command
    if len(parts) > 1:
        safe_text += " [ARGUMENT UKRYTY]"
else:
    safe_text = raw_text[:300]

        conn.execute(
            """
            INSERT INTO events
            (username, player_uuid, event_type, event_text)
            VALUES (%s, %s, %s, %s)
            """,
            (
                data.username,
                data.player_uuid,
                "command",
                safe_text,
            ),
        )

        return {"ok": True, "stored": True}


@app.post("/admin/licenses")
def create_license(x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)

    raw = "LUXE-" + secrets.token_urlsafe(24)

    with db() as conn:
        conn.execute(
            "INSERT INTO licenses (key_hash) VALUES (%s)",
            (key_hash(raw),),
        )

    return {
        "license_key": raw,
        "warning": "Copy this key now. It is stored as a hash and cannot be displayed again.",
    }


@app.get("/admin/sessions")
def list_sessions(x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)

    with db() as conn:
        conn.execute("""
            UPDATE sessions
            SET active = FALSE, ended_at = NOW()
            WHERE active = TRUE
            AND last_seen < NOW() - INTERVAL '3 minutes'
        """)

        rows = conn.execute("""
            SELECT username, player_uuid, mod_version,
                   started_at, last_seen, active
            FROM sessions
            ORDER BY last_seen DESC
            LIMIT 500
        """).fetchall()

        return rows


@app.get("/admin/events")
def list_events(x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)

    with db() as conn:
        rows = conn.execute("""
            SELECT username, player_uuid, event_type,
                   event_text, created_at
            FROM events
            ORDER BY created_at DESC
            LIMIT 1000
        """).fetchall()

        return rows


@app.post("/admin/licenses/{license_key}/revoke")
def revoke_license(
    license_key: str,
    x_admin_key: str | None = Header(default=None),
):
    require_admin(x_admin_key)

    with db() as conn:
        cur = conn.execute(
            "UPDATE licenses SET revoked = TRUE WHERE key_hash = %s",
            (key_hash(license_key),),
        )

        if cur.rowcount == 0:
            raise HTTPException(404, "License not found")

    return {"ok": True}
