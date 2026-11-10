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
