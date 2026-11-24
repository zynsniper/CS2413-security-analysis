"""SQLite storage for users (Chi's part).

One table. `totp_secret` is nullable and stays empty until Kimse's MFA work fills
it; the column exists now so his part doesn't require a schema migration.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT UNIQUE NOT NULL,
    pw_hash     TEXT NOT NULL,
    totp_secret TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


@contextmanager
def connect(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: str) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


def create_user(db_path: str, username: str, pw_hash: str, totp_secret: str | None = None) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO users (username, pw_hash, totp_secret) VALUES (?, ?, ?)",
            (username, pw_hash, totp_secret),
        )
        return cur.lastrowid


def get_user(db_path: str, username: str):
    with connect(db_path) as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def user_exists(db_path: str, username: str) -> bool:
    return get_user(db_path, username) is not None
