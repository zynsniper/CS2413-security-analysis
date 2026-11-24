"""Central configuration and feature flags for the login service.

Each defence is a flag so it can be switched on or off, which is what lets us
measure its effect in a controlled before/after experiment. Chi builds the base
(hashing always on); each teammate turns on and implements their own flag:

    LOCKOUT_ENABLED / RATE_LIMIT_ENABLED  -> Omar
    POLICY_ENABLED                        -> Bunthong
    MFA_ENABLED                           -> Kimse
"""
from __future__ import annotations

import os


def _bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")
    DB_PATH = os.environ.get("DB_PATH", "app.db")

    HASH_SCHEME = os.environ.get("HASH_SCHEME", "argon2id")

    LOCKOUT_ENABLED = _bool(os.environ.get("LOCKOUT_ENABLED"), True)         # [Omar]
    RATE_LIMIT_ENABLED = _bool(os.environ.get("RATE_LIMIT_ENABLED"), True)   # [Omar]
    POLICY_ENABLED = _bool(os.environ.get("POLICY_ENABLED"), True)           # [Bunthong]

    MFA_ENABLED = _bool(os.environ.get("MFA_ENABLED"), False)                # [Kimse]

    LOCKOUT_MAX_FAILURES = 5
    LOCKOUT_SECONDS = 300            # 5 minutes
    RATE_LIMIT_PER_MIN = 30         # per IP
    POLICY_MIN_LENGTH = 15          # 8 when MFA is enabled,  15 mimimum length password
    POLICY_MIN_LENGTH_WITH_MFA = 8
