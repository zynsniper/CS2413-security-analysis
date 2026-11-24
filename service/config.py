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

    # Password storage scheme: "argon2id" (default), "bcrypt", or "md5" (insecure,
    # for the before/after storage comparison only).
    HASH_SCHEME = os.environ.get("HASH_SCHEME", "argon2id")

    # --- Defence flags --------------------------------------------------------
    # The three implemented defences default to ON so the service demonstrates
    # them with no extra setup. Turn one off per run to capture a "before"
    # screenshot, e.g.  POLICY_ENABLED=0 flask --app app run
    LOCKOUT_ENABLED = _bool(os.environ.get("LOCKOUT_ENABLED"), True)         # [Omar]
    RATE_LIMIT_ENABLED = _bool(os.environ.get("RATE_LIMIT_ENABLED"), True)   # [Omar]
    POLICY_ENABLED = _bool(os.environ.get("POLICY_ENABLED"), True)           # [Bunthong]
    # MFA stays OFF until enrolment exists: nothing writes users.totp_secret,
    # so mfa_required() can never fire, and turning this on would also drop the
    # policy minimum from 15 to 8 characters (see register() in app.py).
    MFA_ENABLED = _bool(os.environ.get("MFA_ENABLED"), False)                # [Kimse]

    # Settings the teammates' mechanisms will read (kept here so all numbers live
    # in one place and match report/2-methodology.md).
    LOCKOUT_MAX_FAILURES = 5
    LOCKOUT_SECONDS = 300            # 5 minutes
    RATE_LIMIT_PER_MIN = 30         # per IP
    POLICY_MIN_LENGTH = 15          # 8 when MFA is enabled
    POLICY_MIN_LENGTH_WITH_MFA = 8
