"""Integration seams for the three add-on defences.

Each function is a safe no-op while its flag is off, so the base app runs on its
own. The named owner replaces the body and flips the matching flag in config.py.
Keeping the seams here means app.py never has to be restructured.
"""
from __future__ import annotations

import math
import unicodedata
from collections import deque
from functools import lru_cache
from pathlib import Path
from threading import RLock

from flask import current_app, has_app_context

from config import Config


# In-memory state for the single-process local demonstration.
_login_failures: dict[str, int] = {}
_locked_until: dict[str, float] = {}
_ip_attempts: dict[str, deque[float]] = {}
_state_lock = RLock()


def _setting(name):
    """Read configuration from the active Flask application."""
    if has_app_context():
        return current_app.config[name]
    return getattr(Config, name)


def reset_login_controls():
    """Clear login-control state between tests and experiments."""
    with _state_lock:
        _login_failures.clear()
        _locked_until.clear()
        _ip_attempts.clear()


# ---------------------------------------------------- Bunthong: password policy
# NIST SP 800-63B-4: 15-64 characters (8 with MFA), blocklist check, no composition rules.
POLICY_MAX_LENGTH = 64
_DATA = Path(__file__).resolve().parents[1] / "experiment" / "data"
_BLOCKLIST_FILES = [_DATA / "top-10000.txt", _DATA / "wordlist-sample.txt"]


@lru_cache(maxsize=1)
def load_blocklist() -> frozenset[str]:
    """Top-10,000 list if present (it is git-ignored), else the bundled sample list."""
    for path in _BLOCKLIST_FILES:
        if path.exists():
            with open(path, encoding="utf-8", errors="ignore") as fh:
                return frozenset(line.strip().lower() for line in fh if line.strip())
    return frozenset()


def policy_errors(password: str, mfa_enabled: bool = False) -> list[str]:
    """Return reasons the password is unacceptable (empty list = acceptable)."""
    if not Config.POLICY_ENABLED:
        return []
    pw = unicodedata.normalize("NFKC", password)
    min_len = Config.POLICY_MIN_LENGTH_WITH_MFA if mfa_enabled else Config.POLICY_MIN_LENGTH
    errors: list[str] = []
    if len(pw) < min_len:
        errors.append(f"password must be at least {min_len} characters")
    if len(pw) > POLICY_MAX_LENGTH:
        errors.append(f"password must be at most {POLICY_MAX_LENGTH} characters")
    if pw.lower() in load_blocklist():
        errors.append("password is too common or has appeared in a data breach")
    return errors


# ------------------------------------------------- Omar: lockout + rate limiting
def check_lockout(username: str, now: float) -> tuple[bool, int]:
    """Return whether login is allowed and remaining lock time."""
    if not _setting("LOCKOUT_ENABLED"):
        return True, 0

    with _state_lock:
        expiry = _locked_until.get(username)

        if expiry is None:
            return True, 0

        if now < expiry:
            return False, math.ceil(expiry - now)

        # The temporary lock has expired.
        _locked_until.pop(username, None)
        _login_failures.pop(username, None)
        return True, 0


def record_login_result(
    username: str,
    success: bool,
    now: float,
) -> None:
    """Count failed passwords and clear state after successful login."""
    if not _setting("LOCKOUT_ENABLED"):
        return

    with _state_lock:
        if success:
            _login_failures.pop(username, None)
            _locked_until.pop(username, None)
            return

        # Requests during a lock do not extend its duration.
        if now < _locked_until.get(username, 0):
            return

        # Discard an expired lock before counting a new failure.
        if username in _locked_until:
            _locked_until.pop(username, None)
            _login_failures.pop(username, None)

        failures = _login_failures.get(username, 0) + 1

        if failures >= _setting("LOCKOUT_MAX_FAILURES"):
            _locked_until[username] = (
                now + _setting("LOCKOUT_SECONDS")
            )
            _login_failures.pop(username, None)
        else:
            _login_failures[username] = failures


def check_rate_limit(ip: str, now: float) -> bool:
    """Allow at most the configured number of requests per IP per 60s."""
    if not _setting("RATE_LIMIT_ENABLED"):
        return True

    with _state_lock:
        attempts = _ip_attempts.setdefault(ip, deque())

        # Retain only requests inside the rolling 60-second window.
        while attempts and attempts[0] <= now - 60:
            attempts.popleft()

        if len(attempts) >= _setting("RATE_LIMIT_PER_MIN"):
            return False

        attempts.append(now)
        return True


# --------------------------------------------------------------- Kimse: TOTP MFA
def mfa_required(user) -> bool:
    return Config.MFA_ENABLED and bool(user["totp_secret"])


def verify_mfa(user, code: str | None, now: float) -> bool:
    """Verify a submitted TOTP code. NOT IMPLEMENTED in this service.

    The TOTP defence is implemented and measured in the experiment harness only
    (experiment/defenses.py, exp5). It was never wired into the Flask app, and no
    enrolment route writes users.totp_secret, so mfa_required() cannot fire while
    MFA_ENABLED stays off. Recorded as a scope boundary in report 3.4 and 4.2.
    """
    if not Config.MFA_ENABLED:
        return True
    return False  # deny if MFA is ever enabled without a real check behind it
