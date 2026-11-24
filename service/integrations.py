"""Integration seams for the three add-on defences.

Each function is a safe no-op while its flag is off, so the base app runs on its
own. The named owner replaces the body and flips the matching flag in config.py.
Keeping the seams here means app.py never has to be restructured.
"""
from __future__ import annotations

import urllib
import secretsimport 
import quote 
import base64
import hashlib
import hmac
import math
import struct
import unicodedata
from collections import deque
from functools import lru_cache
from pathlib import Path
from threading import RLock

from flask import current_app, has_app_context

from config import Config


_login_failures: dict[str, int] = {}
_locked_until: dict[str, float] = {}
_ip_attempts: dict[str, deque[float]] = {}
_state_lock = RLock()
_totp_last_step: dict[str, int] = {}

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
        _totp_last_step.clear()

# Bunthong: this is where i wrote my password policy
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

        # this is when the temporary lock has expired.
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

        if now < _locked_until.get(username, 0):
            return

        #this for us to discard an expired lock before counting a new failure.
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

        while attempts and attempts[0] <= now - 60:
            attempts.popleft()

        if len(attempts) >= _setting("RATE_LIMIT_PER_MIN"):
            return False

        attempts.append(now)
        return True


#kimse part totp mfa
TOTP_PERIOD = 30
TOTP_DIGITS = 6
TOTP_DRIFT_STEPS = 1 

def generate_totp_secret() -> str:
    """New random 160-bit secret, Base32-encoded, for storing in users.totp_secret."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def provisioning_uri(secret: str, username: str, issuer: str = "CS2413 Demo") -> str:
    """otpauth:// URI to render as a QR code for Google Authenticator, Authy, etc."""
    label = quote(f"{issuer}:{username}")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"
    )


def _decode_secret(secret: str) -> bytes:
    cleaned = secret.strip().replace(" ", "").upper()
    cleaned += "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned)


def totp_at(secret: str, step: int) -> str:
    """The code for one 30-second step (RFC 4226 HOTP dynamic truncation)."""
    digest = hmac.new(_decode_secret(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** TOTP_DIGITS).zfill(TOTP_DIGITS)


def mfa_required(user) -> bool:
    return bool(_setting("MFA_ENABLED")) and bool(user["totp_secret"])


def verify_mfa(user, code: str | None, now: float) -> bool:
    """Verify a submitted TOTP code against the user's stored secret.

    Accepts the current step plus or minus TOTP_DRIFT_STEPS, compares in constant
    time, and rejects reuse of a code (or any earlier step) that already succeeded,
    so an intercepted code cannot be replayed inside its validity window.
    """
    if not mfa_required(user):
        return True

    if code is None:
        return False
    code = code.strip().replace(" ", "")
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return False

    secret = user["totp_secret"]
    current = int(now // TOTP_PERIOD)
    try:
        matched = None
        for step in range(current - TOTP_DRIFT_STEPS, current + TOTP_DRIFT_STEPS + 1):
            if hmac.compare_digest(totp_at(secret, step), code):
                matched = step
    except (binascii.Error, ValueError):
        return False

    if matched is None:
        return False
    with _state_lock:
        if matched <= _totp_last_step.get(secret, -1):
            return False
        _totp_last_step[secret] = matched
    return True
