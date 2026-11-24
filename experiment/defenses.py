"""The defences under test: password hashing, a registration blocklist,
an account-lockout model, and TOTP-based MFA.

Each defence degrades gracefully if an optional library is missing, so the
harness always runs:
  - Argon2id  -> falls back to PBKDF2-HMAC-SHA256 (stdlib) if argon2-cffi absent.
  - TOTP      -> falls back to a minimal RFC 6238 implementation if pyotp absent.

Keep these settings in sync with report/03-chosen-mechanisms.md.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import unicodedata

# ---------------------------------------------------------------- hashing ----

def hash_md5(password: str, salt: bytes = b"") -> str:
    """Deliberately WEAK baseline (fast, unsalted-ish). For comparison only."""
    return hashlib.md5(salt + password.encode()).hexdigest()


try:
    import bcrypt

    BCRYPT_AVAILABLE = True

    def hash_bcrypt(password: str, cost: int = 12) -> str:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=cost)).decode()

    def verify_bcrypt(stored: str, password: str) -> bool:
        return bcrypt.checkpw(password.encode(), stored.encode())
except ImportError:  # stdlib fallback so the harness still runs
    BCRYPT_AVAILABLE = False

    def hash_bcrypt(password: str, cost: int = 12) -> str:
        salt = secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 2 ** cost * 16)
        return "pbkdf2bc$" + base64.b64encode(salt).decode() + "$" + dk.hex()

    def verify_bcrypt(stored: str, password: str) -> bool:
        _, b64salt, want = stored.split("$")
        salt = base64.b64decode(b64salt)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 2 ** 12 * 16)
        return hmac.compare_digest(dk.hex(), want)


try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError

    _ph = PasswordHasher(
        time_cost=3, memory_cost=64 * 1024, parallelism=1, hash_len=32, salt_len=16
    )
    ARGON2_AVAILABLE = True

    def hash_argon2(password: str) -> str:
        return _ph.hash(password)

    def verify_argon2(stored: str, password: str) -> bool:
        try:
            return _ph.verify(stored, password)
        except VerifyMismatchError:
            return False
except ImportError:  # stdlib fallback so the harness still runs
    ARGON2_AVAILABLE = False

    def hash_argon2(password: str) -> str:
        salt = secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
        return "pbkdf2$" + base64.b64encode(salt).decode() + "$" + dk.hex()

    def verify_argon2(stored: str, password: str) -> bool:
        _, b64salt, want = stored.split("$")
        salt = base64.b64decode(b64salt)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
        return hmac.compare_digest(dk.hex(), want)


# ------------------------------------------------------- password policy ----
# NIST SP 800-63B-4: 15-64 characters, blocklist check, no composition rules.

POLICY_MIN_LEN = 15
POLICY_MAX_LEN = 64

POLICY_MESSAGES = {
    "too_short": f"Password must be at least {POLICY_MIN_LEN} characters. Try a passphrase of several words.",
    "too_long": f"Password must be at most {POLICY_MAX_LEN} characters.",
    "blocklisted": "This password is too common or has appeared in a data breach. Choose another.",
}


def check_password_policy(password: str, blocklist: set[str], *, enabled: bool = True,
                          min_len: int = POLICY_MIN_LEN, max_len: int = POLICY_MAX_LEN) -> tuple[bool, str]:
    """Return (accepted, reason). enabled=False accepts everything (the "before" case)."""
    if not enabled:
        return True, "accepted"
    pw = unicodedata.normalize("NFKC", password)
    if len(pw) < min_len:
        return False, "too_short"
    if len(pw) > max_len:
        return False, "too_long"
    if pw.lower() in blocklist:
        return False, "blocklisted"
    return True, "accepted"


def passes_blocklist(password: str, blocklist: set[str], min_len: int = POLICY_MIN_LEN) -> bool:
    """Older interface: True if the policy accepts the password."""
    return check_password_policy(password, blocklist, min_len=min_len)[0]


# --------------------------------------------------------------- lockout ----

class LockoutPolicy:
    """R2: lock an account after `max_failures` consecutive misses for `lock_seconds`.

    Uses an injectable clock (seconds) so the online experiments can run on a
    simulated timeline instead of real wall-clock time.
    """

    def __init__(self, max_failures: int = 5, lock_seconds: int = 300):
        self.max_failures = max_failures
        self.lock_seconds = lock_seconds
        self._fails: dict[str, int] = {}
        self._locked_until: dict[str, float] = {}

    def is_locked(self, user: str, now: float) -> bool:
        return now < self._locked_until.get(user, 0)

    def record_failure(self, user: str, now: float) -> None:
        self._fails[user] = self._fails.get(user, 0) + 1
        if self._fails[user] >= self.max_failures:
            self._locked_until[user] = now + self.lock_seconds
            self._fails[user] = 0

    def record_success(self, user: str) -> None:
        self._fails.pop(user, None)
        self._locked_until.pop(user, None)


# ------------------------------------------------------------------ MFA ----

try:
    import pyotp

    def new_totp_secret() -> str:
        return pyotp.random_base32()

    def totp_now(secret: str, now: float) -> str:
        return pyotp.TOTP(secret).at(int(now))
except ImportError:  # minimal RFC 6238 fallback
    def new_totp_secret() -> str:
        return base64.b32encode(secrets.token_bytes(10)).decode().rstrip("=")

    def totp_now(secret: str, now: float, step: int = 30, digits: int = 6) -> str:
        key = base64.b32decode(secret + "=" * (-len(secret) % 8))
        counter = int(now) // step
        mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
        offset = mac[-1] & 0x0F
        code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
        return str(code).zfill(digits)


if __name__ == "__main__":
    print("Argon2 library available:", ARGON2_AVAILABLE)
    h = hash_argon2("correct horse battery staple")
    print("sample strong hash verifies:", verify_argon2(h, "correct horse battery staple"))
    s = new_totp_secret()
    print("sample TOTP code:", totp_now(s, time.time()))
