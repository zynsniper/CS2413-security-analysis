"""Password hashing for the login service (Chi's part).

Supports three storage schemes so the before/after storage comparison can swap
one line and re-measure:

    argon2id : OWASP-recommended, memory-hard (64 MiB, 3 passes)   [production]
    bcrypt   : cost factor 12                                       [comparison]
    md5      : fast, broken — the "before" baseline only            [comparison]

verify_password() auto-detects the scheme from the stored hash, so a database
can hold mixed schemes during a migration.
"""
from __future__ import annotations

import hashlib

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

BCRYPT_COST = 12
_ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=1,
                     hash_len=32, salt_len=16)


def hash_password(password: str, scheme: str = "argon2id") -> str:
    if scheme == "argon2id":
        return _ph.hash(password)
    if scheme == "bcrypt":
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=BCRYPT_COST)).decode()
    if scheme == "md5": 
        return "md5$" + hashlib.md5(password.encode()).hexdigest()
    raise ValueError(f"unknown hash scheme: {scheme!r}")


def detect_scheme(stored: str) -> str:
    if stored.startswith("$argon2"):
        return "argon2id"
    if stored.startswith("$2a$") or stored.startswith("$2b$") or stored.startswith("$2y$"):
        return "bcrypt"
    if stored.startswith("md5$"):
        return "md5"
    raise ValueError("unrecognised hash format")


def verify_password(stored: str, password: str) -> bool:
    scheme = detect_scheme(stored)
    if scheme == "argon2id":
        try:
            return _ph.verify(stored, password)
        except VerifyMismatchError:
            return False
    if scheme == "bcrypt":
        return bcrypt.checkpw(password.encode(), stored.encode())
    if scheme == "md5":
        return stored == "md5$" + hashlib.md5(password.encode()).hexdigest()
    return False


if __name__ == "__main__":
    for s in ("argon2id", "bcrypt", "md5"):
        h = hash_password("correct horse battery staple", s)
        print(f"{s:9} -> {h[:48]}...  verify={verify_password(h, 'correct horse battery staple')}")
