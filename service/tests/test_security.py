"""Chi's tests: password hashing (part of the 21 service tests)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import security  # noqa: E402

PW = "correct-horse-battery-staple"


def test_argon2id_is_really_used():
    h = security.hash_password(PW, "argon2id")
    assert h.startswith("$argon2id$")          # real Argon2id, not a fallback
    assert security.detect_scheme(h) == "argon2id"


def test_bcrypt_is_really_used():
    h = security.hash_password(PW, "bcrypt")
    assert h.startswith("$2b$")                 # real bcrypt
    assert "$12$" in h[:7]                       # cost factor 12
    assert security.detect_scheme(h) == "bcrypt"


def test_md5_baseline_marked():
    h = security.hash_password(PW, "md5")
    assert h.startswith("md5$")
    assert security.detect_scheme(h) == "md5"


def test_verify_accepts_correct_and_rejects_wrong():
    for scheme in ("argon2id", "bcrypt", "md5"):
        h = security.hash_password(PW, scheme)
        assert security.verify_password(h, PW) is True
        assert security.verify_password(h, "wrong-password") is False


def test_same_password_hashes_differently_when_salted():
    # Argon2id and bcrypt salt, so two hashes of the same password differ.
    assert security.hash_password(PW, "argon2id") != security.hash_password(PW, "argon2id")
    assert security.hash_password(PW, "bcrypt") != security.hash_password(PW, "bcrypt")
