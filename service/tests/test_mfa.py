
from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1])) 

import integrations as mfa  
from config import Config  

.
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()
NOW = 1234567890.0
STEP = int(NOW // mfa.TOTP_PERIOD)


@pytest.fixture(autouse=True)
def mfa_on(monkeypatch):
    """Turn MFA on and start every test with no used codes."""
    monkeypatch.setattr(Config, "MFA_ENABLED", True)
    mfa.reset_login_controls()
    yield
    mfa.reset_login_controls()


@pytest.fixture
def user():
    return {"username": "alice", "totp_secret": RFC_SECRET}




@pytest.mark.parametrize(
    "timestamp, expected",
    [
        (59, "287082"),
        (1111111109, "081804"),
        (1234567890, "005924"),
        (2000000000, "279037"),
    ],
)
def test_matches_rfc6238_vectors(timestamp, expected):
    assert mfa.totp_at(RFC_SECRET, timestamp // 30) == expected


def test_generated_secret_is_160_bit_base32():
    secret = mfa.generate_totp_secret()
    assert len(base64.b32decode(secret)) == 20
    assert secret != mfa.generate_totp_secret()


def test_provisioning_uri_has_secret_and_issuer():
    uri = mfa.provisioning_uri("ABCDEFGH", "alice")
    assert uri.startswith("otpauth://totp/")
    assert "secret=ABCDEFGH" in uri
    assert "alice" in uri and "issuer=" in uri



def test_correct_code_accepted(user):
    assert mfa.verify_mfa(user, mfa.totp_at(RFC_SECRET, STEP), NOW)


def test_code_with_spaces_accepted(user):
    code = mfa.totp_at(RFC_SECRET, STEP)
    assert mfa.verify_mfa(user, f" {code[:3]} {code[3:]} ", NOW)


def test_wrong_code_rejected(user):
    good = mfa.totp_at(RFC_SECRET, STEP)
    wrong = str((int(good) + 1) % 1_000_000).zfill(6)
    assert not mfa.verify_mfa(user, wrong, NOW)


@pytest.mark.parametrize("bad", [None, "", "12345", "1234567", "abcdef", "12 34a6"])
def test_malformed_code_rejected(user, bad):
    assert not mfa.verify_mfa(user, bad, NOW)


@pytest.mark.parametrize("offset", [-1, 1])
def test_one_step_clock_drift_accepted(user, offset):
    assert mfa.verify_mfa(user, mfa.totp_at(RFC_SECRET, STEP + offset), NOW)


@pytest.mark.parametrize("offset", [-3, -2, 2, 3])
def test_codes_outside_window_rejected(user, offset):
    assert not mfa.verify_mfa(user, mfa.totp_at(RFC_SECRET, STEP + offset), NOW)


def test_replayed_code_rejected(user):
    code = mfa.totp_at(RFC_SECRET, STEP)
    assert mfa.verify_mfa(user, code, NOW)
    assert not mfa.verify_mfa(user, code, NOW + 5)


def test_older_code_rejected_after_newer_one_used(user):
    assert mfa.verify_mfa(user, mfa.totp_at(RFC_SECRET, STEP + 1), NOW)
    assert not mfa.verify_mfa(user, mfa.totp_at(RFC_SECRET, STEP), NOW)


def test_next_period_code_accepted_after_use(user):
    assert mfa.verify_mfa(user, mfa.totp_at(RFC_SECRET, STEP), NOW)
    later = NOW + mfa.TOTP_PERIOD
    assert mfa.verify_mfa(user, mfa.totp_at(RFC_SECRET, STEP + 1), later)


def test_replay_tracking_is_per_user():
    other_secret = mfa.generate_totp_secret()
    alice = {"totp_secret": RFC_SECRET}
    bob = {"totp_secret": other_secret}
    assert mfa.verify_mfa(alice, mfa.totp_at(RFC_SECRET, STEP), NOW)
    assert mfa.verify_mfa(bob, mfa.totp_at(other_secret, STEP), NOW)


def test_reset_clears_replay_state(user):
    code = mfa.totp_at(RFC_SECRET, STEP)
    assert mfa.verify_mfa(user, code, NOW)
    mfa.reset_login_controls()
    assert mfa.verify_mfa(user, code, NOW)


def test_invalid_stored_secret_fails_closed():
    assert not mfa.verify_mfa({"totp_secret": "not*base32!"}, "123456", NOW)



def test_required_only_for_enrolled_users(user):
    assert mfa.mfa_required(user)
    assert not mfa.mfa_required({"totp_secret": None})
    assert not mfa.mfa_required({"totp_secret": ""})


def test_unenrolled_user_passes_without_code():
    assert mfa.verify_mfa({"totp_secret": None}, None, NOW)


def test_flag_off_disables_mfa(monkeypatch, user):
    monkeypatch.setattr(Config, "MFA_ENABLED", False)
    assert not mfa.mfa_required(user)
    assert mfa.verify_mfa(user, None, NOW)
