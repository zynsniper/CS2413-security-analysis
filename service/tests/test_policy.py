"""Bunthong's tests: NIST password policy on /register (part of the 21 service tests)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as app_module  # noqa: E402
from config import Config  # noqa: E402


def make_client(tmp_path, monkeypatch, mfa=False):
    monkeypatch.setattr(Config, "POLICY_ENABLED", True)

    class TestConfig(Config):
        DB_PATH = str(tmp_path / "test.db")
        SECRET_KEY = "test"
        TESTING = True
        MFA_ENABLED = mfa
    return app_module.create_app(TestConfig).test_client()


@pytest.fixture
def client(tmp_path, monkeypatch):
    return make_client(tmp_path, monkeypatch)


def register(client, password, username="alice"):
    return client.post("/register", data={"username": username, "password": password})


def test_short_password_rejected(client):
    r = register(client, "Tr0ub4dor&3")
    assert r.status_code == 400
    assert b"at least 15 characters" in r.data


def test_blocklisted_password_rejected(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch, mfa=True)  # 8-char minimum with MFA
    r = register(client, "password")
    assert r.status_code == 400
    assert b"too common" in r.data


def test_acceptable_password_passes(client):
    r = register(client, "copper lantern orbit maple")
    assert r.status_code == 201
