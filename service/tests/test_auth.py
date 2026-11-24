"""Chi's tests: register / login / protected / logout (part of the 21 service tests)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as app_module  # noqa: E402
from config import Config  # noqa: E402


@pytest.fixture
def client(tmp_path):
    class TestConfig(Config):
        DB_PATH = str(tmp_path / "test.db")
        SECRET_KEY = "test"
        TESTING = True
    flask_app = app_module.create_app(TestConfig)
    return flask_app.test_client()


def register(client, username="alice", password="a-long-enough-password"):
    return client.post("/register", data={"username": username, "password": password})


def test_register_creates_user(client):
    r = register(client)
    assert r.status_code == 201
    assert b"registered user alice" in r.data


def test_duplicate_register_rejected(client):
    register(client)
    r = register(client)
    assert r.status_code == 409


def test_login_success_reaches_protected(client):
    register(client)
    r = client.post("/login", data={"username": "alice", "password": "a-long-enough-password"})
    assert r.status_code == 302  # redirect to /protected
    r2 = client.get("/protected")
    assert r2.status_code == 200
    assert b"alice" in r2.data


def test_login_wrong_password_rejected(client):
    register(client)
    r = client.post("/login", data={"username": "alice", "password": "nope"})
    assert r.status_code == 401


def test_protected_requires_login(client):
    r = client.get("/protected")
    assert r.status_code == 302  # redirected to /login
    assert "/login" in r.headers["Location"]


def test_logout_clears_session(client):
    register(client)
    client.post("/login", data={"username": "alice", "password": "a-long-enough-password"})
    client.get("/logout")
    r = client.get("/protected")
    assert r.status_code == 302  # back to login after logout
