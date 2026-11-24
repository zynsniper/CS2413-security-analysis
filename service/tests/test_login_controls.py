import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as app_module
import integrations as controls
from config import Config


@pytest.fixture
def application(tmp_path):
    class TestConfig(Config):
        DB_PATH = str(tmp_path / "controls.db")
        SECRET_KEY = "test-only"
        TESTING = True
        LOCKOUT_ENABLED = True
        RATE_LIMIT_ENABLED = False
        POLICY_ENABLED = False
        MFA_ENABLED = False

    controls.reset_login_controls()
    application = app_module.create_app(TestConfig)

    yield application

    controls.reset_login_controls()


def register_user(client):
    response = client.post(
        "/register",
        data={
            "username": "omar-test",
            "password": "correct-test-password",
        },
    )
    assert response.status_code == 201


def login(client, password):
    return client.post(
        "/login",
        data={
            "username": "omar-test",
            "password": password,
        },
    )


def test_no_lockout_allows_correct_password(application):
    application.config["LOCKOUT_ENABLED"] = False
    client = application.test_client()
    register_user(client)

    for _ in range(5):
        assert login(client, "incorrect").status_code == 401

    assert login(client, "correct-test-password").status_code == 302
    assert client.get("/protected").status_code == 200


def test_lockout_blocks_correct_password(application):
    client = application.test_client()
    register_user(client)

    for _ in range(5):
        assert login(client, "incorrect").status_code == 401

    assert login(client, "correct-test-password").status_code == 423
    assert client.get("/protected").status_code == 302


def test_login_works_after_lock_expires(application, monkeypatch):
    client = application.test_client()
    register_user(client)

    clock = [1000.0]
    monkeypatch.setattr(app_module.time, "time", lambda: clock[0])

    for _ in range(5):
        assert login(client, "incorrect").status_code == 401

    assert login(client, "correct-test-password").status_code == 423

    # Advance simulated time beyond the 300-second lock.
    clock[0] += 301

    assert login(client, "correct-test-password").status_code == 302


def test_success_clears_previous_failures(application):
    with application.app_context():
        for _ in range(4):
            controls.record_login_result("alice", False, 1000)

        controls.record_login_result("alice", True, 1001)
        controls.record_login_result("alice", False, 1002)

        assert controls.check_lockout("alice", 1003) == (True, 0)


def test_rate_limit_is_separate_for_each_ip(application):
    application.config["RATE_LIMIT_ENABLED"] = True

    with application.app_context():
        for _ in range(30):
            assert controls.check_rate_limit("192.0.2.1", 1000)

        assert not controls.check_rate_limit("192.0.2.1", 1000)
        assert controls.check_rate_limit("192.0.2.2", 1000)


def test_rate_limit_allows_requests_after_window(application):
    application.config["RATE_LIMIT_ENABLED"] = True

    with application.app_context():
        for _ in range(30):
            assert controls.check_rate_limit("192.0.2.1", 1000)

        assert not controls.check_rate_limit("192.0.2.1", 1059)
        assert controls.check_rate_limit("192.0.2.1", 1060)


def test_login_route_returns_429_after_limit(application):
    application.config["LOCKOUT_ENABLED"] = False
    application.config["RATE_LIMIT_ENABLED"] = True
    client = application.test_client()

    for _ in range(30):
        response = client.post(
            "/login",
            data={"username": "missing-user", "password": "incorrect"},
        )
        assert response.status_code == 401

    response = client.post(
        "/login",
        data={"username": "missing-user", "password": "incorrect"},
    )
    assert response.status_code == 429