"""Flask login service (Chi's part): user database, register, login, a protected
page, and logout, with password hashing.

The three add-on defences are wired through integrations.py but off by default,
so this file is the stable base the team builds on. Run:

    pip install -r requirements.txt
    flask --app app run        # or: python app.py
"""
from __future__ import annotations

import time

from flask import (Flask, redirect, render_template, request, session, url_for,
                   flash, abort)

import db
import integrations as seam
import security
from config import Config


def create_app(config: type[Config] = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config)
    db.init_db(app.config["DB_PATH"])

    @app.get("/")
    def home():
        return redirect(url_for("protected") if "user" in session else url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return render_template("register.html")
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if not username or not password:
            return _msg("username and password are required", 400)
        if db.user_exists(app.config["DB_PATH"], username):
            return _msg("username already taken", 409)
        # [Bunthong] password policy runs here (no-op while POLICY_ENABLED is off)
        errors = seam.policy_errors(password, mfa_enabled=app.config["MFA_ENABLED"])
        if errors:
            return _msg("rejected: " + "; ".join(errors), 400)
        pw_hash = security.hash_password(password, app.config["HASH_SCHEME"])
        uid = db.create_user(app.config["DB_PATH"], username, pw_hash)
        return _msg(f"registered user {username} (id {uid}) using {app.config['HASH_SCHEME']}", 201)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")
        now = time.time()
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        otp = request.form.get("otp")

        # [Omar] rate limit + lockout run here (no-ops while flags are off)
        if not seam.check_rate_limit(request.remote_addr or "?", now):
            return _msg("too many requests, slow down", 429)
        allowed, retry = seam.check_lockout(username, now)
        if not allowed:
            return _msg(f"account locked, try again in {retry}s", 423)

        user = db.get_user(app.config["DB_PATH"], username)
        ok = bool(user) and security.verify_password(user["pw_hash"], password)
        if not ok:
            seam.record_login_result(username, False, now)
            return _msg("invalid username or password", 401)

        # [Kimse] second factor runs here (no-op while MFA_ENABLED is off)
        if seam.mfa_required(user) and not seam.verify_mfa(user, otp, now):
            return _msg("valid password but MFA code required/incorrect", 401)

        seam.record_login_result(username, True, now)
        session["user"] = username
        return redirect(url_for("protected"))

    @app.get("/protected")
    def protected():
        if "user" not in session:
            return redirect(url_for("login"))
        return render_template("protected.html", user=session["user"])

    @app.get("/logout")
    def logout():
        session.pop("user", None)
        return redirect(url_for("login"))

    def _msg(text: str, status: int = 200):
        # Readable for curl screenshots; a browser just sees the same text.
        return (text + "\n", status, {"Content-Type": "text/plain; charset=utf-8"})

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
