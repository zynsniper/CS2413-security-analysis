"""Seed the database with a few accounts so login can be tested by hand.

    python seed.py            # uses the default DB and HASH_SCHEME
    HASH_SCHEME=bcrypt python seed.py

For the full 100-account experiment set, use experiment/accounts.py instead;
this is just a handful for manual / curl testing of the base app.
"""
from __future__ import annotations

import db
import security
from config import Config

DEMO_USERS = [
    ("alice", "correct-horse-battery-staple"),
    ("bob", "Tr0ub4dour&3xtra-long"),
    ("carol", "a-very-long-passphrase-to-remember"),
]


def main() -> None:
    db.init_db(Config.DB_PATH)
    for username, password in DEMO_USERS:
        if db.user_exists(Config.DB_PATH, username):
            print(f"skip {username} (exists)")
            continue
        pw_hash = security.hash_password(password, Config.HASH_SCHEME)
        db.create_user(Config.DB_PATH, username, pw_hash)
        print(f"added {username} ({Config.HASH_SCHEME})")


if __name__ == "__main__":
    main()
