# Login service (Flask + SQLite)

The base application for the Team 1 experiment. Chi owns this base: the user
database, register/login/protected/logout, and password hashing. Each other
defence is a feature flag with a clearly marked seam, so Omar, Bunthong and Kimse
add their mechanism without restructuring anything.

## Run it
```bash
cd service
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python seed.py            # add a few demo accounts
flask --app app run       # http://127.0.0.1:5000  (or: python app.py)
```

## Routes
| Route | Method | Purpose |
| --- | --- | --- |
| `/register` | GET/POST | Create an account; password is hashed with `HASH_SCHEME` |
| `/login` | GET/POST | Verify password, start a session (seams for lockout + MFA) |
| `/protected` | GET | Visible only with a valid session |
| `/logout` | GET | Clears the session |

Endpoints return plain-text messages with real HTTP status codes, so they're easy
to screenshot with `curl` for the report:
```bash
curl -i -X POST localhost:5000/register --data "username=dave&password=short"
curl -i -X POST localhost:5000/login    --data "username=alice&password=correct-horse-battery-staple"
```

## Password storage (Chi)
`security.py` implements three schemes; switch with the `HASH_SCHEME` env var:
- `argon2id` (default) — 64 MiB, 3 passes, OWASP-recommended.
- `bcrypt` — cost factor 12.
- `md5` — broken; the "before" baseline for the storage comparison only.

`verify_password()` detects the scheme from the stored hash, so the table can hold
mixed schemes during a migration. `python security.py` prints a sample of each.

## Feature flags (config.py) — owners
| Flag | Owner | Default | Seam (in `integrations.py`) |
| --- | --- | --- | --- |
| `LOCKOUT_ENABLED`, `RATE_LIMIT_ENABLED` | Omar | on | `check_lockout`, `record_login_result`, `check_rate_limit` |
| `POLICY_ENABLED` | Bunthong | on | `policy_errors` |
| `MFA_ENABLED` | Kimse | **off** | `mfa_required`, `verify_mfa` |

The three implemented defences default to **on**, so the service demonstrates
them with no extra setup. Turn one off per run to capture a "before" screenshot,
e.g. `POLICY_ENABLED=0 flask --app app run`.

`MFA_ENABLED` stays off: `verify_mfa` is a stub and no enrolment route writes
`users.totp_secret`, so `mfa_required()` can never fire. Enabling it would also
drop the policy minimum from 15 to 8 characters. TOTP is implemented and measured
in `experiment/` instead; see report §3.4 and §4.2.

## Tests
`pytest -q` from `service/` — 21 tests, and they pass on a fresh clone with no
extra data. See `tests/README.md` for who owns which.
