# Login Security Analysis

**CS2413 Information Security | Team 1**  
Chi Seng, Omar Khair, Bunthong Kong, Kimse Lim

This project evaluates protections against password-based attacks using a local Flask and SQLite login application and a Python experiment harness with synthetic accounts.

## Security Mechanisms

| Mechanism | Configuration |
| --- | --- |
| Password hashing | Argon2id by default; bcrypt and MD5 for comparison |
| Account lockout | Five failed attempts trigger a 300-second lock |
| IP rate limiting | 30 login requests per rolling 60 seconds per IP |
| Password policy | 15–64 characters and common-password blocklist screening |
| TOTP MFA | Implemented and evaluated in the experiment harness only |

The Flask application supports registration, login, a protected page, and logout. TOTP enrolment and verification are not implemented in the service, so keep `MFA_ENABLED=0`.

## Repository Structure

| Folder | Contents |
| --- | --- |
| `service/` | Flask application, SQLite storage, security controls, and tests |
| `experiment/` | Synthetic accounts, dictionaries, simulated attacks, and results |
| `report/` | Methodology, evaluation, references, and screenshots |

## Setup

Run these commands in Windows PowerShell from the repository root:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r service/requirements.txt
.\.venv\Scripts\python.exe -m pip install -r experiment/requirements.txt
.\.venv\Scripts\python.exe -m pip install bcrypt
```

## Run the Application

```powershell
cd service
..\.venv\Scripts\python.exe -m flask --app app run
```

Open http://127.0.0.1:5000. Press `Ctrl+C` to stop the server.

Security settings are defined in `service/config.py`. Environment variables can override them before starting the server:

- `HASH_SCHEME`: `argon2id`, `bcrypt`, or `md5`
- `LOCKOUT_ENABLED`: `1` or `0`
- `RATE_LIMIT_ENABLED`: `1` or `0`
- `POLICY_ENABLED`: `1` or `0`
- `MFA_ENABLED`: keep `0` in the service

Restart the server after changing settings.

## Run the Tests

From the repository root:

```powershell
cd service
..\.venv\Scripts\python.exe -m pytest -q
cd ..
```

## Run the Experiments

From the repository root:

```powershell
cd experiment
..\.venv\Scripts\python.exe run_experiments.py data/top-10000.txt
cd ..
```

Omit `data/top-10000.txt` to use the bundled sample dictionary.

Confirm that the output reports bcrypt and Argon2 as available. Otherwise, the harness substitutes PBKDF2, and the measurements must not be reported as bcrypt or Argon2id results.

The runner prints results and generates `experiment/results/summary.json`. Demonstration screenshots are stored in `report/images/`. See `report/3-evaluation-and-results.md` for interpretation.

## Scope and Limitations

All experiments use local infrastructure and synthetic accounts.

TOTP results come from the harness, not the Flask service. Lockout and rate-limit counters are stored in memory and reset when the application restarts. Password-cracking results depend on the test environment and do not establish resistance to every attack.