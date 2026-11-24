# Automated tests (21 in this directory, split by owner)

Run all: from `service/`, `pytest -q`.

| File | Owner | Tests |
| --- | --- | --- |
| `test_security.py` | Chi | Argon2id used, bcrypt (cost 12) used, md5 baseline tagged, verify accept/reject, salted hashes differ (5) |
| `test_auth.py` | Chi | register, duplicate rejected, login→protected, wrong password 401, protected needs login, logout clears session (6) |
| `test_login_controls.py` | Omar | correct password before/during/after lock, success clears failures, per-IP rate limit isolation, rate-limit window expiry, `/login` returns 429 past the cap (7) |
| `test_policy.py` | Bunthong | short-password reject, blocklist reject, acceptable password passes (3) |

A further 7 policy tests run against the experiment harness in
`experiment/test_policy.py`, for **28 automated tests in total**.

There is no `test_mfa.py`: the TOTP second factor is implemented in the
experiment harness (`experiment/defenses.py`) but is not wired into the Flask
service, where `verify_mfa` remains a stub and no enrolment route writes
`users.totp_secret`. See §3.4 and §4.2 of the report.
