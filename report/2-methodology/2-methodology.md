# 2. Methodology

## 2.1 Environment

| Item | Value |
| --- | --- |
| CPU / RAM / OS | Ryzen 5 5600 (6C/12T), 16 GB, Windows 11 Pro (build 26300) |
| Language / framework | Python 3.12.10, Flask 3.1.3 + SQLite |
| Libraries | bcrypt 5.0.0, argon2-cffi 25.1.0, pyotp 2.12.1, pytest 9.2.0 |
| Dictionary | SecLists top-10,000 password list [8] |
| Test accounts | 100 synthetic accounts, 4 strength categories, fixed seed |

Key configuration values: bcrypt cost 12; Argon2id with 64 MiB and 3 passes;
lockout after 5 failures for 5 minutes; 30 attempts per minute per IP address; a
15-character minimum (8 with MFA enabled).

## 2.2 Chosen solution and justification

- **Argon2id** stores each password as a slow, salted, memory-hard hash; chosen
  over bcrypt or SHA-256 because it is memory-hard and the current OWASP
  recommendation [2], [4].
- **Length-and-blocklist policy** requires 15+ characters screened against
  breached lists; chosen over complexity rules because NIST advises against
  composition rules [5].
- **Account lockout with per-IP rate limiting** slows repeated failures; chosen
  per the OWASP Authentication guidance to blunt online guessing.
- **TOTP MFA** adds a second factor; chosen over SMS codes because it needs no
  phone network and resists SIM swapping [7].
- **Layering** all four, because each covers a different one of the four threats.

## 2.3 Tests and procedures

Every defence mechanism functions independently via toggle configurations,
isolating single variables per evaluation. Storage schemes in offline
assessments receive identical computational time allocations. Online attack
simulations execute against the live web server utilizing an accelerated
one-hour operational clock, facing an adversary informed of system policies. A
suite of 28 automated tests validates correct functional logic: 21 against the
Flask service (`service/tests/`) confirming hashing correctness, lockout
activation thresholds, per-IP rate limiting and policy enforcement against
improper inputs, plus 7 policy tests against the experiment harness
(`experiment/test_policy.py`). The TOTP second factor is implemented and
measured in the experiment harness only, so it has no service-level test.
Testing occurred exclusively on local infrastructure using generated synthetic
profiles, ensuring zero impact on live services or external networks.
