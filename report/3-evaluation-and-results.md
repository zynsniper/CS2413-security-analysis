# 3. Evaluation and Results

Repository: https://github.com/zynsniper/login-security-analysis

All figures below come from `experiment/run_experiments.py data/top-10000.txt`
and from the Flask service with the defence flags toggled; the raw output is
committed at `experiment/results/summary.json`.

## 3.1 Database breach (storage)

*Figure 1: MD5 cracking output and bcrypt/Argon2id cracking output.*

Across identical five-second computational allocations, MD5 enabled 4,633,731
offline evaluations, compromising 25 out of 100 stored accounts. Standardizing
on bcrypt restricted guessing throughput to 26 attempts with no accounts
compromised, and Argon2id to 48 attempts, likewise with none. Rapid hash
computation inherently privileges adversarial brute-forcing, while memory-hard
constructs like Argon2id impose intentional overhead that drastically inflates
the computational expenditure per candidate password — five orders of magnitude
fewer guesses in the same time budget.

## 3.2 Online guessing (lockout)

*Figure 2: attempts without lockout and attempts blocked by lockout.*

Disabling defensive controls permitted an automated attack tool to execute 7
consecutive authentication requests against a target user account unimpeded, and
the correct password then succeeded (HTTP 302). Enforcing temporary lockout
mechanics restricted sustained testing by rejecting the subsequent 2 attempts
once the five-failure threshold activated; the correct password was then refused
as well (HTTP 423). Though neither harness run achieved takeover, because the
guess list did not contain the target's password, unthrottled endpoints grant
persistent exposure, whereas automated account locking establishes a strict
upper bound on permissible authentication attempts.

## 3.3 Weak passwords (policy)

*Figure 3: weak password accepted and registration rejection message.*

Absence of credential validation rules permitted registration across 100% of
tested profiles, `123456` included. Applying NIST-aligned policy parameters
restricted successful provisioning to 35 out of 100 attempts, systematically
rejecting the remaining 65 for falling short of the 15-character minimum. The
breached-password blocklist never fired: only two entries in the top-10,000 list
reach 15 characters, so under this policy the length rule screens every common
password first. Eliminating low-entropy candidates effectively mitigates the
primary targets exploited during automated spray attacks.

## 3.4 Reused passwords (MFA)

*Figure 4: credential stuffing with MFA disabled and with MFA enabled.*

Simulated credential stuffing compromised 100 out of 100 single-factor target
profiles, whereas enabling multi-factor authentication prevented account
takeovers entirely (0/100). Because these attack vectors leverage valid
credentials harvested from third-party breaches, primary password verification
remains fundamentally insufficient. This comparison was measured in the
experiment harness, where TOTP is implemented; the second factor was not wired
into the Flask service, so it carries no service-level demonstration.
