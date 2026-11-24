# Experiment harness

Measures how the chosen defences reduce risk against the threats in
`report/1-introduction.md`. Everything runs locally against **synthetic accounts
only**.

## Ethics & scope
These scripts attack only our own locally generated, random synthetic accounts
and locally computed hashes. They never target real users, real credentials, or
any system we do not own. This is defensive measurement, not an attack tool.

## Run it
```bash
cd experiment
python -m venv .venv && source .venv/bin/activate      # optional
pip install -r requirements.txt                        # optional but recommended
python run_experiments.py                              # uses sample wordlist
python run_experiments.py data/top-10000.txt           # real dictionary
```
The harness runs even without the optional libraries: Argon2id falls back to
PBKDF2 (stdlib) and TOTP to a built-in RFC 6238 implementation. Install the
requirements for results that match the report's stated settings.

`data/top-10000.txt` is git-ignored, so a fresh clone falls back to the bundled
15-word sample list. The report's figures come from the real list — the two give
very different guess counts (4,633,731 vs 8,440 for MD5), so state which list a
number came from.

## What each file does
| File | Role |
| --- | --- |
| `accounts.py` | Generates 100 synthetic accounts (4 strength tiers, fixed seed). |
| `defenses.py` | Hashing (MD5 vs Argon2id), blocklist, lockout policy, TOTP MFA. |
| `attacks.py` | Offline dictionary+mangling crack; online brute/spray/stuffing on a simulated clock. |
| `run_experiments.py` | Runs the four experiments and writes `results/summary.json`. |
| `test_policy.py` | 7 unit tests for the password policy. |

## Experiments (named to match report §3)
- **exp1 (storage)** MD5 vs bcrypt (cost 12) vs Argon2id under an equal time budget → accounts cracked.
- **exp3 (lockout)** Online brute force, lockout off vs on → takeovers / attempts blocked.
- **exp5 (MFA)** Credential stuffing, MFA off vs on → account takeovers. TOTP lives
  here only; it was never wired into the Flask service.
- **policy** Registration blocklist (15-char min) → how many generated passwords are accepted.

The current numbers are committed in `results/summary.json` and quoted in
`report/3-evaluation-and-results.md`.

## Known limitation in exp3
`e2_lockout` brute-forces `users[0]`, whose password (`admin`) is not in the
hard-coded 7-guess list, so neither the off nor the on run achieves a takeover.
The comparison therefore shows attempts blocked rather than a takeover prevented.
Adding `accounts.COMMON` to the `guesses` list in `run_experiments.py` would make
it a true before/after.
