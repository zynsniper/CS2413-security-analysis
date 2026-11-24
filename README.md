# Login Service — Security Analysis & Controlled Experiment

**Team 1 — Final Project**
Chi Seng · Omar · Bunthong · Kimse

Information Security final project. We build a Flask login service with switchable
defences and measure, in controlled before-and-after experiments, how each defence
reduces the risk of four password attacks: **offline cracking, online guessing,
password spraying, and credential stuffing.**

## Repository structure
| Path | What's in it |
| --- | --- |
| `report/final-submission.md` | The submitted report, all four sections in one file |
| `report/1-introduction.md` | Problem, existing approaches (cited), our solution (15 marks) |
| `report/2-methodology/2-methodology.md` | Environment, chosen mechanisms + justification, tests (25 marks) |
| `report/3-evaluation-and-results.md` | Four before/after comparisons with screenshots (30 marks) |
| `report/4-conclusion.md` | Summary, contributions table, challenges (10 marks) |
| `report/references.md` | IEEE reference list [1]–[8] |
| `experiment/` | Harness: synthetic accounts, defences, simulated attacks (exp1/exp3/exp5) |
| `service/` | The Flask + SQLite login service and its 21 tests |

## Status
All four report sections are complete and all four defences are accounted for:

| Defence | Flag | In the service | Measured |
| --- | --- | --- | --- |
| Argon2id / bcrypt / MD5 storage | `HASH_SCHEME` | Yes (always on) | exp1 |
| Account lockout + per-IP rate limit | `LOCKOUT_ENABLED`, `RATE_LIMIT_ENABLED` | Yes | exp3 + live demo |
| NIST password policy | `POLICY_ENABLED` | Yes | policy + live demo |
| TOTP MFA | `MFA_ENABLED` | **No** — harness only | exp5 |

TOTP is implemented and measured in `experiment/` but was never wired into the
Flask service: `verify_mfa` is a stub and no enrolment route writes
`users.totp_secret`. This is stated in the report (§3.4, §4.2) rather than
glossed over.

## Results
From `experiment/run_experiments.py data/top-10000.txt`, committed at
`experiment/results/summary.json`:

| Experiment | Before | After |
| --- | --- | --- |
| exp1 storage (equal 5 s budget) | MD5: 4,633,731 guesses, 25/100 cracked | Argon2id: 48 guesses, 0 cracked |
| exp3 lockout | correct password accepted after 5 failures (HTTP 302) | refused for 5 minutes (HTTP 423) |
| policy | 100/100 passwords accepted, `123456` included | 35/100 accepted, 65 rejected on length |
| exp5 MFA | 100/100 accounts taken over by stuffing | 0/100 |

## The service and defences
A Flask + SQLite login service where each defence toggles on/off:
- **Storage:** Argon2id (64 MiB, 3 passes) — baseline comparison vs bcrypt (cost 12) and MD5.
- **Lockout + rate limiting:** 5 failures → 5-minute lock; 30 attempts/min/IP.
- **Password policy:** 15-char minimum (8 with MFA), screened against breached lists, no composition rules.
- **MFA:** TOTP (RFC 6238) — in the harness only, see Status above.

## Reproducing the results
```bash
# the service and its tests (21 tests, no extra data needed)
cd service && pip install -r requirements.txt && pytest -q

# the experiments; the sample wordlist ships with the repo
cd experiment && pip install -r requirements.txt
python run_experiments.py                        # bundled 15-word sample list
python run_experiments.py data/top-10000.txt     # the real dictionary [8], git-ignored
```
The three implemented defences default to **on**. Turn one off to capture a
"before" run, e.g. `POLICY_ENABLED=0 flask --app app run`.

Note that `data/top-10000.txt` is git-ignored, so a fresh clone falls back to the
bundled sample list; the headline numbers above need the real list.

## How we worked
- One branch per person (`omar/login-controls`, `bunthong/experiment`,
  `kimse/introduction`); merged into `main`. The branches are kept so each
  member's own commits stay visible.
- Each report section stays within its word budget; the submitted report is 946
  words excluding references.
- Numbers go into the report only after they come out of `experiment/` or the
  service, so they're reproducible.

## Ethics & scope
Defensive research. **Every attack runs only against our own local service and
synthetic, randomly generated accounts** — never real users, real credentials, or
any system we don't own.
