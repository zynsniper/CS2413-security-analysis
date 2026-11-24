# Securing Password Logins — Team 1 Final Project Report

Chi Seng, Omar, Bunthong, Kimse

## 1. Introduction

Passwords remain the main gatekeeper for most online accounts, and attackers
keep finding ways around them. Verizon's 2026 Data Breach Investigations Report
found credential abuse provided initial access in 13% of more than 22,000
breaches [1]. We examine four attacks on password logins: offline cracking of a
stolen database, online guessing against one account, spraying a few common
passwords across many accounts, and stuffing login pages with credentials leaked
elsewhere.

Industry guidance addresses each. Because fast hashes such as SHA-256 let an
attacker test guesses at speed, OWASP advises salted, deliberately slow hashing
with Argon2id or bcrypt [2]. Bcrypt's cost factor can be raised as hardware
improves [3], and Argon2 further raises the cost per guess by demanding
memory [4]. For passwords used without a second factor, NIST SP 800-63B-4 sets a
15-character minimum, screens candidates against breached lists, limits failed
attempts, and drops composition rules [5]. Against spraying and stuffing, OWASP
identifies multi-factor authentication as the strongest defence [6]; time-based
one-time passwords (TOTP) are a widespread implementation [7].

Our Flask service implements all four: Argon2id storage, account lockout with
per-IP rate limiting, a NIST-aligned policy, and TOTP MFA. Each defence toggles
independently, letting us measure its effect in controlled before-and-after
experiments.

## 2. Methodology

### 2.1 Environment

| Item | Value |
| --- | --- |
| CPU / RAM / OS | Ryzen 5 5600, 16 GB, Windows 11 |
| Stack | Python 3.12, Flask, SQLite |
| Libraries | bcrypt, argon2-cffi, pyotp, pytest |
| Dictionary | SecLists top-10,000 list [8] |
| Accounts | 100 synthetic, 4 strength categories, fixed seed |

Settings: bcrypt cost 12; Argon2id 64 MiB and 3 passes; lockout after 5 failures
for 5 minutes; 30 requests per minute per IP; 15-character minimum.

### 2.2 Chosen solution and justification

- **Argon2id** gives slow, salted, memory-hard storage; chosen over bcrypt and
  SHA-256 as the current OWASP recommendation [2], [4].
- **Length-and-blocklist policy** requires 15+ characters screened against
  breached lists; chosen over complexity rules, which NIST advises against [5].
- **Lockout with per-IP rate limiting** caps repeated failures, following OWASP
  authentication guidance.
- **TOTP MFA** adds a second factor needing no phone network, so it resists SIM
  swapping [7].

Each covers a different one of the four threats, so we layer all four.

### 2.3 Tests and procedures

Every defence is a toggle, so each experiment changes one variable. Offline
schemes receive identical time budgets. Online attacks run against the live
server on an accelerated one-hour clock, facing an attacker who knows the
policy. Twenty-eight automated tests check hashing correctness, lockout
thresholds, per-IP rate limiting and policy enforcement; MFA has no
service-level test, for the reason given in 3.4. Everything ran locally against
synthetic accounts, with no effect on real systems or users.

## 3. Evaluation and Results

Repository: https://github.com/zynsniper/login-security-analysis

### 3.1 Database breach (storage)

*Figure 1: offline cracking output for MD5, bcrypt and Argon2id.*

In identical five-second budgets, MD5 allowed 4,633,731 guesses and cracked 25
of 100 accounts. Bcrypt allowed 26 guesses and cracked none; Argon2id allowed 48
and cracked none. Fast hashing favours the attacker, while memory-hard Argon2id
inflates the cost per candidate by five orders of magnitude.

### 3.2 Online guessing (lockout)

*Figure 2: login attempts with lockout off, then on.*

With lockout off, the tool sent 7 consecutive requests unimpeded and the correct
password then succeeded (HTTP 302). With lockout on, the 2 attempts after the
five-failure threshold were rejected, and the correct password was refused as
well (HTTP 423). Neither harness run took the account, because the guess list
lacked its password, but an unthrottled endpoint gives unlimited exposure while
lockout imposes a hard cap.

### 3.3 Weak passwords (policy)

*Figure 3: registration accepting `123456`, then rejecting it with reasons.*

With no policy, all 100 test passwords registered, `123456` included. Under the
NIST policy, 35 of 100 were accepted and 65 rejected, every one for falling
short of 15 characters. The blocklist never fired: only two top-10,000 entries
reach 15 characters, so length screens every common password first. Removing
low-entropy passwords eliminates the targets spraying relies on.

### 3.4 Reused passwords (MFA)

*Figure 4: credential stuffing with MFA off, then on.*

Stuffing took over all 100 single-factor accounts; with MFA enabled, none
(0/100). Because stuffing uses credentials that are already valid, checking the
password alone cannot stop it. This result comes from the experiment harness,
where TOTP is implemented; the second factor was not wired into the Flask
service, so it has no live demonstration.

## 4. Conclusion

### 4.1 Summary

We measured how four standard defences reduce the risk of four password attacks
on a Flask login service. No single defence sufficed: slow hashing protects a
leaked database, lockout caps online guessing, the policy removes spraying
targets, and MFA stops reused credentials. They must be layered.

### 4.2 Team contributions

| Member | Responsibility | Delivery |
| --- | --- | --- |
| Chi Seng | Methodology; password storage | Built the MD5, bcrypt and Argon2id schemes; ran exp1; wrote Methodology; merged the team's branches |
| Omar | Evaluation 3.1–3.2; account lockout | Implemented the failure counter, timed lockout and per-IP rate limiting; added 7 tests; produced the before/after demonstrations |
| Bunthong | Evaluation 3.3–3.4; password policy | Implemented the 15-character minimum and breached-password blocklist; added policy tests; ran the policy experiment |
| Kimse | Introduction; MFA design | Wrote the Introduction and specified the TOTP factor. TOTP is implemented and measured in the harness only; it was not wired into the service, where `verify_mfa` remains a stub |

### 4.3 Challenges and how we solved them

- Running hours of online attack quickly — solved with a simulated clock.
- Keeping the cracking comparison fair — every scheme got the same attacker and
  time budget.
- Long predictable passwords such as `passwordpassword` pass a top-10,000
  blocklist — recorded as a limitation, with the full Have I Been Pwned list as
  the fix.

## References

[1] Verizon Business. "2026 data breach investigations report: Executive summary." Verizon. https://www.verizon.com/business/resources/executivebriefs/2026-dbir-executive-summary.pdf (accessed Nov. 12, 2026).

[2] OWASP Cheat Sheet Series. "Password storage cheat sheet." OWASP. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html (accessed Nov. 12, 2026).

[3] N. Provos and D. Mazières, "A future-adaptable password scheme," in Proc. 1999 USENIX Annu. Tech. Conf., Monterey, CA, USA, Jun. 1999, pp. 81–92. [Online]. Available: https://www.usenix.org/conference/1999-usenix-annual-technical-conference/presentation/future-adaptable-password-scheme

[4] A. Biryukov, D. Dinu, D. Khovratovich, and S. Josefsson, "Argon2 memory-hard function for password hashing and proof-of-work applications," Internet Research Task Force, RFC 9106, Sep. 2021. [Online]. Available: https://datatracker.ietf.org/doc/html/rfc9106

[5] D. Temoshok et al., "Digital identity guidelines: Authentication and authenticator management," National Institute of Standards and Technology, Gaithersburg, MD, USA, NIST SP 800-63B-4, Jul. 2025, doi: 10.6028/NIST.SP.800-63B-4.

[6] OWASP Cheat Sheet Series. "Credential stuffing prevention cheat sheet." OWASP. https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html (accessed Nov. 12, 2026).

[7] D. M'Raihi, S. Machani, M. Pei, and J. Rydell, "TOTP: Time-based one-time password algorithm," Internet Engineering Task Force, RFC 6238, May 2011. [Online]. Available: https://datatracker.ietf.org/doc/rfc6238

[8] D. Miessler et al. "SecLists." GitHub. https://github.com/danielmiessler/SecLists (accessed Nov. 12, 2026).
