# 3. Evaluation and Results

Repository: https://github.com/zynsniper/CS2413-security-analysis

We evaluated storage, password policy, and MFA using synthetic accounts in the experiment harness. We tested account lockout and IP rate limiting separately through the Flask application.

## 3.1 Database breach: password storage

*Figure 1: Offline password recovery using MD5, bcrypt, and Argon2id.

With a five-second budget per algorithm, MD5 completed 4,633,731 password checks and recovered 25 of 100 passwords. Bcrypt completed 26 checks and Argon2id completed 48, with neither recovering a password. Both substantially reduced guessing throughput compared with MD5. These results reflect the selected settings and test machine. Zero recoveries within this short budget do not establish that passwords cannot be cracked.

## 3.2 Online guessing: lockout and rate limiting

*Figures 2a–2b: Correct-password login after five failures, with lockout disabled and enabled.

Without lockout, the correct password succeeded after five failed attempts (HTTP 302). With lockout enabled, five failures triggered a 300-second lock, and the correct password was rejected (HTTP 423). Separately, IP rate limiting rejected request 31 within a rolling 60-second window (HTTP 429). Automated tests also verified recovery after simulated lock expiry.

## 3.3 Weak passwords: password policy

*Figure 3: Password-policy acceptance results and Flask registration responses.

With the policy disabled, the harness accepted all 100 generated passwords. Enabling the policy accepted 35 and rejected 65 because they were shorter than 15 characters. No additional rejection was attributed to the blocklist because the rejected candidates failed the length check first. This experiment demonstrates length enforcement, but does not separately measure the blocklist’s contribution or resistance to password spraying.

## 3.4 Reused passwords: MFA

*Figure 4: Simulated credential stuffing with MFA disabled and enabled.

The attacker supplied correct passwords for all 100 synthetic accounts but no OTPs. Without MFA, all 100 logins succeeded. With TOTP required, none succeeded. This demonstrates protection against password-only credential stuffing under the stated assumptions. MFA was evaluated in the harness and was not integrated into the Flask service.