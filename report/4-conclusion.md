# 4. Conclusion

## 4.1 Summary

We set out to measure how standard defences reduce the risk of four
password-based attacks on a login service. We built a Flask service with
switchable Argon2id storage, lockout and rate limiting, a NIST-style policy, and
TOTP MFA, and tested each in controlled before-and-after experiments. No single
defence was enough: slow hashing protects a leaked database, lockout stops brute
force, the policy removes spraying targets, and MFA stops reused passwords, so
they must be layered.

## 4.2 Team contributions

| Member | Responsibility | Specific delivery |
| --- | --- | --- |
| Chi Seng | Methodology section; password storage (database breach threat) | Built MD5, bcrypt and Argon2id storage schemes; ran exp1 offline cracking test; wrote Methodology; integrated the team's branches |
| Omar | Half of Evaluation; account lockout (online guessing threat) | Implemented the failed-attempt counter, timed lockout and per-IP rate limiting; added 7 automated tests; produced the live before-and-after demonstrations |
| Bunthong | Other half of Evaluation; password policy (weak passwords threat) | Implemented the 15-character minimum and common-password blocklist; added policy tests; ran the policy experiment over 100 generated passwords |
| Kimse | Introduction section; MFA design (reused passwords threat) | Wrote the Introduction; specified the TOTP second factor and its justification. TOTP is implemented and measured in the experiment harness (exp5) but was not wired into the Flask service, where `verify_mfa` remains a stub and no enrolment route exists |

## 4.3 Challenges and how we solved them

- Running hours of online attack in reasonable time. It was solved with a
  simulated clock.
- Making the cracking comparison fair. It was solved by giving every scheme the
  same attacker and time budget.
- Long predictable passwords such as `passwordpassword` pass a top-10,000
  blocklist. It was recorded as a limitation with a proposed fix (the full Have I
  Been Pwned list).
