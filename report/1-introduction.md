# 1. Introduction

Passwords remain the main gatekeeper for most online accounts, and attackers keep finding ways around them. Verizon's 2026 Data Breach Investigations Report found credential abuse provided initial access in 13% of more than 22,000 breaches [1]. We examine four attacks on password logins: offline cracking of a stolen database, online guessing against one account, spraying a few common passwords across many accounts, and stuffing login pages with credentials leaked elsewhere.

Industry guidance addresses each. Because fast hashes such as SHA-256 let an attacker test guesses at speed, OWASP advises salted, deliberately slow hashing with Argon2id or bcrypt [2]. Bcrypt's cost factor can be raised as hardware improves [3], and Argon2 further raises the cost per guess by demanding memory [4]. For passwords used without a second factor, NIST SP 800-63B-4 sets a 15-character minimum, screens candidates against breached lists, limits failed attempts, and drops composition rules [5]. Against spraying and stuffing, OWASP identifies multi-factor authentication as the strongest defence [6]; time-based one-time passwords (TOTP) are a widespread implementation [7].

Our Flask service implements all four: Argon2id storage, account lockout with per-IP rate limiting, a NIST-aligned policy, and TOTP MFA. Each defence toggles independently, letting us measure its effect in controlled before-and-after experiments.

