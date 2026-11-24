"""Simulated attacks for the experiment.

SCOPE: these functions run ONLY against the locally generated synthetic accounts
and their locally computed hashes. Nothing here touches a real system, real
accounts, or the network.

  - offline_crack : dictionary + mangling against a list of (user, hash) pairs.
  - online_attack : brute force / spraying / stuffing against an in-memory
                    server model, on a simulated clock, respecting lockout + MFA.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import defenses


# ------------------------------------------------------------ dictionary ----

def load_wordlist(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return [line.strip() for line in fh if line.strip()]


def mangle(word: str) -> list[str]:
    """A few classic rules. Extend this to match your attacker model."""
    out = {word, word.capitalize(), word.upper(), word + "1", word + "!",
           word + "123", word.replace("o", "0").replace("a", "@")}
    return list(out)


# --------------------------------------------------------------- offline ----

@dataclass
class OfflineResult:
    algorithm: str
    cracked: int
    total: int
    guesses: int
    seconds: float


def offline_crack(hashed, wordlist, *, algorithm, time_budget=5.0, salt=b""):
    """Try to recover passwords from (user, stored_hash) pairs.

    `hashed`   : list of (user, stored) where stored was produced by `algorithm`.
    `algorithm`: "md5" or "argon2" — selects how a candidate is checked.
    `time_budget`: wall-clock seconds; models the "equal time budget" control.
    """
    start = time.monotonic()
    guesses = 0
    cracked = 0
    candidates = [c for w in wordlist for c in mangle(w)]

    for user, stored in hashed:
        found = False
        for cand in candidates:
            if time.monotonic() - start > time_budget:
                break
            guesses += 1
            if algorithm == "md5":
                found = defenses.hash_md5(cand, salt) == stored
            elif algorithm == "bcrypt":
                found = defenses.verify_bcrypt(stored, cand)
            else:  # argon2 / pbkdf2 fallback — intentionally slow to check
                found = defenses.verify_argon2(stored, cand)
            if found:
                cracked += 1
                break
        if time.monotonic() - start > time_budget:
            break
    return OfflineResult(algorithm, cracked, len(hashed), guesses,
                         round(time.monotonic() - start, 3))


# ---------------------------------------------------------------- online ----

@dataclass
class OnlineResult:
    mode: str
    takeovers: int
    attempts: int
    lockouts: int


class ServerModel:
    """In-memory login endpoint with optional lockout and MFA, simulated clock."""

    def __init__(self, accounts, *, lockout=None, mfa=False):
        self.pw = {a.username: a.password for a in accounts}
        self.lockout = lockout
        self.mfa = mfa
        self.secrets = {a.username: defenses.new_totp_secret() for a in accounts}
        self.locked_hits = 0

    def login(self, user, password, now, otp=None):
        if self.lockout and self.lockout.is_locked(user, now):
            self.locked_hits += 1
            return False
        if self.pw.get(user) != password:
            if self.lockout:
                self.lockout.record_failure(user, now)
            return False
        # password correct; MFA is the second factor an attacker usually lacks
        if self.mfa:
            if otp != defenses.totp_now(self.secrets[user], now):
                return False
        if self.lockout:
            self.lockout.record_success(user)
        return True


def online_attack(server, accounts, *, mode, guesses=None, now_start=0.0, step=1.0):
    """mode = 'brute' | 'spray' | 'stuffing'. Clock advances `step` per attempt."""
    now = now_start
    attempts = takeovers = 0
    users = [a.username for a in accounts]
    guesses = guesses or ["123456", "password", "qwerty", "abc123", "letmein"]

    if mode == "brute":            # many guesses, one (first) account
        target = users[0]
        for g in guesses:
            attempts += 1
            now += step
            if server.login(target, g, now):
                takeovers += 1
                break
    elif mode == "spray":          # one guess, every account
        for g in guesses:
            for u in users:
                attempts += 1
                now += step
                if server.login(u, g, now):
                    takeovers += 1
    elif mode == "stuffing":       # breached user:pass pairs (here: the real ones)
        for a in accounts:
            attempts += 1
            now += step
            if server.login(a.username, a.password, now):  # correct pw, no OTP
                takeovers += 1
    return OnlineResult(mode, takeovers, attempts,
                        getattr(server, "locked_hits", 0))
