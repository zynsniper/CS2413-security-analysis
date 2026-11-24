"""Run the controlled experiments E1-E4 and print a results table.

    python run_experiments.py [path-to-wordlist]

Defaults to the bundled sample wordlist. Swap in the real top-10,000 list via
the argument (see experiment/data/README.md). All targets are the local
synthetic accounts only.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import accounts as acct
import attacks
import defenses

HERE = Path(__file__).parent


def e1_hashing(data, wordlist):
    """exp1 (storage): MD5 vs bcrypt vs Argon2id, equal time budget, same dict."""
    md5_hashes = [(a.username, defenses.hash_md5(a.password)) for a in data]
    bc_hashes = [(a.username, defenses.hash_bcrypt(a.password)) for a in data]
    arg_hashes = [(a.username, defenses.hash_argon2(a.password)) for a in data]
    r_md5 = attacks.offline_crack(md5_hashes, wordlist, algorithm="md5", time_budget=5.0)
    r_bc = attacks.offline_crack(bc_hashes, wordlist, algorithm="bcrypt", time_budget=5.0)
    r_arg = attacks.offline_crack(arg_hashes, wordlist, algorithm="argon2", time_budget=5.0)
    return r_md5, r_bc, r_arg


def e2_lockout(data):
    """E2: online brute force with lockout off vs on."""
    off = attacks.ServerModel(data, lockout=None, mfa=False)
    on = attacks.ServerModel(data, lockout=defenses.LockoutPolicy(5, 300), mfa=False)
    guesses = ["000000", "111111", "123456", "password", "qwerty", "abc123", "letmein"]
    return (attacks.online_attack(off, data, mode="brute", guesses=guesses),
            attacks.online_attack(on, data, mode="brute", guesses=guesses))


def e3_mfa(data):
    """E3: credential stuffing (correct passwords, no OTP) with MFA off vs on."""
    off = attacks.ServerModel(data, mfa=False)
    on = attacks.ServerModel(data, mfa=True)
    return (attacks.online_attack(off, data, mode="stuffing"),
            attacks.online_attack(on, data, mode="stuffing"))


def e4_blocklist(data, wordlist):
    """policy: registration with the password policy off (before) vs on (after)."""
    blocklist = {w.lower() for w in wordlist}
    before = [defenses.check_password_policy(a.password, blocklist, enabled=False) for a in data]
    after = [defenses.check_password_policy(a.password, blocklist, enabled=True) for a in data]
    reasons = Counter(reason for ok, reason in after if not ok)
    by_cat = {}
    for a, (ok, _) in zip(data, after):
        c = by_cat.setdefault(a.category, {"accepted": 0, "total": 0})
        c["total"] += 1
        c["accepted"] += ok
    examples = {}
    for a, (ok, reason) in zip(data, after):
        if not ok and reason not in examples:
            examples[reason] = (a.password, defenses.POLICY_MESSAGES[reason])
    return {"accepted_before": sum(ok for ok, _ in before), "accepted_after": sum(ok for ok, _ in after),
            "total": len(data), "reasons": dict(reasons), "by_category": by_cat, "examples": examples}


def main():
    wl_path = sys.argv[1] if len(sys.argv) > 1 else str(HERE / "data" / "wordlist-sample.txt")
    wordlist = attacks.load_wordlist(wl_path)
    data = acct.generate()

    r_md5, r_bc, r_arg = e1_hashing(data, wordlist)
    lk_off, lk_on = e2_lockout(data)
    mfa_off, mfa_on = e3_mfa(data)
    pol = e4_blocklist(data, wordlist)

    print(f"\nWordlist: {wl_path} ({len(wordlist)} words)")
    print(f"Libraries present -> bcrypt: {defenses.BCRYPT_AVAILABLE}, argon2: {defenses.ARGON2_AVAILABLE}")
    print("=" * 60)
    print("exp1  Database breach / storage (offline crack, equal 5s budget)")
    print(f"      MD5     : {r_md5.cracked}/{r_md5.total} cracked ({r_md5.guesses} guesses)")
    print(f"      bcrypt  : {r_bc.cracked}/{r_bc.total} cracked ({r_bc.guesses} guesses)")
    print(f"      Argon2id: {r_arg.cracked}/{r_arg.total} cracked ({r_arg.guesses} guesses)")
    print("exp3  Online guessing / lockout (brute force against one account)")
    print(f"      lockout off: {lk_off.takeovers} takeover(s), {lk_off.attempts} attempts")
    print(f"      lockout on : {lk_on.takeovers} takeover(s), {lk_on.lockouts} blocked-by-lock")
    print("exp5  Reused passwords / MFA (credential stuffing)")
    print(f"      MFA off: {mfa_off.takeovers}/{len(data)} takeovers")
    print(f"      MFA on : {mfa_on.takeovers}/{len(data)} takeovers")
    print("policy  Weak passwords (NIST policy: min-len 15, max 64, common-list reject)")
    print(f"      policy off: {pol['accepted_before']}/{pol['total']} accepted")
    print(f"      policy on : {pol['accepted_after']}/{pol['total']} accepted, "
          f"{pol['total'] - pol['accepted_after']} rejected {pol['reasons']}")
    for cat, c in pol["by_category"].items():
        print(f"        {cat:10s} {c['accepted']}/{c['total']} accepted")
    for reason, (pw, msg) in pol["examples"].items():
        print(f"      e.g. {pw!r} -> REJECTED ({reason}): {msg}")
    print("=" * 60)

    results = {
        "libraries": {"bcrypt": defenses.BCRYPT_AVAILABLE, "argon2": defenses.ARGON2_AVAILABLE},
        "exp1_storage": {"md5_cracked": r_md5.cracked, "bcrypt_cracked": r_bc.cracked,
                         "argon2_cracked": r_arg.cracked, "total": r_md5.total},
        "exp3_lockout": {"lockout_off_takeovers": lk_off.takeovers, "lockout_on_blocked": lk_on.lockouts},
        "exp5_mfa": {"mfa_off_takeovers": mfa_off.takeovers, "mfa_on_takeovers": mfa_on.takeovers},
        "policy": {"accepted_before": pol["accepted_before"], "accepted_after": pol["accepted_after"],
                   "total": pol["total"], "reasons": pol["reasons"], "by_category": pol["by_category"]},
    }
    out = HERE / "results" / "summary.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
