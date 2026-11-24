"""Generate synthetic user accounts for the controlled experiment.

Only synthetic, randomly generated accounts are produced here. No real user
data is used anywhere in this project.

Four strength categories (25 accounts each by default):
  - weak    : straight from the common-password list
  - medium  : a dictionary word + a few digits/symbol
  - strong  : random mixed-character string
  - passphrase : several random words joined (long but human-ish)

A fixed seed makes the whole set reproducible.
"""
from __future__ import annotations

import json
import random
import string
from dataclasses import dataclass, asdict
from pathlib import Path

SEED = 1337  # fixed so every run produces the same accounts

COMMON = [
    "123456", "password", "qwerty", "abc123", "letmein", "monkey",
    "dragon", "football", "iloveyou", "admin", "welcome", "sunshine",
]
WORDS = [
    "orange", "guitar", "planet", "silver", "forest", "rocket", "cactus",
    "velvet", "harbor", "pixel", " member", "copper", "ember", "tidal",
]


@dataclass
class Account:
    username: str
    password: str
    category: str


def _weak(rng: random.Random) -> str:
    return rng.choice(COMMON)


def _medium(rng: random.Random) -> str:
    word = rng.choice(WORDS).strip().capitalize()
    return f"{word}{rng.randint(0, 999)}{rng.choice('!@#$')}"


def _strong(rng: random.Random) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(12, 16)))


def _passphrase(rng: random.Random) -> str:
    return "-".join(rng.choice(WORDS).strip() for _ in range(4))


GENERATORS = {
    "weak": _weak,
    "medium": _medium,
    "strong": _strong,
    "passphrase": _passphrase,
}


def generate(per_category: int = 25, seed: int = SEED) -> list[Account]:
    rng = random.Random(seed)
    accounts: list[Account] = []
    uid = 0
    for category, gen in GENERATORS.items():
        for _ in range(per_category):
            accounts.append(Account(f"user{uid:03d}", gen(rng), category))
            uid += 1
    return accounts


def save(accounts: list[Account], path: str | Path) -> None:
    Path(path).write_text(json.dumps([asdict(a) for a in accounts], indent=2))


if __name__ == "__main__":
    accts = generate()
    out = Path(__file__).parent / "results" / "accounts.json"
    save(accts, out)
    counts = {c: sum(1 for a in accts if a.category == c) for c in GENERATORS}
    print(f"Generated {len(accts)} synthetic accounts -> {out}")
    print("By category:", counts)
