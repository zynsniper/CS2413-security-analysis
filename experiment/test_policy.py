"""Unit tests for the password policy in defenses.py."""
import defenses

BL = {"password", "123456", "qwertyqwertyqwerty"}


def test_short_password_rejected():
    assert defenses.check_password_policy("Tr0ub4dor&3", BL) == (False, "too_short")


def test_exactly_15_chars_accepted():
    assert defenses.check_password_policy("x7x7x7x7x7x7x7q", BL)[0]


def test_blocklisted_rejected_case_insensitive():
    assert defenses.check_password_policy("QwertyQwertyQwerty", BL) == (False, "blocklisted")


def test_no_composition_rules():
    assert defenses.check_password_policy("copper lantern orbit maple", BL)[0]


def test_64_allowed_65_rejected():
    assert defenses.check_password_policy("a" * 64, BL)[0]
    assert defenses.check_password_policy("a" * 65, BL) == (False, "too_long")


def test_policy_off_accepts_anything():
    assert defenses.check_password_policy("123456", BL, enabled=False) == (True, "accepted")


def test_old_wrapper_still_works():
    assert not defenses.passes_blocklist("password", BL)
