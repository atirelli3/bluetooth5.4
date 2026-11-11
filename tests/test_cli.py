"""The scenario CLI: every scenario reaches its expected outcome, and the exit code says whether they all did."""

import re
import runpy
import sys
from types import SimpleNamespace

import pytest

from bt54 import __main__ as cli
from bt54 import ccm
from bt54.pairing import PairingFailed, Reason
from bt54.toolbox import e

NONCE = bytes(range(13))
AAD = ccm.ll_aad(0x02)


@pytest.mark.parametrize("name", cli.SCENARIOS)
def test_a_scenario_reaches_its_expected_outcome(name, capsys):
    assert cli.main([name]) == 0
    out = capsys.readouterr().out
    assert f"expected: {cli.SCENARIOS[name][0]}" in out
    assert "PASS" in out


def test_all_runs_every_scenario(capsys):
    assert cli.main(["all"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines().count("  PASS") == len(cli.SCENARIOS)
    assert "  FAIL" not in out.splitlines()


def test_the_scenario_names_are_the_documented_ones():
    assert list(cli.SCENARIOS) == [
        "just-works",
        "just-works-mitm",
        "numeric-comparison",
        "numeric-comparison-mitm",
        "numeric-comparison-mitm-blind",
        "knob-bredr",
        "knob-le",
        "ead",
    ]


def test_a_wrong_outcome_prints_both_and_exits_1(monkeypatch, capsys):
    monkeypatch.setitem(cli.SCENARIOS, "just-works", ("paired", lambda: "not paired"))
    assert cli.main(["just-works"]) == 1
    out = capsys.readouterr().out
    assert "expected: paired" in out
    assert "actual:   not paired" in out
    assert "FAIL" in out


def test_one_failing_scenario_fails_all(monkeypatch, capsys):
    monkeypatch.setitem(cli.SCENARIOS, "knob-le", ("a", lambda: "b"))
    assert cli.main(["all"]) == 1
    verdicts = capsys.readouterr().out.splitlines()
    assert verdicts.count("  PASS") == len(cli.SCENARIOS) - 1
    assert verdicts.count("  FAIL") == 1


def raise_dhkey_check_failed():
    raise PairingFailed(Reason.DHKEY_CHECK_FAILED)


def test_a_pairing_failure_is_the_actual_outcome(monkeypatch, capsys):
    monkeypatch.setitem(
        cli.SCENARIOS,
        "just-works",
        ("pairing failed: DHKEY_CHECK_FAILED", raise_dhkey_check_failed),
    )
    assert cli.main(["just-works"]) == 0
    assert "actual:   pairing failed: DHKEY_CHECK_FAILED" in capsys.readouterr().out


@pytest.mark.parametrize("argv", [["nope"], []])
def test_an_unknown_or_missing_scenario_exits_2(argv, capsys):
    with pytest.raises(SystemExit) as exited:
        cli.main(argv)
    assert exited.value.code == 2
    assert "usage" in capsys.readouterr().err


def test_the_session_key_is_e_of_ltk_and_skd(monkeypatch):
    """Vol 6 Part B §5.1.3.1: SK = e(LTK, SKD); the IV is a separate 8-octet draw."""
    ltk, skd, iv = bytes(range(16)), bytes(range(16, 32)), bytes(range(8))
    draws = iter([skd, iv])
    monkeypatch.setattr(cli.secrets, "token_bytes", lambda _: next(draws))
    assert cli._session(ltk) == (e(ltk, skd), iv)


def test_a_relay_that_needs_no_second_key_is_not_a_mitm(monkeypatch):
    """If forwarding Alice's ciphertext unchanged works, Eve sits between nobody."""
    monkeypatch.setattr(cli, "_session", lambda ltk: (bytes(16), bytes(8)))
    assert cli._mitm(False, cli._JUST_WORKS) == "no MitM: both links share a key"


def test_a_number_collision_is_redrawn_so_the_users_still_reject(monkeypatch):
    numbers = iter([5, 5, 7])
    monkeypatch.setattr(
        cli, "exchange", lambda *_: SimpleNamespace(number=next(numbers))
    )
    with pytest.raises(PairingFailed) as failed:
        cli._mitm(True, cli._NUMERIC)
    assert failed.value.reason is Reason.NUMERIC_COMPARISON_FAILED
    assert next(numbers, None) is None


@pytest.mark.parametrize(
    ("name", "shown"),
    [
        pytest.param("just-works", False, id="just-works-shows-nothing"),
        pytest.param("just-works-mitm", False, id="just-works-mitm-shows-nothing"),
        pytest.param("numeric-comparison", True, id="numeric-comparison-shows-it"),
        pytest.param("numeric-comparison-mitm", True, id="nc-mitm-shows-both"),
    ],
)
def test_only_numeric_comparison_shows_a_number(name, shown, capsys):
    """Vol 3 Part H §2.3.5.6.2: Just Works shows no value to the user."""
    cli.main([name])
    assert bool(re.search(r"\b\d{6}\b", capsys.readouterr().out)) is shown


def test_a_packet_that_fails_to_verify_is_the_actual_outcome(monkeypatch, capsys):
    def raise_invalid_tag():
        raise ccm.InvalidTag("bad mic")

    monkeypatch.setitem(
        cli.SCENARIOS, "just-works", ("a packet failed to verify", raise_invalid_tag)
    )
    assert cli.main(["just-works"]) == 0
    assert "actual:   a packet failed to verify" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("rate", "text"),
    [
        pytest.param(10**11, "8 days", id="hardware-1e11"),
        pytest.param(10**10, "83 days", id="hardware-1e10"),
        pytest.param(10**9, "2 years", id="hardware-1e9-is-834-days-so-years"),
        pytest.param(1, "2,284,931,318 years", id="one-trial-per-second"),
    ],
)
def test_the_floor_duration(rate, text):
    """2^56 trials at `rate` trials per second."""
    assert cli._duration(rate) == text


def test_knob_le_prints_the_three_speed_rows(capsys):
    cli.main(["knob-le"])
    out = capsys.readouterr().out
    for label in (
        "hand-rolled CCM, one core",
        "AESCCM in a Python loop, one core",
        "assumed attacker hardware",
    ):
        row = next(line for line in out.splitlines() if label in line)
        assert re.search(r"[\d,]+ trials/s  [\d,]+ (years|days)$", row)


def test_the_native_rate_is_a_positive_number_of_trials_per_second():
    key, nonce = bytes(range(1, 17)), bytes(range(13))
    sealed = ccm.encrypt(key, nonce, b"secret", AAD)
    assert cli._native_rate(sealed, nonce, AAD) > 0


def test_knob_le_reports_a_one_octet_key_that_gets_accepted(monkeypatch):
    monkeypatch.setattr(cli, "exchange", lambda central, peripheral: None)
    assert cli.knob_le().startswith("pairing accepted a 1-octet key; ")


def test_running_the_module_exits_with_the_status_of_main(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["bt54", "knob-bredr"])
    monkeypatch.delitem(sys.modules, "bt54.__main__")
    with pytest.raises(SystemExit) as exited:
        runpy.run_module("bt54.__main__", run_name="__main__")
    assert exited.value.code == 0


def sealed_under(key_octets: int) -> tuple[bytes, bytes]:
    """(key, sealed packet) with a key whose only non-zero octets are the last key_octets (0x01, 0x02, ...)."""
    key = bytes(16 - key_octets) + bytes(range(1, key_octets + 1))
    return key, ccm.encrypt(key, NONCE, b"secret", AAD)


def test_the_brute_force_recovers_a_one_octet_key():
    key, sealed = sealed_under(1)
    assert cli._recover_key(sealed, NONCE, AAD, 1) == (key, 2)


@pytest.mark.parametrize("last", [0x00, 0xFF])
def test_the_brute_force_covers_the_whole_one_octet_space(last):
    key = bytes(15) + bytes([last])
    sealed = ccm.encrypt(key, NONCE, b"secret", AAD)
    assert cli._recover_key(sealed, NONCE, AAD, 1) == (key, last + 1)


@pytest.mark.parametrize("first", [0x00, 0x01, 0xFF])
def test_the_bredr_brute_force_searches_keys_that_keep_their_first_octet(first):
    """Vol 2 Part H §9.4: a 1-octet BR/EDR key is that octet followed by 15 zero octets."""
    key = bytes([first]) + bytes(15)
    sealed = ccm.encrypt(key, NONCE, b"secret", AAD)
    assert cli._recover_key(sealed, NONCE, AAD, 1, bredr=True) == (key, first + 1)


def test_the_bredr_brute_force_does_not_find_an_le_masked_key():
    key = bytes(15) + b"\x07"
    sealed = ccm.encrypt(key, NONCE, b"secret", AAD)
    assert cli._recover_key(sealed, NONCE, AAD, 1, bredr=True) == (None, 256)


def test_knob_bredr_zeroes_the_least_significant_octets(monkeypatch, capsys):
    """The session key it prints is one octet then 15 zero octets (BR/EDR), not the LE layout."""
    monkeypatch.setattr(cli.secrets, "token_bytes", lambda n: b"\x7c" * n)
    assert cli.knob_bredr() == "key recovered"
    assert "session key (1 octet): 7c" + "00" * 15 + "," in capsys.readouterr().out


def test_ead_scenario_reports_a_scanner_that_draws_the_same_key(monkeypatch):
    monkeypatch.setattr(cli.secrets, "token_bytes", lambda n: b"\x7c" * n)
    assert cli.ead_scenario() == "scanner without the key opened the advertisement"


def test_the_brute_force_finds_nothing_in_too_small_a_key_space():
    _, sealed = sealed_under(2)
    assert cli._recover_key(sealed, NONCE, AAD, 1) == (None, 256)


@pytest.mark.parametrize("bredr", [False, True])
def test_the_brute_force_does_not_hide_a_bad_parameter(bredr):
    """ead-and-ccm.md: only InvalidTag means 'wrong key'; a bad nonce must not read as 'key not found'."""
    _, sealed = sealed_under(1)
    with pytest.raises(ValueError, match="nonce must be") as raised:
        cli._recover_key(sealed, bytes(6), AAD, 1, bredr=bredr)
    assert not isinstance(raised.value, ccm.InvalidTag)
