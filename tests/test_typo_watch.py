"""Hermetic tests for typo_watch (no network)."""

import pytest

from sentinel.findings import Severity
from sentinel.typo_watch import _split, generate_typos, score_candidate


def test_split_valid():
    assert _split("Example.COM") == ("example", "com")


def test_split_invalid():
    with pytest.raises(ValueError):
        _split("notadomain")


def test_omission_and_transposition_present():
    c = generate_typos("example.com", max_candidates=5000)
    assert "xample.com" in c["omission"]          # dropped first 'e'
    assert "eaxmple.com" in c["transposition"]    # swapped 'x'/'a'


def test_homoglyph_and_bitsquat_present():
    c = generate_typos("example.com", max_candidates=5000)
    assert "examp1e.com" in c["homoglyph"]        # l -> 1
    assert "example.co" in c["tld-swap"]


def test_combosquatting_present():
    c = generate_typos("example.com", max_candidates=5000)
    assert "example-login.com" in c["combosquatting"]


def test_candidates_are_deduped_and_capped():
    c = generate_typos("example.com", max_candidates=50)
    total = sum(len(v) for v in c.values())
    assert total <= 50
    assert total == len({x for v in c.values() for x in v})


def test_original_never_included():
    c = generate_typos("example.com", max_candidates=5000)
    assert not any("example.com" in v for v in c.values())


def test_score_all_signals_critical():
    score, sev = score_candidate(
        "examp1e.com", "homoglyph",
        {"resolves": True, "has_mx": True, "in_ct_logs": True})
    assert score == 30 + 25 + 20 + 10
    assert sev == Severity.CRITICAL


def test_score_no_signals_info():
    score, sev = score_candidate(
        "examp1e.com", "omission",
        {"resolves": False, "has_mx": False, "in_ct_logs": False})
    assert score == 0
    assert sev == Severity.INFO


def test_score_dns_only_medium():
    score, sev = score_candidate(
        "examp1e.com", "omission",
        {"resolves": True, "has_mx": False, "in_ct_logs": False})
    assert score == 30
    assert sev == Severity.MEDIUM  # 30
