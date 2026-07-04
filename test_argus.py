"""
tests/test_argus.py
===================
Unit tests for Argus v4.0 pure utility functions.

All tests run fully offline — no network calls, no disk I/O, no optional
third-party imports required.  Every target function lives in argus.py and
depends only on the Python standard library.

Run from the project root::

    pytest tests/test_argus.py -v

Or with coverage::

    pytest tests/test_argus.py -v --tb=short --cov=argus --cov-report=term-missing
"""
from __future__ import annotations

import os
import sys

# Allow ``import argus`` when running from repo root or from the tests/ dir.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import argus


# =============================================================================
#  _safe_slug
# =============================================================================

def test_safe_slug_replaces_spaces_with_underscore() -> None:
    assert argus._safe_slug("hello world") == "hello_world"


def test_safe_slug_empty_string_returns_default() -> None:
    assert argus._safe_slug("") == "scan"


def test_safe_slug_whitespace_only_returns_default() -> None:
    assert argus._safe_slug("   ") == "scan"


def test_safe_slug_all_invalid_chars_returns_custom_default() -> None:
    assert argus._safe_slug("!@#$%", default="out") == "out"


def test_safe_slug_strips_leading_and_trailing_dots() -> None:
    assert argus._safe_slug("..foo..") == "foo"


def test_safe_slug_preserves_alphanumeric_dash_dot_underscore() -> None:
    assert argus._safe_slug("a-b.c_d") == "a-b.c_d"


# =============================================================================
#  _normalize_url
# =============================================================================

def test_normalize_url_prepends_https_when_no_scheme() -> None:
    assert argus._normalize_url("example.com") == "https://example.com"


def test_normalize_url_preserves_existing_http() -> None:
    assert argus._normalize_url("http://example.com") == "http://example.com"


def test_normalize_url_preserves_existing_https() -> None:
    assert argus._normalize_url("https://example.com") == "https://example.com"


def test_normalize_url_empty_string_returns_empty() -> None:
    assert argus._normalize_url("") == ""


# =============================================================================
#  _issue_to_dict  /  _issue_severity_counts
# =============================================================================

def test_issue_to_dict_maps_all_five_fields() -> None:
    issue = argus.Issue("HIGH", "XSS", "Reflected XSS", "Detail here", "Fix it")
    assert argus._issue_to_dict(issue) == {
        "severity": "HIGH",
        "category": "XSS",
        "title":    "Reflected XSS",
        "detail":   "Detail here",
        "fix":      "Fix it",
    }


def test_issue_to_dict_fix_can_be_none() -> None:
    issue = argus.Issue("INFO", "Headers", "Missing header", "No X-Frame-Options")
    d = argus._issue_to_dict(issue)
    assert d["fix"] is None


def test_issue_severity_counts_tallies_each_level() -> None:
    issues = [
        argus.Issue("CRITICAL", "A", "t", "d"),
        argus.Issue("HIGH",     "B", "t", "d"),
        argus.Issue("HIGH",     "B", "t", "d"),
        argus.Issue("INFO",     "C", "t", "d"),
    ]
    counts = argus._issue_severity_counts(issues)
    assert counts["CRITICAL"] == 1
    assert counts["HIGH"]     == 2
    assert counts["MEDIUM"]   == 0
    assert counts["LOW"]      == 0
    assert counts["INFO"]     == 1


def test_issue_severity_counts_empty_list() -> None:
    counts = argus._issue_severity_counts([])
    assert all(v == 0 for v in counts.values())


# =============================================================================
#  _caesar_shift
# =============================================================================

def test_caesar_shift_rot13_forward() -> None:
    assert argus._caesar_shift("Hello, World!", 13) == "Uryyb, Jbeyq!"


def test_caesar_shift_rot13_is_own_inverse() -> None:
    text = "The Quick Brown Fox"
    assert argus._caesar_shift(argus._caesar_shift(text, 13), 13) == text


def test_caesar_shift_wraps_around_alphabet() -> None:
    assert argus._caesar_shift("xyz", 3) == "abc"


def test_caesar_shift_preserves_non_alpha_characters() -> None:
    assert argus._caesar_shift("Hello, World!", 0) == "Hello, World!"


# =============================================================================
#  _vigenere_transform
# =============================================================================

def test_vigenere_known_encrypt_output() -> None:
    assert argus._vigenere_transform("HELLO", "KEY") == "RIJVS"


def test_vigenere_encrypt_then_decrypt_is_identity() -> None:
    plaintext = "HELLO WORLD"
    key       = "KEY"
    cipher    = argus._vigenere_transform(plaintext, key)
    assert argus._vigenere_transform(cipher, key, decrypt=True) == plaintext


def test_vigenere_non_alpha_characters_pass_through() -> None:
    # Digits and punctuation must be unchanged by the cipher
    result = argus._vigenere_transform("HELLO 123!", "KEY")
    assert result[5] == " "
    assert result[6:9] == "123"
    assert result[9] == "!"


def test_vigenere_keyword_with_no_letters_raises() -> None:
    with pytest.raises(ValueError, match="letter"):
        argus._vigenere_transform("Hello", "123")


# =============================================================================
#  _english_score
# =============================================================================

def test_english_score_rates_english_above_binary() -> None:
    eng = argus._english_score("the quick brown fox is in the forest")
    raw = argus._english_score("\x00\x01\x02\x03\xff\xfe\xfd")
    assert eng > raw


# =============================================================================
#  _xor_bytes
# =============================================================================

def test_xor_bytes_single_byte_key_round_trip() -> None:
    data = b"hello world"
    key  = b"\x42"
    assert argus._xor_bytes(argus._xor_bytes(data, key), key) == data


def test_xor_bytes_multi_byte_key_round_trip() -> None:
    data = b"argus toolkit"
    key  = b"KEY"
    assert argus._xor_bytes(argus._xor_bytes(data, key), key) == data


def test_xor_bytes_empty_key_raises_value_error() -> None:
    with pytest.raises(ValueError, match="empty"):
        argus._xor_bytes(b"data", b"")


# =============================================================================
#  _xor_score_english
# =============================================================================

def test_xor_score_english_text_beats_binary_bytes() -> None:
    eng = argus._xor_score_english(b"the quick brown fox")
    raw = argus._xor_score_english(bytes(range(20)))
    assert eng > raw


def test_xor_score_non_printable_bytes_yield_negative_score() -> None:
    score = argus._xor_score_english(b"\x00\x01\x02")
    assert score < 0


# =============================================================================
#  _parse_ports
# =============================================================================

def test_parse_ports_single_port() -> None:
    assert argus._parse_ports("80") == [80]


def test_parse_ports_comma_separated_list() -> None:
    assert argus._parse_ports("80,443") == [80, 443]


def test_parse_ports_hyphen_range() -> None:
    assert argus._parse_ports("20-22") == [20, 21, 22]


def test_parse_ports_mixed_list_and_range() -> None:
    assert argus._parse_ports("80,443,8000-8002") == [80, 443, 8000, 8001, 8002]


def test_parse_ports_empty_string_returns_common_ports() -> None:
    assert argus._parse_ports("") == sorted(argus.COMMON_PORTS)


def test_parse_ports_over_limit_raises_value_error() -> None:
    with pytest.raises(ValueError, match="2,000"):
        argus._parse_ports(",".join(str(i) for i in range(1, 2002)))


# =============================================================================
#  _classify_ioc
# =============================================================================

def test_classify_ioc_detects_md5() -> None:
    assert argus._classify_ioc("d41d8cd98f00b204e9800998ecf8427e") == "hash-md5"


def test_classify_ioc_detects_sha1() -> None:
    assert argus._classify_ioc("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash-sha1"


def test_classify_ioc_detects_sha256() -> None:
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert argus._classify_ioc(sha256) == "hash-sha256"


def test_classify_ioc_detects_ipv4() -> None:
    assert argus._classify_ioc("8.8.8.8") == "ip"


def test_classify_ioc_detects_ipv6() -> None:
    assert argus._classify_ioc("2001:db8::1") == "ip"


def test_classify_ioc_detects_https_url() -> None:
    assert argus._classify_ioc("https://evil.com/payload") == "url"


def test_classify_ioc_detects_http_url() -> None:
    assert argus._classify_ioc("http://evil.com") == "url"


def test_classify_ioc_detects_email() -> None:
    assert argus._classify_ioc("attacker@evil.com") == "email"


def test_classify_ioc_detects_domain() -> None:
    assert argus._classify_ioc("evil.com") == "domain"


def test_classify_ioc_returns_unknown_for_unrecognised_input() -> None:
    assert argus._classify_ioc("not_an_ioc!!") == "unknown"


# =============================================================================
#  _scrub_key
# =============================================================================

def test_scrub_key_redacts_key_found_in_message() -> None:
    result = argus._scrub_key("Error: key=ABCD1234 failed", "ABCD1234")
    assert "ABCD1234"      not in result
    assert "***REDACTED***" in result


def test_scrub_key_leaves_message_unchanged_when_key_absent() -> None:
    msg = "Error: something went wrong"
    assert argus._scrub_key(msg, "ABCD1234") == msg


def test_scrub_key_empty_api_key_leaves_message_unchanged() -> None:
    msg = "Error msg"
    assert argus._scrub_key(msg, "") == msg


# =============================================================================
#  _hash_text_value  /  _guess_hash_algorithms
# =============================================================================

def test_hash_text_value_md5_empty_string() -> None:
    # Well-known MD5 of the empty string
    assert argus._hash_text_value("", "md5") == "d41d8cd98f00b204e9800998ecf8427e"


def test_hash_text_value_sha256_hello() -> None:
    # Well-known SHA-256 of "hello"
    expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert argus._hash_text_value("hello", "sha256") == expected


def test_guess_hash_algorithms_maps_lengths_to_known_algo() -> None:
    assert argus._guess_hash_algorithms("a" * 32)  == ["md5"]
    assert argus._guess_hash_algorithms("a" * 40)  == ["sha1"]
    assert argus._guess_hash_algorithms("a" * 64)  == ["sha256"]
    assert argus._guess_hash_algorithms("a" * 128) == ["sha512"]


def test_guess_hash_algorithms_unknown_length_returns_all() -> None:
    assert argus._guess_hash_algorithms("a" * 10) == argus.HASH_ALGORITHMS


# =============================================================================
#  _message_to_bits  /  _bits_to_message
# =============================================================================

def test_bits_round_trip_for_several_strings() -> None:
    for text in ("Hi", "argus", "Hello, World!", ""):
        bits = list(argus._message_to_bits(text))
        assert argus._bits_to_message(bits) == text


def test_message_to_bits_ends_with_null_byte() -> None:
    """The encoder appends a null byte as a stop marker."""
    bits = list(argus._message_to_bits("A"))
    assert bits[-8:] == [0, 0, 0, 0, 0, 0, 0, 0]


# =============================================================================
#  _rot47
# =============================================================================

def test_rot47_known_output() -> None:
    assert argus._rot47("Hello, World!") == "w6==@[ (@C=5P"


def test_rot47_is_own_inverse() -> None:
    """Applying ROT47 twice recovers the original text."""
    text = "Hello, World! 1+2=3"
    assert argus._rot47(argus._rot47(text)) == text


def test_rot47_space_is_unchanged() -> None:
    """Space (ASCII 32) is outside the ROT47 range and must pass through."""
    assert argus._rot47(" ") == " "


# =============================================================================
#  _morse_encode  /  _morse_decode
# =============================================================================

def test_morse_encode_sos() -> None:
    assert argus._morse_encode("SOS") == "... --- ..."


def test_morse_encode_word_space_becomes_slash() -> None:
    encoded = argus._morse_encode("A B")
    assert "/" in encoded


def test_morse_decode_sos() -> None:
    assert argus._morse_decode("... --- ...") == "SOS"


def test_morse_round_trip() -> None:
    text = "ARGUS"
    assert argus._morse_decode(argus._morse_encode(text)) == text


# =============================================================================
#  _beacon_histogram
# =============================================================================

def test_beacon_histogram_empty_input_returns_empty_list() -> None:
    assert argus._beacon_histogram([]) == []


def test_beacon_histogram_all_equal_values_returns_single_line() -> None:
    lines = argus._beacon_histogram([5.0, 5.0, 5.0])
    assert len(lines) == 1
    assert "5.00s" in lines[0]


def test_beacon_histogram_default_bins_produces_eight_lines() -> None:
    intervals = [float(i) for i in range(1, 9)]
    lines = argus._beacon_histogram(intervals, bins=8)
    assert len(lines) == 8


def test_beacon_histogram_custom_bin_count_respected() -> None:
    intervals = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]
    lines = argus._beacon_histogram(intervals, bins=3)
    assert len(lines) == 3
