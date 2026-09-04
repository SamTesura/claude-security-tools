#!/usr/bin/env python3
"""Unit tests for the pure logic in mcp_security_server.

Covered: input sanitizers, URL/path validation, argv secret redaction, nmap
output parsing, unique-name generation, bounded output decoding, and
fail-closed scope enforcement (IP / CIDR / hyphen-range / hostname / URL).

Deliberately NOT covered (needs a live target, Docker, or a real MCP transport):
the async @mcp.tool scan wrappers (nmap_basic, sqlmap_scan, ...), which only
shell out to external binaries after the validated argv is built.
"""

import json

import pytest

import mcp_security_server as m


# --------------------------------------------------------------- sanitizers
@pytest.mark.parametrize("target", ["192.168.1.1", "example.com", "host-1.local", "10.0.0.0/24", "a"])
def test_sanitize_target_accepts_valid(target):
    assert m.sanitize_target(target) == target


def test_sanitize_target_rejects_empty():
    with pytest.raises(ValueError):
        m.sanitize_target("")


def test_sanitize_target_rejects_too_long():
    with pytest.raises(ValueError):
        m.sanitize_target("a" * 256)


def test_sanitize_target_rejects_leading_dash():
    with pytest.raises(ValueError):
        m.sanitize_target("-oG")


def test_sanitize_target_rejects_path_traversal():
    with pytest.raises(ValueError):
        m.sanitize_target("a/../b")


def test_sanitize_target_rejects_shell_chars():
    with pytest.raises(ValueError):
        m.sanitize_target("host;rm")


def test_sanitize_input_accepts_plain():
    assert m.sanitize_input("1-1000") == "1-1000"


@pytest.mark.parametrize("bad", ["a;b", "a|b", "a&b", "a$b", "a`b", "a(b)", "a<b", 'a"b', "a\\b"])
def test_sanitize_input_rejects_dangerous_chars(bad):
    with pytest.raises(ValueError):
        m.sanitize_input(bad)


def test_sanitize_input_rejects_leading_dash():
    with pytest.raises(ValueError):
        m.sanitize_input("-flag")


def test_sanitize_url_accepts_http_and_https():
    assert m.sanitize_url("http://localhost/x") == "http://localhost/x"
    assert m.sanitize_url("https://a.com/b?c=1") == "https://a.com/b?c=1"


def test_sanitize_url_rejects_non_http_scheme():
    with pytest.raises(ValueError):
        m.sanitize_url("ftp://a.com")


def test_sanitize_url_rejects_whitespace():
    with pytest.raises(ValueError):
        m.sanitize_url("http://a.com/ b")


def test_sanitize_url_rejects_control_and_shell_chars():
    with pytest.raises(ValueError):
        m.sanitize_url("http://a.com/`id`")


def test_sanitize_url_rejects_too_long():
    with pytest.raises(ValueError):
        m.sanitize_url("http://a.com/" + "a" * 2048)


def test_sanitize_path_accepts_normal():
    assert m.sanitize_path("/usr/share/wordlists/x.txt") == "/usr/share/wordlists/x.txt"


def test_sanitize_path_rejects_traversal():
    with pytest.raises(ValueError):
        m.sanitize_path("/a/../etc/passwd")


def test_sanitize_path_rejects_leading_dash():
    with pytest.raises(ValueError):
        m.sanitize_path("-rf")


def test_sanitize_path_rejects_control_chars():
    with pytest.raises(ValueError):
        m.sanitize_path("/a/\x00/b")


# ------------------------------------------------------------- redact_cmd
def test_redact_cmd_masks_secret_flag_value():
    out = m.redact_cmd(["wpscan", "--url", "http://a.com", "--api-token", "SECRET123"])
    assert "SECRET123" not in out
    assert "***REDACTED***" in out
    assert "--api-token" in out


def test_redact_cmd_masks_url_userinfo():
    out = m.redact_cmd(["curl", "http://user:pass@a.com/x"])
    assert "pass" not in out
    assert "***@a.com" in out


def test_redact_cmd_passes_through_plain_args():
    out = m.redact_cmd(["nmap", "-sS", "127.0.0.1"])
    assert out == "nmap -sS 127.0.0.1"


# ---------------------------------------------------------- nmap parsing
def test_parse_nmap_output_extracts_ports():
    sample = "\n".join([
        "Starting Nmap",
        "PORT     STATE SERVICE VERSION",
        "22/tcp   open  ssh     OpenSSH 8.2",
        "80/tcp   open  http    nginx 1.18",
        "443/tcp  closed https",
        "not a port line",
    ])
    parsed = m.parse_nmap_output(sample)
    ports = parsed["open_ports"]
    assert {"port": "22/tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.2"} in ports
    assert any(p["port"] == "443/tcp" and p["state"] == "closed" for p in ports)
    assert len(ports) == 3


def test_parse_nmap_output_empty_when_no_ports():
    assert m.parse_nmap_output("no ports here")["open_ports"] == []


# ------------------------------------------------------ unique name / decode
def test_unique_name_sanitizes_and_shapes():
    name = m._unique_name("nmap", "1.2.3.4/24", ext="txt")
    assert name.startswith("nmap_")
    assert name.endswith(".txt")
    assert "/" not in name  # slash sanitized away


def test_unique_name_empty_target_defaults():
    name = m._unique_name("tool", "!!!")
    assert "target" in name or name.startswith("tool_")


def test_unique_name_is_unique():
    a = m._unique_name("t", "x")
    b = m._unique_name("t", "x")
    assert a != b


def test_decode_cap_handles_none_and_empty():
    assert m._decode_cap(None) == ""
    assert m._decode_cap(b"") == ""


def test_decode_cap_passthrough_small():
    assert m._decode_cap(b"hello") == "hello"


def test_decode_cap_truncates_over_limit(monkeypatch):
    monkeypatch.setattr(m, "MAX_OUTPUT_BYTES", 10)
    out = m._decode_cap(b"x" * 50)
    assert "output truncated" in out
    assert out.startswith("x" * 10)


# ------------------------------------------------------- scope enforcement
@pytest.fixture
def enforce_scope(tmp_path):
    """Switch the module into fail-closed enforce mode against a temp scope."""
    scope = {
        "cidrs": ["127.0.0.0/8", "192.168.1.0/24"],
        "hosts": ["localhost", "testphp.vulnweb.com"],
        "url_patterns": [r"^https?://testphp\.vulnweb\.com(/.*)?$"],
    }
    f = tmp_path / "scope.json"
    f.write_text(json.dumps(scope))
    old_file = m.SCOPE_FILE
    old_scope = m._SCOPE
    m.SCOPE_FILE = str(f)
    m._load_scope()
    yield
    m.SCOPE_FILE = old_file
    m._SCOPE = old_scope


def test_scope_allows_in_range_ip(enforce_scope):
    m.enforce_scope_target("127.0.0.1")
    m.enforce_scope_target("192.168.1.55")


def test_scope_rejects_out_of_range_ip(enforce_scope):
    with pytest.raises(PermissionError):
        m.enforce_scope_target("8.8.8.8")


def test_scope_allows_listed_host(enforce_scope):
    m.enforce_scope_target("localhost")


def test_scope_rejects_unlisted_host(enforce_scope):
    with pytest.raises(PermissionError):
        m.enforce_scope_target("evil.example.com")


def test_scope_allows_contained_cidr(enforce_scope):
    m.enforce_scope_target("192.168.1.0/28")


def test_scope_rejects_overlapping_but_uncontained_cidr(enforce_scope):
    with pytest.raises(PermissionError):
        m.enforce_scope_target("0.0.0.0/0")


def test_scope_allows_in_range_hyphen_range(enforce_scope):
    m.enforce_scope_target("192.168.1.1-254")


def test_scope_rejects_out_of_range_hyphen_range(enforce_scope):
    with pytest.raises(PermissionError):
        m.enforce_scope_target("8.8.8.1-254")


def test_scope_url_allows_listed_host(enforce_scope):
    m.enforce_scope_url("http://localhost:8080/x")


def test_scope_url_allows_pattern_match(enforce_scope):
    m.enforce_scope_url("http://testphp.vulnweb.com/listproducts.php")


def test_scope_url_rejects_prefix_bypass(enforce_scope):
    # start-anchored .match would let this through; fullmatch must reject it.
    with pytest.raises(PermissionError):
        m.enforce_scope_url("http://testphp.vulnweb.com.attacker.com/x")


def test_scope_url_rejects_unlisted(enforce_scope):
    with pytest.raises(PermissionError):
        m.enforce_scope_url("http://evil.example.com/")


def test_scope_audit_mode_allows_everything():
    # Default import state is audit mode: nothing is rejected.
    old = m._SCOPE
    m._SCOPE = {"mode": "audit"}
    try:
        m.enforce_scope_target("8.8.8.8")
        m.enforce_scope_url("http://anything.example.com/")
    finally:
        m._SCOPE = old
