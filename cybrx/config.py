"""Central configuration. Change the brand name or limits here only."""

from __future__ import annotations

import ipaddress
import os

# Working name; the real brand is chosen later (SPEC.md, D-01).
BRAND_NAME: str = os.environ.get("CYBRX_BRAND_NAME", "CybrX")

# Addresses no scan may ever touch, whatever a scope says (SECURITY.md, SBD-02).
ALWAYS_DENY_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",            # "this network"
        "127.0.0.0/8",          # loopback
        "169.254.0.0/16",       # link-local, includes cloud metadata 169.254.169.254
        "224.0.0.0/4",          # multicast
        "255.255.255.255/32",   # broadcast
        "::/128",               # unspecified
        "::1/128",              # loopback
        "fe80::/10",            # link-local
        "ff00::/8",             # multicast
        "100.100.100.200/32",   # Alibaba Cloud ECS metadata
        "fd00:ec2::254/128",    # AWS metadata (IPv6)
        # Cloud metadata inventory: AWS, Azure, GCP, Oracle, DigitalOcean, Tencent (169.254.x) are
        # covered by 169.254.0.0/16 above. Add new providers here AND to the scanner egress firewall.
        "::ffff:0:0/96",        # IPv4-mapped IPv6 as a CIDR (single IPs are unwrapped and checked as IPv4)
    )
)


def _platform_deny() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """The platform's own addresses, from CYBRX_PLATFORM_DENY (comma-separated IPs/CIDRs)."""
    raw = os.environ.get("CYBRX_PLATFORM_DENY", "")
    return tuple(ipaddress.ip_network(p.strip(), strict=False) for p in raw.split(",") if p.strip())


PLATFORM_DENY_NETWORKS = _platform_deny()

# The platform's own domain names, from CYBRX_PLATFORM_DENY_HOSTNAMES (comma-separated).
# A name also blocks its subdomains BY NAME: "cybrx.example" blocks "api.cybrx.example".
# Only names listed here are resolved, so list EVERY platform hostname (api., portal., ...)
# and put every platform IP/CIDR in CYBRX_PLATFORM_DENY: subdomains cannot be discovered.
PLATFORM_DENY_HOSTNAMES: tuple[str, ...] = tuple(
    h.strip().rstrip(".").lower()
    for h in os.environ.get("CYBRX_PLATFORM_DENY_HOSTNAMES", "").split(",")
    if h.strip()
)

# Run mode. "development" (the default) restricts every scan to the lab networks, whatever a
# scope says (SBD-07). "production" must be set explicitly and requires a platform inventory.
MODE: str = os.environ.get("CYBRX_MODE", "development").strip().lower()
if MODE not in ("development", "production"):
    raise ValueError(f"CYBRX_MODE must be 'development' or 'production', got {MODE!r}")

# Development lab boundary (docs/lab.md). Cannot be widened by a scope's allow-list.
LAB_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(n.strip())
    for n in os.environ.get("CYBRX_LAB_NETWORKS", "192.168.56.0/24").split(",")
    if n.strip()
)

# Largest CIDR a single target may cover (a /16 in IPv4). Bigger ranges are refused.
MAX_CIDR_ADDRESSES: int = int(os.environ.get("CYBRX_MAX_CIDR_ADDRESSES", "65536"))

# Longest target string accepted.
MAX_TARGET_LENGTH: int = 2048
