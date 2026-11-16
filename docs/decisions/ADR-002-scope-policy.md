# ADR-002: Strict IP-based scope policy

**Status:** Accepted, 2026-11-16 (after review of task 1.1)

## Context
The first scope guard let a hostname in the allow-list authorise **any** address it resolved to,
and compared denied hostnames by name only. Review showed both could be bypassed:
- allow `approved.lab`, DNS points it at `198.51.100.77` (outside the lab) → was allowed;
- deny `blocked.lab` (= `192.168.56.101`), then submit `192.168.56.101` or another alias → was allowed.

## Decision
1. **Allow-lists hold IPs and CIDRs only.** A hostname or URL target is allowed only if **every** address it
   resolves to is inside the allowed networks. A scope with a hostname in its allow-list is refused.
2. **Deny-lists may hold hostnames.** They are resolved at check time and the addresses they protect are
   blocked whichever way they are reached (IP, alias, CIDR). If a deny entry cannot be resolved, the check
   fails closed.
3. **Platform hostnames** (`CYBRX_PLATFORM_DENY_HOSTNAMES`) are blocked by name, including subdomains, and
   their resolved addresses are protected.
4. **IPv6 forms that embed IPv4** (IPv4-mapped, 6to4, Teredo, NAT64) are rejected as targets: use the IPv4 form.

## Consequences
- Customers authorise by IP/CIDR. Example: allow `203.0.113.10/32`, then scan `https://shop.customer.test`.
- Hostname-based authorisation (useful for cloud/CDN-hosted customer sites whose IPs change) is postponed until
  Phase 6, where it requires **verified ownership** (DNS TXT record) **and pinning** of the approved addresses for
  the whole scan.
- Dynamic DNS: a denied hostname protects the addresses it resolves to **at check time**. Scans re-check scope
  when they start, so a change is picked up on the next scan.
- Runners must scan `Decision.resolved_ips`, not the hostname, so DNS cannot change between check and scan.
