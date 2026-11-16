# CybrX — Project Specification

> **CybrX** is a working name. The product name lives in one config value (`BRAND_NAME`) so it can be changed later in one place.
> This file is the single source of truth. Every AI assistant (Claude, ChatGPT) and every contributor reads `SPEC.md`, `CONVENTIONS.md` and `SECURITY.md` before writing code. If code and this file disagree, this file wins — or this file is updated first.

---

## 1. What we are building

A self-service **vulnerability assessment (VA) platform**. A customer logs in to a web portal, defines what they own, launches scans, sees findings on a dashboard and downloads reports.

**Three scan modules:**

| Module | Input | What it does | Example target |
|---|---|---|---|
| External | Public IPs, CIDRs, DNS hostnames | Port/service discovery from the internet, then CVE and misconfiguration checks | `203.0.113.10`, `mail.example.com` |
| Internal | Private IPs, CIDRs, internal hostnames | Same checks from inside the customer LAN, via an on-prem agent; later authenticated (SSH/SMB) checks | `10.0.0.0/24`, `dc01.corp.local` |
| Web app | URLs | Crawls and tests the application | `https://portal.example.com` |

**Customer structure:**

```
Customer (tenant)          e.g. "Demo Clinic"
 └─ Group (network/env)    e.g. "Demo Clinic — Public Internet"
     ├─ Scope              allow-list, deny-list, start/end dates, who authorised it
     └─ Targets (assets)   per module: IPs / hostnames / URLs
         └─ Scans → Findings
```

A group can hold targets for all three modules.

**Product suite (future):** CybrX Scan (this project) · CybrX Strike (pentest — separate project) · CybrX Comply (PCI DSS — later) · CybrX Govern (governance — separate project) · CybrX Insight (dashboards).

## 2. Decisions so far

| # | Decision | Status |
|---|---|---|
| D-01 | Working name **CybrX**, held in `BRAND_NAME` config | Decided |
| D-02 | Portal language: **English only** for now | Decided |
| D-03 | Hosting: **cloud** (VPS/cloud provider), demo environment first | Decided |
| D-04 | First target customer: unknown — build and test against a **demo environment** | Decided |
| D-05 | **Secure by design** from day one (see `SECURITY.md`) | Decided |
| D-06 | Wrap proven open-source scanners; never write our own scanner engine | Decided |
| D-07 | SQLite in Phase 1, PostgreSQL from Phase 2 (same schema) | Decided |
| D-08 | PCI DSS module, governance portal and pentest portal are **out of scope** for this project; design the data model so they can plug in later (`compliance_tags`) | Decided |
| D-09 | Internal scanning through an **outbound-only agent** installed in the customer network | Decided |
| D-10 | **Strict IP scope:** allow-lists hold IPs/CIDRs only; denied hostnames protect their resolved IPs (`docs/decisions/ADR-002-scope-policy.md`) | Decided |

New decisions are added here (or as `docs/decisions/ADR-NNN.md`) before code depends on them.

## 3. Architecture

```
 Customer browser
       │ HTTPS
 ┌─────▼──────────── Portal tier (internet-facing) ─────────────┐
 │ Reverse proxy (Caddy/Traefik) → Next.js portal → FastAPI API  │
 │ Keycloak (login, MFA)  PostgreSQL  Redis queue  MinIO/S3      │
 └─────┬──────────────────────────────────────────▲─────────────┘
       │ scan jobs (queue)                          │ results
 ┌─────▼───────────────┐                  ┌─────────┴──────────────┐
 │ Scan workers        │                  │ Internal agent (Docker)│
 │ External + Web      │                  │ in customer LAN,       │
 │ no inbound ports    │                  │ outbound mTLS only     │
 └─────────────────────┘                  └────────────────────────┘
       ▲
 Feed updater (daily): NVD, CISA KEV, EPSS, nuclei-templates, Greenbone feed, OSV
```

**Rules of the architecture**
- The portal never runs scanners. Workers never accept inbound connections.
  *Example:* if the portal is compromised, the attacker still cannot reach a scanner or the database directly.
- The internal agent connects **out** to the platform and pulls jobs; the customer opens no inbound firewall ports.
  *Example:* agent at `10.0.0.50` polls `https://api.<platform>/agent/jobs` over mutual TLS.

## 4. Tools per module

| Module | Tools (wrapped, never re-implemented) |
|---|---|
| External | `nmap` (ports, versions) → `nuclei` (CVE/misconfig templates) → `testssl.sh` (TLS). Later: `subfinder` + `httpx` (discovery), Greenbone/OpenVAS (deep network checks) |
| Internal | Same as external, run by the agent; later authenticated checks via Greenbone with SSH/SMB credentials |
| Web app | OWASP ZAP (automation framework), `nuclei` web templates, `katana` (crawler), `nikto`. `sqlmap` only when explicitly enabled for an engagement |

## 5. Vulnerability data (updated daily)

| Feed | Gives us | Example use |
|---|---|---|
| NVD API 2.0 | CVEs, CVSS, affected products (CPE) | `OpenSSH 8.5p1` → matching CVEs |
| nuclei-templates | Checks for new CVEs, often within days | New template confirms a CVE is actually exploitable |
| Greenbone community feed | Network vulnerability tests | Missing Windows patches over SMB |
| CISA KEV | CVEs exploited in the wild | Flag `known_exploited = true`, raise likelihood |
| EPSS | Probability of exploitation (daily) | EPSS 0.94 → fix now; 0.01 → can wait |
| OSV / GitHub Advisories | Library vulnerabilities | jQuery 3.4 → known XSS |

A nightly job syncs all feeds into the database. Stored results can be re-matched against new data without rescanning (e.g. a CVE published today that affects a version seen last week raises an alert).

## 6. Assessment workflow (modelled in the platform)

1. **Scope** — targets, allow/deny lists, dates, test depth, signed authorisation.
2. **Information gathering** — hosts, ports, services, technologies → Assets.
3. **Scanning** — network, host, application, configuration → Findings.
4. **Validation** — every High/Critical is re-checked before it reaches a client report; unconfirmed ones stay `open` with `needs_validation = true`; false ones → `false-positive`.
5. **Risk rating** — risk matrix (see `CONVENTIONS.md`).

## 7. Reports

- PDF (HTML template → WeasyPrint), plus CSV and JSON export.
- Structure: Executive summary → Findings (sorted by risk) → Appendix (scope, tool versions, scan configuration, glossary).
- Never include exploit steps beyond what is needed to reproduce and verify the fix.

## 8. Build phases

Each phase ends with a working **gate**. Do not build ahead of the current phase.

| Phase | Goal | Gate (done when…) |
|---|---|---|
| **0. Readiness** | Repo, docs, isolated lab, tools installed | `nmap -sV <metasploitable-ip>` from Kali lists services; docs committed |
| **1. External engine** | Python engine on Kali: scope guard → nmap → nuclei → normalise → SQLite → HTML report | Full scan of Metasploitable 2 gives a clean, de-duplicated report; a second scan updates `last_seen` instead of duplicating |
| **2. API + data** | FastAPI, PostgreSQL, Redis queue, workers, daily feed updater | Scan launched via API runs in a worker; feeds sync nightly; findings enriched with KEV/EPSS |
| **3. Portal** | Next.js portal, Keycloak login + MFA, customers/groups/targets, dashboard, PDF download | A demo user logs in, creates a group, scans, downloads a PDF |
| **4. Web app module** | ZAP + katana + nuclei web | Juice Shop and DVWA scans produce web findings in the same Finding format |
| **5. Internal agent** | Docker agent, mTLS, outbound-only; then authenticated checks | Agent in the lab network scans a private subnet and reports back |
| **6. Public launch readiness** | Ownership verification, billing, scan limits, hardening, own pentest | Checklist in `SECURITY.md` §9 fully done |

## 9. Phase 0 + Phase 1 task list

Each task is small, has one owner per session (Claude **or** ChatGPT builds, the other reviews), and is committed when its "done when" is met.

| # | Task | Done when… |
|---|---|---|
| 0.1 | Create private repo `cybrx`; commit `SPEC.md`, `CONVENTIONS.md`, `SECURITY.md` | Files on `main` |
| 0.2 | Lab network: host-only `192.168.56.0/24`, no internet route | Kali can reach lab VMs; lab VMs cannot reach the internet |
| 0.3 | Lab targets: Metasploitable 2 (VM), DVWA + OWASP Juice Shop (Docker) | All three reachable from Kali |
| 0.4 | Tools on Kali: Python 3.11 venv, `nmap`, `nuclei` (`nuclei -update-templates`) | `nmap --version`, `nuclei -version` work |
| 1.1 | `scope.py` — scope guard (allow/deny, dates, always-deny list) | Unit tests: `192.168.56.101` allowed; `8.8.8.8`, `169.254.169.254` blocked and logged |
| 1.2 | `runners/nmap_runner.py` — run nmap safely, parse XML → Assets | Metasploitable = one host with open ports and service versions |
| 1.3 | `runners/nuclei_runner.py` — run nuclei safely, parse JSONL | Raw nuclei results returned for lab targets |
| 1.4 | `normalize.py` — tool output → Finding (schema in `CONVENTIONS.md`) + fingerprint | Every finding has all required fields |
| 1.5 | `store.py` — SQLite storage with de-duplication by fingerprint | Second scan updates `last_seen`, no duplicates |
| 1.6 | `report.py` — HTML report sorted by risk then severity | One readable page for the Metasploitable scan |
| 1.7 | `cli.py` — `cybrx scan --group lab --targets 192.168.56.101` | One command runs 1.1 → 1.6 end to end; audit log written |

## 10. Out of scope (for now)

Pentest workbench, governance portal, PCI DSS module, Arabic/RTL, on-prem installation, billing, attack-surface discovery from a domain name, Jira integration, AI triage.
