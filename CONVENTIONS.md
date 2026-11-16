# CybrX — Conventions

Rules every piece of code follows, whichever AI or person writes it. Read with `SPEC.md` and `SECURITY.md`.

---

## 1. Stack

| Layer | Choice | Notes |
|---|---|---|
| Scan engine / workers | Python 3.11+ | Standard library first; add a dependency only when it clearly earns its place |
| Scanners | nmap, nuclei → later testssl.sh, ZAP, katana, nikto, subfinder, httpx, Greenbone | Orchestrate, never re-implement |
| API | FastAPI + SQLAlchemy + Pydantic | Pydantic models validate every input |
| Database | SQLite (Phase 1) → PostgreSQL (Phase 2+) | Same schema; migrations with Alembic from Phase 2 |
| Queue | Redis + Celery (or RQ) | From Phase 2 |
| Portal | Next.js (TypeScript) + Tailwind + shadcn/ui + Recharts | From Phase 3 |
| Identity | Keycloak (OIDC, MFA, per-customer roles) | Never hand-roll authentication |
| Reports | HTML templates → PDF with WeasyPrint | |
| Object storage | MinIO / S3 | Reports and raw scan output |
| Deploy | Docker Compose → Kubernetes later | |

## 2. Repository layout (Phase 1)

```
cybrx/
├── SPEC.md  CONVENTIONS.md  SECURITY.md
├── docs/decisions/           ADR-001-*.md, ...
├── cybrx/
│   ├── config.py             BRAND_NAME, paths, rate limits
│   ├── scope.py              scope guard (runs before every tool)
│   ├── runners/
│   │   ├── nmap_runner.py
│   │   └── nuclei_runner.py
│   ├── normalize.py          tool output → Finding
│   ├── risk.py               likelihood × impact → risk_rating
│   ├── store.py              SQLite, de-duplication
│   ├── report.py             HTML report
│   ├── audit.py              audit log
│   └── cli.py
├── templates/report.html
└── tests/                    pytest, one test file per module
```

## 3. Naming

- Python: `snake_case` for files, functions, variables; `PascalCase` for classes; `UPPER_CASE` for constants.
- One runner per tool, named `<tool>_runner.py`, exposing `run(targets, options) -> RawResult` and `parse(raw) -> list[...]`.
- Brand name only from `config.BRAND_NAME` — never typed into templates or code.
  *Example:* report title = `f"{BRAND_NAME} Vulnerability Report"`.

## 4. Core entities

```
Customer → Group → Scope → Asset → Scan → Finding
```

| Entity | Key fields | Example |
|---|---|---|
| Customer | id, name | `Demo Clinic` |
| Group | id, customer_id, name, modules | `Demo Clinic — Public Internet`, modules = external, web |
| Scope | group_id, allow_list, deny_list, starts_at, ends_at, authorised_by, authorised_at | allow `192.168.56.0/24`, deny `192.168.56.1` |
| Asset | id, group_id, type (ip / hostname / url), value, first_seen, last_seen | `ip`, `192.168.56.101` |
| Scan | id, group_id, module, tool_versions, started_at, finished_at, launched_by, command_lines | `external`, nmap 7.95 + nuclei 3.x |
| Finding | see §5 | |

## 5. Finding schema

**Every tool's output is normalised to this shape.** Nothing downstream (database, dashboard, report) reads raw tool output.

| Field | Type | Meaning | Example |
|---|---|---|---|
| `id` | str | Human ID within a report | `FND-001` |
| `title` | str | Short name | `vsftpd 2.3.4 backdoor` |
| `category` | enum | `injection` \| `authentication` \| `authorization` \| `misconfiguration` \| `exposure` \| `vulnerable-component` \| `other` | `vulnerable-component` |
| `severity` | enum | Technical severity from CVSS or the tool: `critical` \| `high` \| `medium` \| `low` \| `info` | `critical` |
| `cvss` | float \| null | CVSS base score | `9.8` |
| `cve` | list[str] | CVE IDs | `["CVE-2011-2523"]` |
| `likelihood` | enum | `low` \| `medium` \| `high` | `high` |
| `business_impact` | enum | `low` \| `medium` \| `high` (default `medium` until the customer sets asset criticality) | `medium` |
| `risk_rating` | enum | From the risk matrix (§6) | `high` |
| `known_exploited` | bool | In CISA KEV (Phase 2+) | `true` |
| `epss` | float \| null | EPSS probability (Phase 2+) | `0.97` |
| `asset` | str | Host, hostname or URL | `192.168.56.101` |
| `port` | int \| null | | `21` |
| `protocol` | str \| null | | `tcp` |
| `tool` | str | Source tool | `nuclei` |
| `rule_id` | str | Tool's check ID | `CVE-2011-2523` (nuclei template id) |
| `description` | str | What it is | |
| `evidence` | str | What the tool saw — redacted, no secrets | `220 (vsFTPd 2.3.4)` |
| `remediation` | str | How to fix | `Upgrade vsftpd to a maintained version` |
| `references` | list[str] | Links | NVD URL |
| `compliance_tags` | list[str] | Framework mappings (for future PCI/governance modules) | `["PCI-DSS-6.3.3"]` |
| `status` | enum | `open` \| `fixed` \| `accepted-risk` \| `false-positive` \| `verified` | `open` |
| `needs_validation` | bool | High/Critical not yet re-checked | `true` |
| `first_seen` / `last_seen` | datetime (UTC, ISO 8601) | | `2026-11-16T20:00:00Z` |
| `fingerprint` | str | `sha256(asset + "|" + str(port) + "|" + rule_id)` | `9f2c…` |

**Category examples:** SQL injection → `injection`; IDOR → `authorization`; default admin password → `authentication`; directory listing → `misconfiguration`; exposed `.git` folder → `exposure`; outdated OpenSSH with CVEs → `vulnerable-component`.

**De-duplication rule:** same fingerprint across scans = same finding. Update `last_seen` (and evidence if changed); never insert a duplicate. A finding not seen in a later full scan of the same asset becomes `fixed` (Phase 2+).

## 6. Risk rating (severity ≠ risk)

Severity measures the vulnerability. Risk measures what it means for **this** customer.

`risk_rating = matrix(likelihood, business_impact)`

| Likelihood ↓ / Impact → | Low | Medium | High |
|---|---|---|---|
| **High** | Medium | High | Critical |
| **Medium** | Low | Medium | High |
| **Low** | Low | Low | Medium |

- **Likelihood** factors: internet-facing vs internal, attack complexity, privileges needed, user interaction, public exploit available, in CISA KEV, high EPSS.
- **Business impact** factors: data sensitivity, system criticality, disruption, compliance obligations.
- *Example:* outdated jQuery with a known XSS on a public marketing page = likelihood high × impact low → **Medium**. The same flaw on the checkout page handling card data = high × high → **Critical**.
- Dashboards and reports sort by `risk_rating`, then `severity`; both are shown.

## 7. Code rules

- Type hints on every function; docstring on every public function.
- No global state; configuration from `config.py` / environment variables.
- Every external tool call goes through its runner — never `subprocess` elsewhere.
- Times in UTC, ISO 8601.
- Logs: structured (JSON lines), never containing secrets or full credentials.
- Tests: `pytest`; each module has tests; every bug fix adds a test that would have caught it.
  *Example:* `test_scope.py::test_blocks_cloud_metadata_ip`.
- Small commits, one task per commit, message like `1.2 nmap runner: parse XML into assets`.

## 8. Working with two AI assistants

- Start every session by giving the assistant `SPEC.md`, `CONVENTIONS.md` and `SECURITY.md`, then **one** task from SPEC §9.
  *Example prompt:* "Follow the three attached files exactly. Task 1.2: write `runners/nmap_runner.py`. Done when: Metasploitable is parsed into one host with ports and versions. Include tests."
- One assistant builds, the other reviews against these files and `SECURITY.md`.
- If an assistant wants to change a convention, it proposes the change; you decide and update the file first.
- Never paste real secrets, customer IPs or credentials into either assistant — use placeholders like `<API_KEY>`.
