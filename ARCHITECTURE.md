# Architecture: TripleSec Network Vulnerability Scanner

## Purpose
A network vulnerability scanner that runs nmap against a target, enriches every discovered CVE with NVD, EPSS, and OS patch intelligence, applies a four-stage filter pipeline to eliminate noise, and delivers PDF + HTML reports to n8n via webhook. Used by security teams to track exploitable vulnerabilities across server networks.

## Stack
| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| Framework | Flask (HTTP service mode) |
| External APIs | NVD, EPSS (FIRST.org), Ubuntu USN, Debian Tracker, Red Hat Security, MSRC |
| Report generation | reportlab (PDF), matplotlib (chart), inline base64 HTML |
| Config format | TOML (tomllib / tomli fallback) |
| Runtime | Ubuntu 24.04, systemd service |

## Module Map
| Module | File | Lines | Purpose |
|---|---|---|---|
| Entry point / CLI | vuln-scanner.py | 570–610 | Arg parsing, config loading, mode dispatch |
| Config loader | vuln-scanner.py | 75–155 | find_config, load_config, validate_config, ensure_dirs |
| nmap runner | vuln-scanner.py | 160–260 | run_nmap, XML parser, vulners script extractor |
| CVE enrichment | vuln-scanner.py | 265–360 | enrich_all_cves (parallel), NVD fetch, EPSS fetch |
| Patch status | vuln-scanner.py | 363–490 | get_patch_status, per-OS checkers, file cache with TTL |
| Filter pipeline | vuln-scanner.py | 493–580 | apply_filters (Filters 1–4), version range check |
| Delta engine | vuln-scanner.py | 583–620 | compute_delta, state file read/write |
| Chart generator | vuln-scanner.py | 625–660 | generate_chart → base64 PNG |
| HTML report | vuln-scanner.py | 663–780 | generate_html_report (self-contained) |
| PDF report | vuln-scanner.py | 783–930 | generate_pdf_report (reportlab) |
| Webhook | vuln-scanner.py | 933–945 | post_webhook (url passed in, not from config) |
| Scan orchestrator | vuln-scanner.py | 948–1050 | run_scan (full pipeline) |
| Flask app | vuln-scanner.py | 1053–1115 | GET /health, POST /scan (202 + daemon thread) |
| Config template | config.toml | 1–125 | All keys documented, safe defaults (no [webhook] section) |
| Systemd unit | vuln-scanner.service | 1–20 | Service definition |

## Data Flow
1. `run_nmap` executes nmap via subprocess, parses XML, extracts CVEs per host/port with OS context
2. `enrich_all_cves` fans out NVD + EPSS requests in parallel (ThreadPoolExecutor, 10 workers); Debian bulk JSON fetched once and cached in memory
3. `apply_filters` runs Filters 1–4 in order on the same list, modifying dicts in-place; returns passing subset
4. `compute_delta` compares filtered CVEs against per-network state file; classifies New/Persistent/Resolved
5. Reports (HTML + PDF) and chart generated; results POSTed to webhook URL supplied by the caller (POST body field `webhook_url` in service mode, `--webhook-url` flag in CLI mode)

## Entry Points
| Type | Location | Description |
|---|---|---|
| CLI | vuln-scanner.py:main() | `python3 vuln-scanner.py <network> <email> --webhook-url <url> [flags]` |
| API | vuln-scanner.py GET /health | Health check |
| API | vuln-scanner.py POST /scan | Trigger scan (202 Accepted, runs in daemon thread); requires `network`, `email`, `webhook_url` in body |
| Service | vuln-scanner.service | systemd unit, binds to flask.host:flask.port |

## Current State
- ✅ Full scan pipeline: nmap → enrich → filter → delta → report → webhook
- ✅ All four filters implemented (severity, EPSS, patch status, version range)
- ✅ Multi-OS patch intelligence (Ubuntu, Debian, RHEL, Windows)
- ✅ HTML and PDF reports with embedded chart
- ✅ Flask service mode and CLI mode
- ✅ Config validation at startup, no hardcoded values
- 🔧 ARCHITECTURE.md auto-update hook not firing (likely WSL2/Node path issue)

## Known Issues & Next Priorities
1. Hook `update-architecture.js` not executing on file writes — ARCHITECTURE.md must be updated manually for now
2. MSRC Windows patch check returns `unknown` when the API returns JSON (update listing) rather than CVRF XML — conservative behaviour, CVE is kept

## Conventions Claude Must Follow
- Never hardcode any URL, path, threshold, or timeout — all must come from config or be passed by the caller
- All config keys must be validated in `validate_config()` before the app starts
- API failures per CVE must log to `paths.error_log` and set `enrichment_partial: true` — never abort the scan
- Patch status goes through the file cache with TTL; never fetch directly in the filter hot path without checking cache first
- Update README.md whenever CLI flags, API shape, filters, config keys, output files, webhook payload, or dependencies change
