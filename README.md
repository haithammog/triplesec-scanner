# TripleSec Network Vulnerability Scanner

A network vulnerability scanner that runs nmap against a target network, enriches every discovered CVE with data from three external intelligence sources, applies a layered post-processing filter pipeline to surface only actionable risk, and delivers both a PDF and a self-contained HTML report to a recipient email address via an n8n webhook.

Operates as a persistent **Flask HTTP service** (called by n8n on a schedule) and as a **standalone CLI tool**.

**No value in the codebase is hardcoded.** Every URL, path, threshold, command, port, and timeout is read from the config file at startup.

---

## Features

- **CVE discovery** via nmap + [vulners.nse](https://github.com/vulnersCom/nmap-vulners)
- **Three enrichment sources** per CVE: NVD (CVSS v3.1 + v4.0), EPSS, OS patch status
- **Four post-processing filters**: severity, exploit likelihood, patch status, version-range applicability
- **Multi-OS patch intelligence**: Ubuntu, Debian, RHEL/CentOS/AlmaLinux/Rocky, Windows
- **Scan delta engine**: New / Persistent / Resolved classification across runs
- **Dual report format**: self-contained HTML + PDF with embedded severity chart
- **n8n webhook integration**: full payload on new findings, digest-only when nothing is new
- **Parallel enrichment**: NVD + EPSS queried concurrently via thread pool
- **Patch cache**: per-CVE/OS file cache with configurable TTL (default 24 h)

---

## Quick Setup on a New Server

Clone the repo and run the steps below. Tested on Ubuntu 24.04.

```bash
# 1. Clone
git clone git@github.com:haithammog/triplesec-scanner.git
cd triplesec-scanner

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install system dependencies
sudo apt install -y nmap

# 4. Install the vulners nmap script
sudo git clone https://github.com/vulnersCom/nmap-vulners \
    /usr/share/nmap/scripts/vulners
sudo nmap --script-updatedb

# 5. Copy the scanner and config
sudo cp vuln-scanner.py /usr/local/bin/vuln-scanner.py
sudo chmod +x /usr/local/bin/vuln-scanner.py
sudo mkdir -p /etc/triplesec
sudo cp config.toml /etc/triplesec/config.toml

# 6. Review and edit the config as needed
sudo nano /etc/triplesec/config.toml

# 7. Install and start the systemd service
sudo cp vuln-scanner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vuln-scanner

# 8. Verify the service is up
curl http://127.0.0.1:8888/health
```

---

## Configuration

The scanner looks for the config file in this order, using the first one found:

1. Path passed via `--config /path/to/config.toml`
2. `/etc/triplesec/config.toml` (system-wide)
3. `~/.triplesec/config.toml` (user-level fallback)

If no config file is found the scanner exits with a clear error listing the paths it searched. It never falls back to internal defaults silently.

All keys are validated at startup. The scanner exits immediately if anything is missing or out of range.

### Config sections

| Section | Purpose |
|---|---|
| `[paths]` | Filesystem locations: output dir, cache dirs, log, nmap binary/script |
| `[flask]` | Host, port, version string for service mode |
| `[filters]` | CVSS min score, EPSS min score, patch cache TTL, unversioned CVE handling |
| `[nmap]` | Full command template with `{nmap_binary}`, `{script}`, `{target}` placeholders |
| `[apis]` | URL templates for NVD, EPSS, Ubuntu, Debian, Red Hat, MSRC |
| `[api_timeouts]` | Per-source HTTP timeout in seconds |
| `[report]` | CVSS thresholds for Critical / High colour-coding |
| `[os_patterns]` | Case-insensitive regex rules for OS family classification |

See [`config.toml`](config.toml) for the full documented template.

---

## Usage

### Flask service mode

Start with no arguments:

```bash
python3 vuln-scanner.py
# or, via systemd:
sudo systemctl start vuln-scanner
```

**Endpoints:**

```
GET  /health
→ {"status":"ok","service":"vuln-scanner","version":"3","port":8888}

POST /scan
→ 202 Accepted  (scan runs in a background daemon thread)
```

**POST /scan request body:**

```json
{
  "network":                "91.221.69.0/24",
  "email":                  "recipient@example.com",
  "webhook_url":            "http://n8n-host:5678/webhook/vuln-scanner",
  "no_patch_check":         false,
  "no_applicability_check": false,
  "unversioned":            "include_flagged",
  "verbose":                false
}
```

`network`, `email`, and `webhook_url` are required. `unversioned` overrides `filters.unversioned_default` for this request only.

### CLI mode

```bash
python3 vuln-scanner.py <network> <email> [flags]
```

**Examples:**

```bash
# Basic scan
python3 vuln-scanner.py 192.168.1.0/24 ops@example.com \
    --webhook-url http://n8n-host:5678/webhook/vuln-scanner

# Skip patch check, verbose filter decisions
python3 vuln-scanner.py 192.168.1.0/24 ops@example.com \
    --webhook-url http://n8n-host:5678/webhook/vuln-scanner \
    --no-patch-check --verbose

# Custom config and output directory
python3 vuln-scanner.py 10.0.0.0/16 ops@example.com \
    --webhook-url http://n8n-host:5678/webhook/vuln-scanner \
    --config ~/my-config.toml --output /tmp/scans

# Exclude CVEs where the running version cannot be confirmed
python3 vuln-scanner.py 192.168.1.0/24 ops@example.com \
    --webhook-url http://n8n-host:5678/webhook/vuln-scanner \
    --unversioned exclude
```

### CLI flags

| Flag | Overrides config key | Effect |
|---|---|---|
| `--config PATH` | — | Load config from this path |
| `--output PATH` | `paths.scan_output_dir` | Override output base directory |
| `--webhook-url URL` | — | **Required.** URL to POST scan results to on completion |
| `--no-patch-check` | — | Skip Filter 3 (patch status lookup) |
| `--no-applicability-check` | — | Skip Filter 4 (NVD version range check) |
| `--unversioned include\|exclude` | `filters.unversioned_default` | Override unversioned CVE handling |
| `--verbose` / `-v` | — | Print per-CVE filter decisions to stdout |

---

## Filter Pipeline

Filters are applied in order. A CVE must pass **all active filters** to appear in the report.

### Filter 1 — Severity

```
CVSS score >= filters.cvss_min_score
```

CVSS v3.1 is used preferentially; v4.0 is used as fallback if v3.1 is absent.

### Filter 2 — Exploit likelihood

```
EPSS score >= filters.epss_min_score
```

EPSS ranges 0.0–1.0. The default threshold of `0.10` requires at least 10% real-world exploit probability.

### Filter 3 — OS patch status

Classifies the host OS using `[os_patterns]`, queries the appropriate source, and excludes CVEs that are already patched.

| OS | Source |
|---|---|
| Ubuntu | Ubuntu Security Notices (`ubuntu.com/security/cves/{cve_id}.json`) |
| Debian | Debian Security Tracker (bulk JSON, fetched once per process run) |
| RHEL / CentOS / AlmaLinux / Rocky | Red Hat Security Data API |
| Windows | Microsoft MSRC CVRF feed |
| Unknown / undetected | Skip — CVE kept, flagged 🔍 |

Patch data is cached per CVE/OS pair with a TTL set in `filters.patch_cache_ttl`. Skipped entirely with `--no-patch-check`.

### Filter 4 — Version range applicability

Compares the service version detected by nmap against the CPE vulnerable version ranges from NVD.

- Version inside range → kept
- Version outside range → excluded
- Version undetectable → behaviour from `filters.unversioned_default`:
  - `include_flagged` — kept with ⚠️ flag
  - `exclude` — silently excluded

Skipped entirely with `--no-applicability-check`.

---

## Scan Output

Each scan produces a timestamped directory under `paths.scan_output_dir`:

```
/var/lib/vuln-scanner/
└── 20240330T143000_91-221-69-0_24/
    ├── raw.json        ← all CVEs from nmap before filtering
    ├── filtered.json   ← CVEs that passed all filters
    ├── delta.json      ← new / persistent / resolved breakdown
    ├── report.html     ← self-contained HTML (no external dependencies)
    └── report.pdf      ← PDF generated with reportlab
```

---

## Delta Engine

After filtering, the current CVE set is compared against the previous scan's state file at `paths.scan_state_dir/<network-slug>.json`:

| Category | Definition |
|---|---|
| **New** 🆕 | Present in current scan, absent from previous |
| **Persistent** 🔁 | Present in both scans |
| **Resolved** ✅ | Absent from current scan, present in previous |

On first run (no state file) all CVEs are classified as New.

**Webhook trigger logic:**
- New CVEs found → POST full report payload (with `pdf_path` and `html_path`)
- No new CVEs → POST digest-only payload (no attachments)

---

## Report Content

Both HTML and PDF reports are identical in content.

1. **Executive Summary** — host count, CVE totals, delta summary (new/persistent/resolved), severity breakdown (Critical/High), filter rejection table
2. **Delta Highlights** — New CVEs table (primary alert section), Resolved CVEs table
3. **Per-Host CVE Table** — all actionable CVEs, sorted New-first then CVSS descending

   Columns: `Host IP | Port/Service | Detected OS | CVE ID | CVSS v3.1 | CVSS v4.0 | EPSS | Severity | Patch Status | Delta | Flags`

4. **Severity Distribution Chart** — Critical/High bar chart split by New vs Persistent (matplotlib, embedded inline as base64)
5. **Appendix** — filtered-out CVEs with reason and CVSS score

**Report flags:**

| Flag | Meaning |
|---|---|
| ⚠️ version unconfirmed | Service version not detected; CVE may not apply to this host |
| 🔍 OS undetected | OS fingerprint unknown; patch check skipped; CVE kept conservatively |
| ⚡ partial enrichment | At least one API call failed for this CVE |

---

## Webhook Payload

**New CVEs found (`trigger: "new_criticals"`):**

```json
{
  "scan_id":   "20240330T143000_91-221-69-0_24",
  "network":   "91.221.69.0/24",
  "email":     "recipient@example.com",
  "timestamp": "2024-03-30T14:30:00+00:00",
  "trigger":   "new_criticals",
  "summary": {
    "total_hosts_scanned":       12,
    "total_cves_found":          47,
    "cves_after_filtering":       8,
    "new_count":                  3,
    "persistent_count":           5,
    "resolved_count":             1,
    "critical_count":             4,
    "high_count":                 4,
    "version_unconfirmed_count":  2
  },
  "pdf_path":  "/var/lib/vuln-scanner/20240330T143000/report.pdf",
  "html_path": "/var/lib/vuln-scanner/20240330T143000/report.html"
}
```

**No new CVEs (`trigger: "digest_only"`):**

```json
{
  "scan_id":        "20240330T143000_91-221-69-0_24",
  "trigger":        "digest_only",
  "summary":        { "new_count": 0, "persistent_count": 5, "resolved_count": 0, "..." : "..." },
  "digest_message": "Daily scan complete. No new findings. 5 persistent CVEs tracked."
}
```

n8n is responsible for reading the payload, attaching report files, and sending the email. The scanner never sends email directly.

---

## Error Handling

| Scenario | Behaviour |
|---|---|
| API failure per CVE | Logged to `paths.error_log`; CVE marked `enrichment_partial: true`; scan continues |
| Patch cache write failure | Warning logged; scan continues without caching |
| Delta state file missing (first run) | All CVEs classified as New |
| nmap failure | Error logged; HTTP 500 from Flask / non-zero exit from CLI |
| Config validation failure | Immediate exit with descriptive message before any work begins |
| Unknown OS / network appliance | Patch check skipped; CVE kept; flagged 🔍 |

---

## File Reference

| File | Purpose |
|---|---|
| `vuln-scanner.py` | Single-file application (Flask service + CLI) |
| `config.toml` | Fully documented configuration template |
| `vuln-scanner.service` | systemd unit file |
