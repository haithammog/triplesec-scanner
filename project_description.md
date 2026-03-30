# TripleSec Network Vulnerability Scanner — Project Description

## Purpose

A network vulnerability scanner that runs nmap against a target network, enriches every
discovered CVE with data from three external intelligence sources, applies layered
post-processing filters to eliminate noise and surface only actionable risk, and delivers
both a PDF and a self-contained HTML report to a recipient email address via an n8n webhook.

It operates as a persistent Flask HTTP service (called by n8n on a schedule) and as a
standalone CLI tool.

**No value in the codebase is hardcoded.** Every URL, path, threshold, command, port, and
timeout is read from the configuration file at startup. The config file is the single source
of truth.

---

## Configuration File

### Location and loading order

The scanner looks for the config file in this order, using the first one found:

1. Path passed via `--config /path/to/config.toml` CLI flag
2. `/etc/triplesec/config.toml` (system-wide)
3. `~/.triplesec/config.toml` (user-level fallback)

If no config file is found, the scanner exits with a clear error message listing the paths
it searched. It never falls back to internal defaults silently.

### Format: TOML

```toml
# =============================================================================
# TripleSec Vulnerability Scanner — Configuration File
# =============================================================================
# All paths, URLs, thresholds, commands, and timeouts are defined here.
# No values are hardcoded in the application. This file is the single source
# of truth. The scanner validates every key at startup and exits immediately
# if anything is missing or invalid.
# =============================================================================


# -----------------------------------------------------------------------------
# [paths] — Filesystem locations
# All paths support ~ expansion. Directories are created automatically on first
# run if they do not exist. The scanner process must have write access to all
# directories below except install_path (read-only after deployment).
# -----------------------------------------------------------------------------
[paths]

# Absolute path to the scanner script itself.
# Used by the systemd service unit to locate the entrypoint.
install_path = "/usr/local/bin/vuln-scanner.py"

# Root directory for scan output. Each scan run creates a timestamped
# subdirectory here containing raw.json, filtered.json, delta.json,
# report.pdf, and report.html.
scan_output_dir = "/var/lib/vuln-scanner"

# Directory for OS patch status cache files. One JSON file per CVE/OS-slug
# pair, named {CVE-ID}_{os-slug}.json (e.g. CVE-2024-1234_ubuntu-noble.json).
# Files older than filters.patch_cache_ttl seconds are re-fetched automatically.
patch_cache_dir = "~/.triplesec/patch_cache"

# Directory for scan delta state files. One JSON file per target network,
# named by network slug (e.g. 91-221-69-0_24.json). Stores the filtered CVE
# set from the previous scan so new/persistent/resolved deltas can be computed.
# On first run (no state file), all CVEs are classified as New.
scan_state_dir = "~/.triplesec/scan_state"

# Path to the scanner's error log. API failures, cache write errors, and nmap
# errors are appended here. The scan continues after non-fatal errors.
error_log = "/var/lib/vuln-scanner/error.log"

# Path to the vulners.nse nmap script used for CVE discovery.
# Install from: https://github.com/vulnersCom/nmap-vulners
nmap_script = "/usr/share/nmap/scripts/vulners.nse"

# Name or absolute path of the nmap binary.
# Use the full path (e.g. /usr/bin/nmap) if nmap is not on the system PATH.
nmap_binary = "nmap"


# -----------------------------------------------------------------------------
# [flask] — Flask HTTP service settings
# Applied when the scanner runs in service mode (no CLI arguments).
# The service binds only to localhost by default; expose via a reverse proxy
# if external access is needed.
# -----------------------------------------------------------------------------
[flask]

# IP address the Flask service binds to.
# Use 127.0.0.1 to restrict to localhost (recommended).
# Use 0.0.0.0 to accept connections on all interfaces.
host = "127.0.0.1"

# TCP port the Flask service listens on. Must be between 1024 and 65535.
port = 8888

# Version string returned in the /health endpoint response.
# Increment when deploying a new version to allow n8n to detect upgrades.
version = "3"


# -----------------------------------------------------------------------------
# [webhook] — n8n webhook integration
# The scanner POSTs scan results here on completion. n8n is responsible for
# reading the payload, attaching report files, and sending the email.
# The scanner never sends email directly.
# -----------------------------------------------------------------------------
[webhook]

# Full URL of the n8n webhook endpoint.
# Must be a valid HTTP or HTTPS URL. The scanner exits at startup if this
# value is missing or malformed.
url = "http://localhost:5678/webhook/vuln-scanner"


# -----------------------------------------------------------------------------
# [filters] — Post-processing filter thresholds
# These four filters are applied in order to every CVE discovered by nmap.
# A CVE must pass all active filters to appear in the actionable report.
# Individual filters can be disabled per-run via CLI flags.
# -----------------------------------------------------------------------------
[filters]

# Filter 1 — Minimum CVSS base score to include a CVE.
# CVEs below this score are excluded and counted in the report's noise summary.
# CVSS v3.1 is used preferentially; v4.0 is used as fallback if v3.1 is absent.
# Valid range: 0.0–10.0. Recommended for production DC: 7.0 (High and above).
cvss_min_score = 7.0

# Filter 2 — Minimum EPSS score (exploit prediction probability) to include a CVE.
# EPSS ranges from 0.0 (no observed exploitation) to 1.0 (near-certain exploitation).
# Most CVEs score below 0.01. A threshold of 0.10 means at least 10% real-world
# exploit probability is required — deliberately aggressive for a DC environment.
# Valid range: 0.0–1.0.
epss_min_score = 0.10

# Filter 3 — Patch status cache time-to-live in seconds.
# Cached patch status files older than this value are re-fetched from the
# OS-specific patch intelligence source before the filter is applied.
# Default: 86400 seconds (24 hours). Set lower for faster cache refresh.
patch_cache_ttl = 86400

# Filter 4 — Behaviour when nmap cannot detect a service version.
# When a service banner is missing or too generic to extract a version number,
# the NVD version-range applicability check cannot be performed.
# "include_flagged" — include the CVE in the report, mark it with ⚠️ as
#                     version_unconfirmed so analysts know to verify manually.
# "exclude"         — silently exclude the CVE (reduces noise, may miss risks).
# This default is overridable per-run with the --unversioned CLI flag.
unversioned_default = "include_flagged"


# -----------------------------------------------------------------------------
# [nmap] — nmap invocation settings
# The command template is constructed at runtime by substituting the three
# placeholders: {nmap_binary}, {script}, and {target}.
# Modify flags here (e.g. add -T4 for faster scans, --host-timeout 30s) without
# touching the application code.
# -----------------------------------------------------------------------------
[nmap]

# Full nmap command template. Required placeholders:
#   {nmap_binary} — resolved from paths.nmap_binary
#   {script}      — resolved from paths.nmap_script
#   {target}      — the network CIDR passed at scan time (e.g. 91.221.69.0/24)
# -sV  : probe open ports to determine service and version
# -O   : enable OS detection (required for patch status routing in Filter 3)
# -oX -: output results as XML to stdout (parsed directly by the scanner)
command = "{nmap_binary} -sV -O --script {script} {target} -oX -"

# The OS detection flag included in the nmap command.
# Stored separately so the application can verify OS detection is enabled
# before attempting patch status lookups. Change only if your nmap version
# uses a different flag.
os_detection_flag = "-O"


# -----------------------------------------------------------------------------
# [apis] — External API URL templates
# All URLs are templates. Placeholders are substituted at runtime:
#   {cve_id} — the CVE identifier (e.g. CVE-2024-12345)
#   {year}   — the four-digit year extracted from the CVE identifier
# Do not remove placeholders — the scanner validates their presence at startup.
# Update these URLs if an API endpoint changes without needing a code change.
# -----------------------------------------------------------------------------
[apis]

# NVD (National Vulnerability Database) — CVE detail endpoint.
# Returns CVSS v3.1 and v4.0 scores, CPE affected version ranges.
# Used by Filter 1 (severity) and Filter 4 (version-range applicability).
# API key optional but recommended for higher rate limits:
# append &apiKey=YOUR_KEY if needed.
nvd_cve_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

# EPSS (Exploit Prediction Scoring System) by FIRST.org — per-CVE exploit probability.
# Returns epss score (0.0–1.0) and percentile rank.
# Used by Filter 2 (exploit likelihood).
epss_url = "https://api.first.org/data/v1/epss?cve={cve_id}"

# Ubuntu Security Notices — patch status per CVE per Ubuntu codename.
# Returns release status (released/pending/needed/not-affected/ignored).
# Used by Filter 3 for hosts classified as Ubuntu.
ubuntu_usn_url = "https://ubuntu.com/security/cves/{cve_id}.json"

# Debian Security Tracker — bulk JSON dataset for all CVEs.
# Fetched once per process run and cached in memory; individual CVEs are
# looked up within the dataset rather than queried per-CVE.
# Used by Filter 3 for hosts classified as Debian.
debian_tracker_url = "https://security-tracker.debian.org/tracker/data/json"

# Red Hat Security Data API — patch status per CVE for RHEL-family OSes.
# Covers RHEL, CentOS, AlmaLinux, and Rocky Linux.
# Used by Filter 3 for hosts classified as RHEL-family.
redhat_cve_url = "https://access.redhat.com/labs/securitydataapi/cve/{cve_id}.json"

# Microsoft Security Response Center (MSRC) — CVRF XML feed by year.
# {year} is extracted from the CVE ID (e.g. CVE-2024-... → 2024).
# Used by Filter 3 for hosts classified as Windows.
msrc_url = "https://api.msrc.microsoft.com/cvrf/v2.0/updates/{year}"


# -----------------------------------------------------------------------------
# [api_timeouts] — Per-source HTTP request timeout in seconds
# If a source does not respond within the timeout, the request is abandoned,
# the CVE is marked enrichment_partial: true, and the scan continues.
# Increase values on slow or rate-limited networks.
# -----------------------------------------------------------------------------
[api_timeouts]

nvd    = 10   # NVD can be slow under high load — increase if timeouts are frequent
epss   = 10
ubuntu = 10
debian = 30   # Bulk JSON download — larger payload, allow more time
redhat = 10
msrc   = 15   # CVRF XML can be large for years with many advisories


# -----------------------------------------------------------------------------
# [report] — Report rendering thresholds
# Used for CVE severity colour-coding in the HTML/PDF report and for the
# severity distribution chart. Adjust to match your organisation's risk
# classification policy.
# -----------------------------------------------------------------------------
[report]

# CVSS score at or above which a CVE is classified as Critical (red).
critical_min = 9.0

# CVSS score at or above which a CVE is classified as High (orange).
# CVEs between high_min and critical_min are shown as High.
# CVEs below high_min that passed Filter 1 are shown as Medium (yellow).
high_min = 7.0


# -----------------------------------------------------------------------------
# [os_patterns] — OS fingerprint classification rules
# These regex patterns are matched against the OS name string returned by nmap.
# Patterns are evaluated in the order listed — the first match determines the
# OS family used for patch status routing in Filter 3.
# If no pattern matches, the host is classified as "unknown" and patch status
# lookup is skipped (CVE is kept, flagged as OS undetected 🔍).
# Patterns are case-insensitive by default via the (?i) prefix.
# Add new entries here to support additional OS families without code changes.
# -----------------------------------------------------------------------------
[os_patterns]

ubuntu  = "(?i)ubuntu"
debian  = "(?i)debian"
rhel    = "(?i)(red hat|centos|almalinux|rocky)"
windows = "(?i)windows"
```

### Config validation at startup

On startup (both Flask and CLI), the scanner validates the config file:
- All required keys are present
- All paths that must exist are accessible
- `cvss_min_score` is a float between 0.0 and 10.0
- `epss_min_score` is a float between 0.0 and 1.0
- `unversioned_default` is one of `include_flagged` or `exclude`
- `flask.port` is an integer between 1024 and 65535
- All URL templates contain the required `{placeholders}`

Exit with a descriptive error for any validation failure — do not start with a broken config.

---

## Deployment Environment

- **Host:** Ubuntu 24.04 (noble), Python 3
- **Install path:** `paths.install_path`
- **Scan output directory:** `paths.scan_output_dir` — one subdirectory per scan, containing:
  - `raw.json` — full nmap + enrichment output before filtering
  - `filtered.json` — CVEs that passed all filters
  - `delta.json` — diff vs previous scan (new / persistent / resolved)
  - `report.pdf` and `report.html` — final deliverables
- **Patch cache directory:** `paths.patch_cache_dir`
  — one JSON file per CVE/OS-slug pair, filename: `{CVE-ID}_{os-slug}.json`
- **Scan state directory:** `paths.scan_state_dir`
  — one JSON file per target network, stores previous scan's filtered CVE set
- **Error log:** `paths.error_log`
- **Systemd service:** `/etc/systemd/system/vuln-scanner.service`
  - `StandardOutput=journal`, `StandardError=journal`, `Environment=PYTHONUNBUFFERED=1`
  - Enabled + started on boot

### Python dependencies (installed via pip)

```
flask python-nmap reportlab matplotlib requests pillow packaging tomllib
```

(`tomllib` is built into Python 3.11+; install `tomli` as fallback for older versions)

### System dependencies (pre-installed on Ubuntu)

```
nmap dpkg
```

### nmap

- Binary path: `paths.nmap_binary`
- Script path: `paths.nmap_script`
- Full command constructed at runtime from `nmap.command` template
- Used for CVE discovery via service version banner matching

---

## Three CVE Intelligence Sources

Every CVE discovered by nmap is enriched by querying all three sources. All URLs and
timeouts are read from the `[apis]` and `[api_timeouts]` config sections.

### 1. NVD (National Vulnerability Database)
- **URL template:** `apis.nvd_cve_url` — `{cve_id}` substituted at runtime
- **Timeout:** `api_timeouts.nvd`
- **Data retrieved:**
  - CVSS v3.1 base score and vector
  - CVSS v4.0 base score and vector (if published — store alongside v3.1; display both in report)
  - CPE list: affected vendor, product, and version ranges
    (`versionStartIncluding`, `versionEndExcluding`, etc.)
- **Used for:** severity scoring (Filter 1) and version-range applicability check (Filter 4)

### 2. EPSS (Exploit Prediction Scoring System)
- **URL template:** `apis.epss_url` — `{cve_id}` substituted at runtime
- **Timeout:** `api_timeouts.epss`
- **Data retrieved:**
  - `epss` score (float 0.0–1.0): probability this CVE is exploited in the wild
  - `percentile` (float): relative rank among all scored CVEs
- **Used for:** exploit likelihood filtering (Filter 2)

### 3. OS Patch Status — multi-OS patch intelligence
- **Used for:** determining whether a CVE is already patched on the scanned host's OS
- **OS detection:** nmap run with `nmap.os_detection_flag`; fingerprint string classified
  using regex patterns from `[os_patterns]` config section
- **Cache TTL:** `filters.patch_cache_ttl` seconds

Per-OS data sources (all URLs from `[apis]` config section):

**Ubuntu**
- **URL template:** `apis.ubuntu_usn_url`
- **Timeout:** `api_timeouts.ubuntu`
- **OS slug:** `ubuntu-{codename}` (codename extracted from nmap fingerprint)
- **Status values:** `released` → exclude; `not-affected` → exclude;
  `pending` / `needed` / `ignored` / absent → keep

**Debian**
- **URL template:** `apis.debian_tracker_url`
- **Timeout:** `api_timeouts.debian`
- **OS slug:** `debian-{codename}`
- **Behaviour:** bulk JSON — fetch once per process run, cache in memory, look up CVE
  within the dataset (no per-CVE requests)
- **Status values:** `resolved` → exclude; `open` / absent → keep

**RHEL / CentOS / AlmaLinux / Rocky Linux**
- **URL template:** `apis.redhat_cve_url`
- **Timeout:** `api_timeouts.redhat`
- **OS slug:** `rhel-{major-version}`
- **Status values:** check `package_state[].fix_state` per major version;
  `Not affected` / `Fix released` → exclude; `Affected` → keep

**Windows**
- **URL template:** `apis.msrc_url` — `{year}` substituted from CVE ID year
- **Timeout:** `api_timeouts.msrc`
- **OS slug:** `windows-{product-slug}`
- **Format:** CVRF XML — parse for affected products and remediation status
- **Status values:** `Remediation.Type == "Vendor Fix"` and patch KB present → exclude;
  otherwise keep

**Unknown OS / network appliances / undetected**
- Skip patch status check; mark `patch_status: "unknown"`; keep the CVE
- Flag visually in report as `OS undetected` 🔍

---

## Post-Processing Filter Pipeline

Filters are applied in order. A CVE is included in the actionable report only if it
**passes all active filters**. All thresholds read from `[filters]` config section.
Each decision is logged per-CVE when `--verbose` is active.

### Filter 1 — Severity threshold

```
CVSS score >= filters.cvss_min_score
(use v3.1 score; fall back to v4.0 if v3.1 is absent)
```

### Filter 2 — Exploit likelihood threshold

```
EPSS score >= filters.epss_min_score
```

### Filter 3 — OS patch status (multi-OS)

Classify host OS using `[os_patterns]`, query the appropriate source, exclude if patched.

| Detected OS | Source config key |
|---|---|
| Ubuntu | `apis.ubuntu_usn_url` |
| Debian | `apis.debian_tracker_url` |
| RHEL / CentOS / AlmaLinux / Rocky | `apis.redhat_cve_url` |
| Windows | `apis.msrc_url` |
| Unknown / appliance / undetected | Skip — mark `patch_status: unknown`, keep CVE |

Skipped entirely when `--no-patch-check` is passed.

### Filter 4 — Universal applicability check (version range)

1. Retrieve CPE version ranges from NVD (already fetched in enrichment step)
2. Extract service version detected by nmap
3. Evaluate whether detected version falls within the NVD-defined vulnerable range
4. Outside range → exclude. Inside range → keep.
5. Version undetectable → behaviour from `filters.unversioned_default`, overridable
   per-run via `--unversioned`:
   - `include_flagged` — include, mark `version_unconfirmed: true`, show ⚠️ in report
   - `exclude` — silently exclude

Applies universally to all protocols and services. No hardcoded per-protocol logic.

Skipped entirely when `--no-applicability-check` is passed.

---

## Scan Delta Engine

After filtering, compare current CVE set against state file at
`{scan_state_dir}/{network_slug}.json`. Classify each CVE:

| Category | Definition |
|---|---|
| **New** | Present in current scan, absent from previous |
| **Persistent** | Present in both scans |
| **Resolved** | Absent from current, present in previous |

Store delta in `delta.json`. Update state file after every successful scan.
First run (no state file): treat all CVEs as New.

**Email trigger logic:**
- New CVEs found → POST full report payload to `webhook.url`
- No new CVEs → POST digest-only payload (no attachments)

---

## Dual Operating Modes

### Flask service mode (no CLI args)

- Host: `flask.host` — Port: `flask.port`
- `GET /health` → `{"status":"ok","service":"vuln-scanner","version":"{flask.version}","port":{flask.port}}`
- `POST /scan` with JSON body:

```json
{
  "network": "91.221.69.0/24",
  "email": "recipient@example.com",
  "no_patch_check": false,
  "no_applicability_check": false,
  "unversioned": "include_flagged",
  "verbose": false
}
```

Per-request `unversioned` overrides `filters.unversioned_default` from config.

Returns `202 Accepted` immediately; scan runs in a daemon thread; on completion POSTs
results to `webhook.url`.

### CLI mode

```
python3 vuln-scanner.py <network> <email> [flags]
```

---

## CLI Flags

| Flag | Overrides config key | Behaviour |
|---|---|---|
| `--config /path/to/config.toml` | — | Load config from this path |
| `--output /path` | `paths.scan_output_dir` | Base path for output files |
| `--no-patch-check` | — | Skip OS patch status lookup (Filter 3) |
| `--no-applicability-check` | — | Skip NVD version range check (Filter 4) |
| `--unversioned include` | `filters.unversioned_default` | Include unversioned CVEs, flag as unconfirmed |
| `--unversioned exclude` | `filters.unversioned_default` | Silently exclude unversioned CVEs |
| `--verbose` | — | Log each per-CVE filter decision to stdout |

---

## n8n Webhook Integration

Webhook URL read from `webhook.url` in config. Raise a clear error at startup if the key
is missing or the value is not a valid HTTP/HTTPS URL.

**New CVEs found (full report trigger):**

```json
{
  "scan_id": "20240330T143000_91-221-69-0_24",
  "network": "91.221.69.0/24",
  "email": "recipient@example.com",
  "timestamp": "2024-03-30T14:30:00Z",
  "trigger": "new_criticals",
  "summary": {
    "total_hosts_scanned": 12,
    "total_cves_found": 47,
    "cves_after_filtering": 8,
    "new_count": 3,
    "persistent_count": 5,
    "resolved_count": 1,
    "critical_count": 4,
    "high_count": 4,
    "version_unconfirmed_count": 2
  },
  "pdf_path": "/var/lib/vuln-scanner/20240330T143000/report.pdf",
  "html_path": "/var/lib/vuln-scanner/20240330T143000/report.html"
}
```

**No new CVEs (digest trigger):**

```json
{
  "scan_id": "20240330T143000_91-221-69-0_24",
  "network": "91.221.69.0/24",
  "email": "recipient@example.com",
  "timestamp": "2024-03-30T14:30:00Z",
  "trigger": "digest_only",
  "summary": {
    "total_hosts_scanned": 12,
    "total_cves_found": 47,
    "cves_after_filtering": 5,
    "new_count": 0,
    "persistent_count": 5,
    "resolved_count": 0
  },
  "digest_message": "Daily scan complete. No new findings. 5 persistent CVEs tracked."
}
```

n8n handles emailing. The scanner never sends email directly.

---

## Report Content (PDF and HTML)

Both reports identical in content. HTML is self-contained (no external dependencies).
PDF generated with reportlab; HTML uses inline CSS and inline base64 charts.
Severity thresholds for colour-coding from `report.critical_min` and `report.high_min`.

**1. Executive Summary**
- Scan target, date/time, duration
- Host count, total CVEs found, CVEs after filtering
- Delta summary: X new / Y persistent / Z resolved
- Severity breakdown (Critical / High)
- Filter rejection table: filter name → count excluded

**2. Delta Highlights**
- Table of NEW CVEs — sorted by CVSS descending (primary alert section)
- Table of RESOLVED CVEs — confirms remediation
- Persistent CVEs appear in the main table only

**3. Per-Host CVE Table (filtered CVEs only)**

Columns:
`Host IP | Port/Service | Detected OS | CVE ID | CVSS v3.1 | CVSS v4.0 | EPSS | Severity | Patch Status | Delta | Flags`

- **Severity:** colour-coded using `report.critical_min` / `report.high_min`
- **Delta:** New 🆕 / Persistent 🔁 / Resolved ✅
- **Flags:** ⚠️ version unconfirmed; 🔍 OS undetected
- Sort: New first, then by CVSS descending

**4. Severity Distribution Chart**
- Bar chart: Critical / High split across new vs persistent — matplotlib, embedded inline

**5. Appendix — Filtered-Out CVEs**
- Summary table only (CVE ID, reason excluded, CVSS)

---

## Error Handling

- **API failure per CVE:** log to `paths.error_log`, mark `enrichment_partial: true`, continue
- **Patch cache write failure:** log warning, continue without caching
- **Delta state file missing (first run):** treat all CVEs as New
- **nmap failure:** log error, return HTTP 500 from Flask / non-zero exit from CLI
- **Config validation failure:** exit immediately with descriptive message before any work begins
