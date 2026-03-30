#!/usr/bin/env python3
"""
TripleSec Network Vulnerability Scanner
Single-file implementation — Flask HTTP service and CLI tool.
All configuration is read from a TOML file; nothing is hardcoded.
"""

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
import sys
import os
import re
import json
import time
import logging
import argparse
import threading
import subprocess
import xml.etree.ElementTree as ET
import base64
import io
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urlparse

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        sys.exit("ERROR: tomllib unavailable. Install with: pip install tomli")

import requests
from flask import Flask, request, jsonify

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from packaging.version import Version, InvalidVersion

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors as rl_colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.enums import TA_CENTER

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CONFIG_SEARCH_PATHS = [
    "/etc/triplesec/config.toml",
    os.path.expanduser("~/.triplesec/config.toml"),
]

REQUIRED_CONFIG_KEYS = [
    ("paths", "install_path"),
    ("paths", "scan_output_dir"),
    ("paths", "patch_cache_dir"),
    ("paths", "scan_state_dir"),
    ("paths", "error_log"),
    ("paths", "nmap_script"),
    ("paths", "nmap_binary"),
    ("flask", "host"),
    ("flask", "port"),
    ("flask", "version"),
    ("filters", "cvss_min_score"),
    ("filters", "epss_min_score"),
    ("filters", "patch_cache_ttl"),
    ("filters", "unversioned_default"),
    ("nmap", "command"),
    ("nmap", "os_detection_flag"),
    ("apis", "nvd_cve_url"),
    ("apis", "epss_url"),
    ("apis", "ubuntu_usn_url"),
    ("apis", "debian_tracker_url"),
    ("apis", "redhat_cve_url"),
    ("apis", "msrc_url"),
    ("api_timeouts", "nvd"),
    ("api_timeouts", "epss"),
    ("api_timeouts", "ubuntu"),
    ("api_timeouts", "debian"),
    ("api_timeouts", "redhat"),
    ("api_timeouts", "msrc"),
    ("report", "critical_min"),
    ("report", "high_min"),
    ("os_patterns", "ubuntu"),
    ("os_patterns", "debian"),
    ("os_patterns", "rhel"),
    ("os_patterns", "windows"),
]

UBUNTU_VERSION_TO_CODENAME = {
    "24.04": "noble",
    "23.10": "mantic",
    "23.04": "lunar",
    "22.04": "jammy",
    "21.10": "impish",
    "21.04": "hirsute",
    "20.10": "groovy",
    "20.04": "focal",
    "18.04": "bionic",
    "16.04": "xenial",
    "14.04": "trusty",
}

# Process-level Debian bulk JSON cache — fetched once, reused across CVEs
_debian_bulk_cache: Optional[dict] = None
_debian_bulk_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Logging — configured after config is loaded
# ---------------------------------------------------------------------------
logger = logging.getLogger("triplesec")


def setup_logging(error_log: str) -> None:
    log_path = Path(error_log).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_path)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Config loading and validation
# ---------------------------------------------------------------------------

def find_config(cli_path: Optional[str] = None) -> Path:
    """Return the config file path, or exit with a clear error."""
    if cli_path:
        p = Path(cli_path).expanduser()
        if p.exists():
            return p
        sys.exit(f"ERROR: Config file not found at specified path: {cli_path}")

    for path_str in CONFIG_SEARCH_PATHS:
        p = Path(path_str).expanduser()
        if p.exists():
            return p

    sys.exit(
        "ERROR: No config file found. Searched:\n"
        + "".join(f"  {p}\n" for p in CONFIG_SEARCH_PATHS)
        + "Pass --config /path/to/config.toml or place the file at one of the above paths."
    )


def load_config(path: Path) -> dict:
    """Load and validate a TOML config file. Exit on any error."""
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    validate_config(cfg)
    return cfg


def validate_config(cfg: dict) -> None:
    """Validate all required keys and value constraints. Exit on failure."""
    errors = []

    for section, key in REQUIRED_CONFIG_KEYS:
        if section not in cfg or key not in cfg[section]:
            errors.append(f"Missing required key: [{section}].{key}")

    if errors:
        sys.exit("Config validation failed:\n" + "\n".join(f"  - {e}" for e in errors))

    cvss_min = cfg["filters"]["cvss_min_score"]
    if not isinstance(cvss_min, (int, float)) or not (0.0 <= float(cvss_min) <= 10.0):
        errors.append("filters.cvss_min_score must be a float between 0.0 and 10.0")

    epss_min = cfg["filters"]["epss_min_score"]
    if not isinstance(epss_min, (int, float)) or not (0.0 <= float(epss_min) <= 1.0):
        errors.append("filters.epss_min_score must be a float between 0.0 and 1.0")

    unversioned = cfg["filters"]["unversioned_default"]
    if unversioned not in ("include_flagged", "exclude"):
        errors.append('filters.unversioned_default must be "include_flagged" or "exclude"')

    port = cfg["flask"]["port"]
    if not isinstance(port, int) or not (1024 <= port <= 65535):
        errors.append("flask.port must be an integer between 1024 and 65535")

    webhook_url = cfg["webhook"]["url"]
    parsed = urlparse(webhook_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        errors.append(f"webhook.url is not a valid HTTP/HTTPS URL: {webhook_url!r}")

    url_checks = [
        ("apis.nvd_cve_url",    cfg["apis"]["nvd_cve_url"],    ["{cve_id}"]),
        ("apis.epss_url",       cfg["apis"]["epss_url"],        ["{cve_id}"]),
        ("apis.ubuntu_usn_url", cfg["apis"]["ubuntu_usn_url"],  ["{cve_id}"]),
        ("apis.debian_tracker_url", cfg["apis"]["debian_tracker_url"], []),
        ("apis.redhat_cve_url", cfg["apis"]["redhat_cve_url"],  ["{cve_id}"]),
        ("apis.msrc_url",       cfg["apis"]["msrc_url"],        ["{year}"]),
    ]
    for key_name, url_val, required_placeholders in url_checks:
        for placeholder in required_placeholders:
            if placeholder not in url_val:
                errors.append(f"{key_name} must contain the placeholder {placeholder!r}")

    if errors:
        sys.exit("Config validation failed:\n" + "\n".join(f"  - {e}" for e in errors))


def ensure_dirs(cfg: dict) -> None:
    """Create required output directories if they don't exist."""
    for key in ("scan_output_dir", "patch_cache_dir", "scan_state_dir"):
        Path(cfg["paths"][key]).expanduser().mkdir(parents=True, exist_ok=True)
    Path(cfg["paths"]["error_log"]).expanduser().parent.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# nmap runner and XML parser
# ---------------------------------------------------------------------------

def run_nmap(cfg: dict, target: str) -> list:
    """
    Run nmap against target using the command template from config.
    Returns a list of CVE dicts with host/port/service/OS context.
    Raises RuntimeError on nmap failure.
    """
    nmap_bin = cfg["paths"]["nmap_binary"]
    script   = cfg["paths"]["nmap_script"]
    cmd_str  = cfg["nmap"]["command"].format(
        nmap_binary=nmap_bin,
        script=script,
        target=target,
    )
    cmd = cmd_str.split()

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("nmap timed out after 1 hour")
    except FileNotFoundError:
        raise RuntimeError(f"nmap binary not found: {nmap_bin!r}")

    if result.returncode != 0 and not result.stdout.strip():
        raise RuntimeError(
            f"nmap failed (exit {result.returncode}): {result.stderr.strip()}"
        )

    return _parse_nmap_xml(result.stdout, cfg)


def _parse_nmap_xml(xml_data: str, cfg: dict) -> list:
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        raise RuntimeError(f"Failed to parse nmap XML output: {e}")

    cves = []

    for host in root.findall("host"):
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host.find("address[@addrtype='ipv6']")
        host_ip = addr_elem.get("addr", "unknown") if addr_elem is not None else "unknown"

        detected_os = _extract_os(host)

        for port in host.findall(".//port"):
            portid   = port.get("portid", "")
            protocol = port.get("protocol", "tcp")

            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            service_elem = port.find("service")
            service_name = product = version = ""
            if service_elem is not None:
                service_name = service_elem.get("name", "")
                product      = service_elem.get("product", "")
                version      = service_elem.get("version", "")
                extra        = service_elem.get("extrainfo", "")
                if extra:
                    version = f"{version} {extra}".strip()

            for script_elem in port.findall("script[@id='vulners']"):
                port_cves = _parse_vulners_script(
                    script_elem, host_ip, portid, protocol,
                    service_name, product, version, detected_os,
                )
                cves.extend(port_cves)

    return cves


def _extract_os(host_elem) -> str:
    os_elem = host_elem.find("os")
    if os_elem is None:
        return ""
    best, best_acc = "", -1
    for osmatch in os_elem.findall("osmatch"):
        acc = int(osmatch.get("accuracy", "0"))
        if acc > best_acc:
            best_acc = acc
            best = osmatch.get("name", "")
    return best


def _parse_vulners_script(
    script_elem, host_ip, portid, protocol,
    service_name, product, version, detected_os,
) -> list:
    cves = []
    seen = set()

    # Structured XML table: script > table[cpe] > table[CVE-ID] > elem[key]
    for cpe_table in script_elem.findall("table"):
        for cve_table in cpe_table.findall("table"):
            cve_id = cve_table.get("key", "")
            if not cve_id.startswith("CVE-"):
                continue
            if cve_id in seen:
                continue

            nmap_cvss = None
            for elem in cve_table.findall("elem"):
                k = elem.get("key", "")
                if k == "cvss":
                    try:
                        nmap_cvss = float(elem.text or "")
                    except (ValueError, TypeError):
                        pass
                elif k == "id" and elem.text:
                    cve_id = elem.text

            seen.add(cve_id)
            cves.append(_make_cve_dict(
                cve_id, host_ip, portid, protocol,
                service_name, product, version, detected_os, nmap_cvss,
            ))

    # Text-output fallback for older vulners script versions
    if not cves:
        output_text = script_elem.get("output", "")
        for m in re.finditer(r"(CVE-\d{4}-\d+)\s+([\d.]+)", output_text):
            cve_id = m.group(1)
            if cve_id in seen:
                continue
            seen.add(cve_id)
            try:
                nmap_cvss = float(m.group(2))
            except ValueError:
                nmap_cvss = None
            cves.append(_make_cve_dict(
                cve_id, host_ip, portid, protocol,
                service_name, product, version, detected_os, nmap_cvss,
            ))

    return cves


def _make_cve_dict(
    cve_id, host_ip, portid, protocol, service_name,
    product, version, detected_os, nmap_cvss,
) -> dict:
    return {
        "cve_id":      cve_id,
        "host_ip":     host_ip,
        "port":        portid,
        "protocol":    protocol,
        "service":     service_name,
        "product":     product,
        "version":     version,
        "detected_os": detected_os,
        "nmap_cvss":   nmap_cvss,
        # Enrichment fields
        "cvss_v31":         None,
        "cvss_v31_vector":  None,
        "cvss_v40":         None,
        "cvss_v40_vector":  None,
        "epss_score":       None,
        "epss_percentile":  None,
        "cpe_ranges":       [],
        "patch_status":     None,
        "enrichment_partial": False,
        "version_unconfirmed": False,
        "os_undetected":    False,
        # Filter tracking
        "filter_excluded_by":      None,
        "filter_exclusion_reason": None,
        # Delta
        "delta": "new",
    }


# ---------------------------------------------------------------------------
# CVE Enrichment — NVD and EPSS (parallel per unique CVE ID)
# ---------------------------------------------------------------------------

def enrich_all_cves(cves: list, cfg: dict, verbose: bool = False) -> None:
    """Enrich CVEs in-place: CVSS scores (NVD) and EPSS scores (parallel)."""
    if not cves:
        return

    unique_ids = list({c["cve_id"] for c in cves})
    _prefetch_debian(cfg)

    enrichment_cache: dict = {}

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_id = {
            executor.submit(_enrich_single_cve, cve_id, cfg): cve_id
            for cve_id in unique_ids
        }
        for future in as_completed(future_to_id):
            cve_id = future_to_id[future]
            try:
                enrichment_cache[cve_id] = future.result()
            except Exception as e:
                logger.error("Enrichment error for %s: %s", cve_id, e)
                enrichment_cache[cve_id] = {"enrichment_partial": True}

    broadcast_keys = (
        "cvss_v31", "cvss_v31_vector", "cvss_v40", "cvss_v40_vector",
        "epss_score", "epss_percentile", "cpe_ranges", "enrichment_partial",
    )
    for cve in cves:
        data = enrichment_cache.get(cve["cve_id"], {})
        for k in broadcast_keys:
            if k in data:
                cve[k] = data[k]


def _enrich_single_cve(cve_id: str, cfg: dict) -> dict:
    result: dict = {"enrichment_partial": False}
    partial = False

    try:
        result.update(_fetch_nvd(cve_id, cfg))
    except Exception as e:
        logger.error("NVD fetch failed for %s: %s", cve_id, e)
        partial = True

    try:
        result.update(_fetch_epss(cve_id, cfg))
    except Exception as e:
        logger.error("EPSS fetch failed for %s: %s", cve_id, e)
        partial = True

    if partial:
        result["enrichment_partial"] = True
    return result


def _fetch_nvd(cve_id: str, cfg: dict) -> dict:
    url     = cfg["apis"]["nvd_cve_url"].format(cve_id=cve_id)
    timeout = cfg["api_timeouts"]["nvd"]
    resp    = requests.get(url, timeout=timeout, headers={"Accept": "application/json"})
    resp.raise_for_status()
    data    = resp.json()

    result: dict = {
        "cvss_v31": None, "cvss_v31_vector": None,
        "cvss_v40": None, "cvss_v40_vector": None,
        "cpe_ranges": [],
    }

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return result

    cve_data = vulns[0].get("cve", {})
    metrics  = cve_data.get("metrics", {})

    for entry in metrics.get("cvssMetricV31", []):
        cvss = entry.get("cvssData", {})
        result["cvss_v31"]        = cvss.get("baseScore")
        result["cvss_v31_vector"] = cvss.get("vectorString")
        break

    for entry in metrics.get("cvssMetricV40", []):
        cvss = entry.get("cvssData", {})
        result["cvss_v40"]        = cvss.get("baseScore")
        result["cvss_v40_vector"] = cvss.get("vectorString")
        break

    ranges = []
    for config_node in cve_data.get("configurations", []):
        for node in config_node.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable", False):
                    ranges.append({
                        "cpe":                   cpe_match.get("criteria", ""),
                        "versionStartIncluding": cpe_match.get("versionStartIncluding"),
                        "versionStartExcluding": cpe_match.get("versionStartExcluding"),
                        "versionEndIncluding":   cpe_match.get("versionEndIncluding"),
                        "versionEndExcluding":   cpe_match.get("versionEndExcluding"),
                    })
    result["cpe_ranges"] = ranges
    return result


def _fetch_epss(cve_id: str, cfg: dict) -> dict:
    url     = cfg["apis"]["epss_url"].format(cve_id=cve_id)
    timeout = cfg["api_timeouts"]["epss"]
    resp    = requests.get(url, timeout=timeout, headers={"Accept": "application/json"})
    resp.raise_for_status()
    data    = resp.json()

    result: dict = {"epss_score": None, "epss_percentile": None}
    items = data.get("data", [])
    if items:
        result["epss_score"]       = float(items[0].get("epss", 0))
        result["epss_percentile"]  = float(items[0].get("percentile", 0))
    return result


# ---------------------------------------------------------------------------
# Patch Status (Filter 3) — per-OS with file cache
# ---------------------------------------------------------------------------

def _prefetch_debian(cfg: dict) -> None:
    """Fetch Debian bulk tracker JSON once per process run."""
    global _debian_bulk_cache
    with _debian_bulk_lock:
        if _debian_bulk_cache is not None:
            return
        try:
            url  = cfg["apis"]["debian_tracker_url"]
            resp = requests.get(url, timeout=cfg["api_timeouts"]["debian"])
            resp.raise_for_status()
            _debian_bulk_cache = resp.json()
        except Exception as e:
            logger.error("Failed to fetch Debian bulk tracker: %s", e)
            _debian_bulk_cache = {}


def classify_os(os_string: str, cfg: dict) -> Optional[str]:
    """Return OS family (ubuntu/debian/rhel/windows) or None if unknown."""
    if not os_string:
        return None
    for family in ("ubuntu", "debian", "rhel", "windows"):
        if re.search(cfg["os_patterns"][family], os_string):
            return family
    return None


def _ubuntu_codename(os_string: str) -> str:
    for codename in UBUNTU_VERSION_TO_CODENAME.values():
        if codename.lower() in os_string.lower():
            return codename
    m = re.search(r"(\d{2}\.\d{2})", os_string)
    if m:
        return UBUNTU_VERSION_TO_CODENAME.get(m.group(1), "focal")
    return "focal"


def _debian_codename(os_string: str) -> str:
    for name in ("bookworm", "bullseye", "buster", "stretch", "jessie", "sid"):
        if name.lower() in os_string.lower():
            return name
    m = re.search(r"[Dd]ebian\s+(\d+)", os_string)
    if m:
        return {"12": "bookworm", "11": "bullseye", "10": "buster", "9": "stretch"}.get(
            m.group(1), "bullseye"
        )
    return "bullseye"


def _rhel_major(os_string: str) -> str:
    m = re.search(r"(\d+)", os_string)
    return m.group(1) if m else "8"


def _cve_year(cve_id: str) -> str:
    m = re.search(r"CVE-(\d{4})-", cve_id)
    return m.group(1) if m else "2024"


def get_patch_status(
    cve_id: str, os_family: str, os_string: str, cfg: dict
) -> str:
    """
    Return 'patched' | 'unpatched' | 'unknown'.
    Results are cached on disk with TTL from config.
    """
    cache_dir = Path(cfg["paths"]["patch_cache_dir"]).expanduser()
    cache_dir.mkdir(parents=True, exist_ok=True)
    ttl = cfg["filters"]["patch_cache_ttl"]

    if os_family == "ubuntu":
        codename = _ubuntu_codename(os_string)
        os_slug  = f"ubuntu-{codename}"
    elif os_family == "debian":
        codename = _debian_codename(os_string)
        os_slug  = f"debian-{codename}"
    elif os_family == "rhel":
        major   = _rhel_major(os_string)
        os_slug = f"rhel-{major}"
    elif os_family == "windows":
        year    = _cve_year(cve_id)
        os_slug = f"windows-{year}"
    else:
        return "unknown"

    cache_file = cache_dir / f"{cve_id}_{os_slug}.json"

    if cache_file.exists():
        age = time.time() - cache_file.stat().st_mtime
        if age < ttl:
            try:
                with open(cache_file) as f:
                    return json.load(f).get("status", "unknown")
            except Exception:
                pass

    try:
        if os_family == "ubuntu":
            status = _check_ubuntu(cve_id, _ubuntu_codename(os_string), cfg)
        elif os_family == "debian":
            status = _check_debian(cve_id, _debian_codename(os_string))
        elif os_family == "rhel":
            status = _check_rhel(cve_id, _rhel_major(os_string), cfg)
        elif os_family == "windows":
            status = _check_windows(cve_id, _cve_year(cve_id), cfg)
        else:
            status = "unknown"
    except Exception as e:
        logger.error("Patch status fetch failed for %s on %s: %s", cve_id, os_slug, e)
        status = "unknown"

    try:
        with open(cache_file, "w") as f:
            json.dump({"status": status, "os_slug": os_slug}, f)
    except Exception as e:
        logger.warning("Cache write failed for %s: %s", cache_file, e)

    return status


def _check_ubuntu(cve_id: str, codename: str, cfg: dict) -> str:
    url  = cfg["apis"]["ubuntu_usn_url"].format(cve_id=cve_id)
    resp = requests.get(url, timeout=cfg["api_timeouts"]["ubuntu"])
    if resp.status_code == 404:
        return "unknown"
    resp.raise_for_status()
    data    = resp.json()
    release = data.get("releases", {}).get(codename, {})
    status  = release.get("status", "")
    return "patched" if status in ("released", "not-affected") else "unpatched"


def _check_debian(cve_id: str, codename: str) -> str:
    global _debian_bulk_cache
    with _debian_bulk_lock:
        data = _debian_bulk_cache or {}
    cve_entry = data.get(cve_id, {})
    packages  = cve_entry.get("packages", {})
    for _pkg, releases in packages.items():
        release_data = releases.get(codename, {})
        if release_data.get("status") == "resolved":
            return "patched"
    return "unpatched" if packages else "unknown"


def _check_rhel(cve_id: str, major: str, cfg: dict) -> str:
    url  = cfg["apis"]["redhat_cve_url"].format(cve_id=cve_id)
    resp = requests.get(url, timeout=cfg["api_timeouts"]["redhat"])
    if resp.status_code == 404:
        return "unknown"
    resp.raise_for_status()
    data = resp.json()
    for pkg in data.get("package_state", []):
        if major in pkg.get("product_name", ""):
            fix_state = pkg.get("fix_state", "")
            if fix_state in ("Not affected", "Fix released"):
                return "patched"
            if fix_state == "Affected":
                return "unpatched"
    return "unknown"


def _check_windows(cve_id: str, year: str, cfg: dict) -> str:
    url  = cfg["apis"]["msrc_url"].format(year=year)
    resp = requests.get(
        url, timeout=cfg["api_timeouts"]["msrc"],
        headers={"Accept": "application/xml, application/json"},
    )
    if resp.status_code == 404:
        return "unknown"
    resp.raise_for_status()

    # Try XML (CVRF) first
    content_type = resp.headers.get("Content-Type", "")
    if "xml" in content_type or resp.content.lstrip()[:5] == b"<?xml":
        try:
            root = ET.fromstring(resp.content)
            # Namespace-agnostic search for CVE element
            for elem in root.iter():
                if elem.tag.endswith("}CVE") or elem.tag == "CVE":
                    if elem.text == cve_id:
                        parent = elem.getparent() if hasattr(elem, "getparent") else None
                        # Look for Remediation sibling
                        vuln_elem = elem.find("..")
                        if vuln_elem is not None:
                            for rem in vuln_elem.iter():
                                if (rem.tag.endswith("}Remediation") or rem.tag == "Remediation"):
                                    if rem.get("Type") == "Vendor Fix":
                                        return "patched"
                        return "unpatched"
        except ET.ParseError:
            pass

    # Fall back to JSON (MSRC /updates/{year} returns JSON listing)
    try:
        data = resp.json()
        # The JSON listing doesn't directly contain CVE patch status.
        # We can't make additional per-update requests here without unbounded calls.
        # Return unknown — the caller will keep the CVE (conservative/safe).
        return "unknown"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Filter Pipeline
# ---------------------------------------------------------------------------

def apply_filters(
    cves: list,
    cfg: dict,
    verbose: bool = False,
    no_patch_check: bool = False,
    no_applicability_check: bool = False,
    unversioned_override: Optional[str] = None,
) -> tuple:
    """
    Apply all four filters in order. Modifies CVE dicts in-place.
    Returns (passing_cves, rejection_counts_by_filter).
    """
    rejection_counts = {
        "severity":     0,
        "epss":         0,
        "patch_status": 0,
        "version_range": 0,
    }
    passing = []

    cvss_min      = float(cfg["filters"]["cvss_min_score"])
    epss_min      = float(cfg["filters"]["epss_min_score"])
    unver_mode    = unversioned_override or cfg["filters"]["unversioned_default"]

    for cve in cves:
        cve_id = cve["cve_id"]

        # ── Filter 1: Severity ────────────────────────────────────────────
        score = cve.get("cvss_v31") or cve.get("cvss_v40") or cve.get("nmap_cvss") or 0.0
        score = float(score)
        if score < cvss_min:
            rejection_counts["severity"] += 1
            cve["filter_excluded_by"]      = "severity"
            cve["filter_exclusion_reason"] = f"CVSS {score:.1f} < {cvss_min}"
            if verbose:
                print(f"  [{cve_id}] EXCLUDED by Filter 1 — CVSS {score:.1f} < {cvss_min}")
            continue

        # ── Filter 2: EPSS ────────────────────────────────────────────────
        epss = cve.get("epss_score")
        if epss is None:
            if verbose:
                print(f"  [{cve_id}] EPSS unavailable — included (enrichment_partial)")
        elif float(epss) < epss_min:
            rejection_counts["epss"] += 1
            cve["filter_excluded_by"]      = "epss"
            cve["filter_exclusion_reason"] = f"EPSS {epss:.4f} < {epss_min}"
            if verbose:
                print(f"  [{cve_id}] EXCLUDED by Filter 2 — EPSS {epss:.4f} < {epss_min}")
            continue

        # ── Filter 3: OS Patch Status ─────────────────────────────────────
        if not no_patch_check:
            os_string = cve.get("detected_os", "")
            os_family = classify_os(os_string, cfg)
            if os_family is None:
                cve["patch_status"] = "unknown"
                cve["os_undetected"] = True
                if verbose:
                    print(f"  [{cve_id}] OS undetected — patch check skipped 🔍")
            else:
                status = get_patch_status(cve_id, os_family, os_string, cfg)
                cve["patch_status"] = status
                if status == "patched":
                    rejection_counts["patch_status"] += 1
                    cve["filter_excluded_by"]      = "patch_status"
                    cve["filter_exclusion_reason"] = f"Already patched ({os_family})"
                    if verbose:
                        print(f"  [{cve_id}] EXCLUDED by Filter 3 — patched on {os_family}")
                    continue

        # ── Filter 4: Version Range Applicability ─────────────────────────
        if not no_applicability_check:
            detected_ver = cve.get("version", "").strip()
            cpe_ranges   = cve.get("cpe_ranges", [])

            if not detected_ver:
                if unver_mode == "exclude":
                    rejection_counts["version_range"] += 1
                    cve["filter_excluded_by"]      = "version_range"
                    cve["filter_exclusion_reason"] = "Version undetected (excluded per config)"
                    if verbose:
                        print(f"  [{cve_id}] EXCLUDED by Filter 4 — version undetected (exclude mode)")
                    continue
                else:
                    cve["version_unconfirmed"] = True
                    if verbose:
                        print(f"  [{cve_id}] Version undetected — included with ⚠️ flag")
            elif cpe_ranges:
                in_range = _version_in_range(detected_ver, cpe_ranges)
                if in_range is False:
                    rejection_counts["version_range"] += 1
                    cve["filter_excluded_by"]      = "version_range"
                    cve["filter_exclusion_reason"] = (
                        f"Version {detected_ver} outside vulnerable range"
                    )
                    if verbose:
                        print(f"  [{cve_id}] EXCLUDED by Filter 4 — {detected_ver} not in range")
                    continue
                elif in_range is None:
                    cve["version_unconfirmed"] = True

        passing.append(cve)
        if verbose:
            epss_str = f"EPSS={cve.get('epss_score', '?')}"
            print(f"  [{cve_id}] INCLUDED — CVSS={score:.1f} {epss_str}")

    return passing, rejection_counts


def _version_in_range(detected: str, cpe_ranges: list) -> Optional[bool]:
    """
    True  — detected version falls within at least one vulnerable range.
    False — outside all ranges (with ranges present).
    None  — comparison not possible (parse error).
    """
    try:
        v = Version(detected.split()[0])
    except InvalidVersion:
        return None

    for rng in cpe_ranges:
        in_this = True
        try:
            si = rng.get("versionStartIncluding")
            se = rng.get("versionStartExcluding")
            ei = rng.get("versionEndIncluding")
            ee = rng.get("versionEndExcluding")
            if si and v < Version(si):
                in_this = False
            if se and v <= Version(se):
                in_this = False
            if ei and v > Version(ei):
                in_this = False
            if ee and v >= Version(ee):
                in_this = False
        except InvalidVersion:
            return None
        if in_this:
            return True

    return False if cpe_ranges else None


# ---------------------------------------------------------------------------
# Scan Delta Engine
# ---------------------------------------------------------------------------

def _network_slug(network: str) -> str:
    return re.sub(r"[./]", "-", network)


def compute_delta(
    filtered_cves: list,
    network: str,
    cfg: dict,
) -> tuple:
    """
    Compare current filtered CVE set against previous scan state file.
    Classifies each CVE as new/persistent. Returns (current_cves, resolved_cves).
    Updates the state file on success.
    """
    state_dir  = Path(cfg["paths"]["scan_state_dir"]).expanduser()
    state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / f"{_network_slug(network)}.json"

    previous: dict = {}
    if state_file.exists():
        try:
            with open(state_file) as f:
                previous = {c["cve_id"]: c for c in json.load(f)}
        except Exception as e:
            logger.error("Failed to read state file %s: %s", state_file, e)

    current_ids = {c["cve_id"] for c in filtered_cves}

    for cve in filtered_cves:
        cve["delta"] = "persistent" if cve["cve_id"] in previous else "new"

    resolved_cves = []
    for cve_id, cve in previous.items():
        if cve_id not in current_ids:
            cve["delta"] = "resolved"
            resolved_cves.append(cve)

    try:
        with open(state_file, "w") as f:
            json.dump(filtered_cves, f, indent=2)
    except Exception as e:
        logger.error("Failed to write state file %s: %s", state_file, e)

    return filtered_cves, resolved_cves


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

def _effective_score(cve: dict) -> float:
    return float(cve.get("cvss_v31") or cve.get("cvss_v40") or cve.get("nmap_cvss") or 0.0)


def _severity_label(score: float, cfg: dict) -> str:
    if score >= cfg["report"]["critical_min"]:
        return "Critical"
    if score >= cfg["report"]["high_min"]:
        return "High"
    return "Medium"


def _severity_color_hex(score: float, cfg: dict) -> str:
    if score >= cfg["report"]["critical_min"]:
        return "#dc3545"
    if score >= cfg["report"]["high_min"]:
        return "#fd7e14"
    return "#ffc107"


def _delta_badge(delta: str) -> str:
    return {"new": "🆕 New", "persistent": "🔁 Persistent", "resolved": "✅ Resolved"}.get(
        delta, delta
    )


def _flags_str(cve: dict) -> str:
    flags = []
    if cve.get("version_unconfirmed"):
        flags.append("⚠️ version unconfirmed")
    if cve.get("os_undetected"):
        flags.append("🔍 OS undetected")
    if cve.get("enrichment_partial"):
        flags.append("⚡ partial enrichment")
    return " ".join(flags)


def _sort_key(cve: dict):
    return (0 if cve.get("delta") == "new" else 1, -_effective_score(cve))


# ---------------------------------------------------------------------------
# Severity Distribution Chart
# ---------------------------------------------------------------------------

def generate_chart(filtered_cves: list, cfg: dict) -> str:
    """Return base64-encoded PNG of severity bar chart (new vs persistent)."""
    crit_min = cfg["report"]["critical_min"]
    high_min = cfg["report"]["high_min"]

    def bucket(cve):
        s = _effective_score(cve)
        if s >= crit_min:
            return "Critical"
        if s >= high_min:
            return "High"
        return "Medium"

    categories = ["Critical", "High", "Medium"]
    new_cvs   = [c for c in filtered_cves if c.get("delta") == "new"]
    pers_cvs  = [c for c in filtered_cves if c.get("delta") == "persistent"]

    def counts(cve_list):
        d = {cat: 0 for cat in categories}
        for c in cve_list:
            d[bucket(c)] += 1
        return [d[cat] for cat in categories]

    new_vals  = counts(new_cvs)
    pers_vals = counts(pers_cvs)

    x     = range(len(categories))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar([i - width / 2 for i in x], new_vals,  width,
           label="New",        color=["#dc3545", "#fd7e14", "#ffc107"])
    ax.bar([i + width / 2 for i in x], pers_vals, width,
           label="Persistent", color=["#a71d2a", "#c65911", "#d39e00"], alpha=0.75)
    ax.set_xticks(list(x))
    ax.set_xticklabels(categories)
    ax.set_ylabel("CVE Count")
    ax.set_title("Severity Distribution: New vs Persistent")
    ax.legend()
    ax.yaxis.get_major_locator().set_params(integer=True)
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=100, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode()


# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------

def _cve_table_rows_html(cve_list: list, cfg: dict) -> str:
    rows = []
    for cve in cve_list:
        score  = _effective_score(cve)
        color  = _severity_color_hex(score, cfg)
        label  = _severity_label(score, cfg)
        v31    = f"{cve['cvss_v31']:.1f}"    if cve.get("cvss_v31")    else "N/A"
        v40    = f"{cve['cvss_v40']:.1f}"    if cve.get("cvss_v40")    else "N/A"
        epss   = f"{cve['epss_score']:.4f}"  if cve.get("epss_score") is not None else "N/A"
        patch  = cve.get("patch_status") or "N/A"
        delta  = _delta_badge(cve.get("delta", ""))
        flags  = _flags_str(cve)
        rows.append(
            f"<tr>"
            f"<td>{cve['host_ip']}</td>"
            f"<td>{cve['port']}/{cve['service']}</td>"
            f"<td>{cve.get('detected_os') or 'Unknown'}</td>"
            f"<td><a href='https://nvd.nist.gov/vuln/detail/{cve['cve_id']}'>"
            f"{cve['cve_id']}</a></td>"
            f"<td>{v31}</td><td>{v40}</td><td>{epss}</td>"
            f"<td style='color:{color};font-weight:bold'>{label}</td>"
            f"<td>{patch}</td><td>{delta}</td><td>{flags}</td>"
            f"</tr>"
        )
    return "\n".join(rows)


def generate_html_report(
    network: str, email: str, scan_id: str,
    scan_start: datetime, scan_duration: float,
    all_cves_raw: list, filtered_cves: list, resolved_cves: list,
    rejection_counts: dict, chart_b64: str, cfg: dict,
) -> str:
    new_cvs   = [c for c in filtered_cves if c.get("delta") == "new"]
    pers_cvs  = [c for c in filtered_cves if c.get("delta") == "persistent"]
    sorted_cvs = sorted(filtered_cves, key=_sort_key)
    excl_cvs   = [c for c in all_cves_raw if c.get("filter_excluded_by")]

    crit_min = cfg["report"]["critical_min"]
    high_min = cfg["report"]["high_min"]
    n_crit   = sum(1 for c in filtered_cves if _effective_score(c) >= crit_min)
    n_high   = sum(1 for c in filtered_cves if high_min <= _effective_score(c) < crit_min)
    n_unver  = sum(1 for c in filtered_cves if c.get("version_unconfirmed"))
    n_hosts  = len({c["host_ip"] for c in all_cves_raw})

    def table_section(title, cve_list):
        if not cve_list:
            return f"<p><em>{title}: none.</em></p>"
        rows = _cve_table_rows_html(cve_list, cfg)
        hdr  = ("<tr><th>Host</th><th>Port/Service</th><th>Detected OS</th>"
                "<th>CVE ID</th><th>CVSS v3.1</th><th>CVSS v4.0</th><th>EPSS</th>"
                "<th>Severity</th><th>Patch Status</th><th>Delta</th><th>Flags</th></tr>")
        return f"<h3>{title}</h3><table>{hdr}{rows}</table>"

    excl_rows = "".join(
        f"<tr><td>{c['cve_id']}</td>"
        f"<td>{c.get('filter_exclusion_reason', '')}</td>"
        f"<td>{c.get('cvss_v31') or c.get('cvss_v40') or c.get('nmap_cvss') or 'N/A'}</td>"
        f"</tr>"
        for c in excl_cvs
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>TripleSec Scan Report — {scan_id}</title>
<style>
body{{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:24px;background:#f8f9fa;color:#212529}}
h1{{color:#1a1a2e;border-bottom:3px solid #dc3545;padding-bottom:8px}}
h2{{color:#16213e;margin-top:28px;border-left:4px solid #fd7e14;padding-left:10px}}
h3{{color:#0f3460}}
table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1);border-radius:6px;overflow:hidden;margin-bottom:18px}}
th{{background:#1a1a2e;color:#fff;padding:9px 11px;text-align:left;font-size:.82em;text-transform:uppercase;letter-spacing:.4px}}
td{{padding:8px 11px;border-bottom:1px solid #e9ecef;font-size:.88em;vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#f1f3f5}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin:18px 0}}
.card{{background:#fff;border-radius:8px;padding:14px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.card .val{{font-size:2em;font-weight:700;color:#1a1a2e}}
.card .lbl{{color:#6c757d;font-size:.82em;margin-top:3px}}
.red{{color:#dc3545}}.orange{{color:#fd7e14}}
a{{color:#0d6efd}}
.chart{{background:#fff;border-radius:8px;padding:14px;box-shadow:0 1px 3px rgba(0,0,0,.1);text-align:center;margin:18px 0}}
.meta{{color:#6c757d;font-size:.88em;margin-bottom:18px}}
footer{{margin-top:36px;color:#6c757d;font-size:.78em;border-top:1px solid #dee2e6;padding-top:9px}}
</style>
</head>
<body>
<h1>TripleSec Vulnerability Scan Report</h1>
<div class="meta">
<strong>Scan ID:</strong> {scan_id} &nbsp;|&nbsp;
<strong>Target:</strong> {network} &nbsp;|&nbsp;
<strong>Date:</strong> {scan_start.strftime('%Y-%m-%d %H:%M:%S UTC')} &nbsp;|&nbsp;
<strong>Duration:</strong> {scan_duration:.1f}s &nbsp;|&nbsp;
<strong>Recipient:</strong> {email}
</div>

<h2>1. Executive Summary</h2>
<div class="grid">
  <div class="card"><div class="val">{n_hosts}</div><div class="lbl">Hosts Scanned</div></div>
  <div class="card"><div class="val">{len(all_cves_raw)}</div><div class="lbl">CVEs Found</div></div>
  <div class="card"><div class="val">{len(filtered_cves)}</div><div class="lbl">After Filtering</div></div>
  <div class="card"><div class="val red">{len(new_cvs)}</div><div class="lbl">New 🆕</div></div>
  <div class="card"><div class="val">{len(pers_cvs)}</div><div class="lbl">Persistent 🔁</div></div>
  <div class="card"><div class="val">{len(resolved_cves)}</div><div class="lbl">Resolved ✅</div></div>
  <div class="card"><div class="val red">{n_crit}</div><div class="lbl">Critical</div></div>
  <div class="card"><div class="val orange">{n_high}</div><div class="lbl">High</div></div>
</div>

<h3>Filter Rejection Summary</h3>
<table>
<tr><th>Filter</th><th>CVEs Excluded</th></tr>
<tr><td>Filter 1 — Severity (CVSS &lt; {cfg['filters']['cvss_min_score']})</td><td>{rejection_counts.get('severity',0)}</td></tr>
<tr><td>Filter 2 — EPSS (score &lt; {cfg['filters']['epss_min_score']})</td><td>{rejection_counts.get('epss',0)}</td></tr>
<tr><td>Filter 3 — Patch Status (already patched)</td><td>{rejection_counts.get('patch_status',0)}</td></tr>
<tr><td>Filter 4 — Version Range (outside vulnerable range)</td><td>{rejection_counts.get('version_range',0)}</td></tr>
</table>

<h2>2. Delta Highlights</h2>
{table_section(f"New CVEs 🆕 ({len(new_cvs)})", new_cvs)}
{table_section(f"Resolved CVEs ✅ ({len(resolved_cves)})", resolved_cves)}

<h2>3. Per-Host CVE Table (Filtered)</h2>
{table_section(f"All Actionable CVEs ({len(sorted_cvs)})", sorted_cvs)}

<h2>4. Severity Distribution Chart</h2>
<div class="chart">
  <img src="data:image/png;base64,{chart_b64}" alt="Severity chart" style="max-width:100%">
</div>

<h2>5. Appendix — Filtered-Out CVEs</h2>
{'<p><em>No CVEs were filtered out.</em></p>' if not excl_cvs else
 '<table><tr><th>CVE ID</th><th>Reason Excluded</th><th>CVSS</th></tr>'
 + excl_rows + '</table>'}

<footer>Generated by TripleSec Vulnerability Scanner &nbsp;|&nbsp;
{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</footer>
</body>
</html>"""


# ---------------------------------------------------------------------------
# PDF Report (reportlab)
# ---------------------------------------------------------------------------

def generate_pdf_report(
    output_path: Path,
    network: str, email: str, scan_id: str,
    scan_start: datetime, scan_duration: float,
    all_cves_raw: list, filtered_cves: list, resolved_cves: list,
    rejection_counts: dict, chart_b64: str, cfg: dict,
) -> None:
    doc = SimpleDocTemplate(
        str(output_path), pagesize=A4,
        rightMargin=1.5 * cm, leftMargin=1.5 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
    )
    styles   = getSampleStyleSheet()
    s_title  = ParagraphStyle("ts_title",  parent=styles["Heading1"], fontSize=17,
                               textColor=rl_colors.HexColor("#1a1a2e"), spaceAfter=5)
    s_h2     = ParagraphStyle("ts_h2",     parent=styles["Heading2"], fontSize=12,
                               textColor=rl_colors.HexColor("#16213e"), spaceAfter=4)
    s_h3     = ParagraphStyle("ts_h3",     parent=styles["Heading3"], fontSize=10,
                               textColor=rl_colors.HexColor("#0f3460"), spaceAfter=3)
    s_body   = ParagraphStyle("ts_body",   parent=styles["Normal"],   fontSize=8.5)
    s_cell   = ParagraphStyle("ts_cell",   parent=styles["Normal"],   fontSize=7,
                               wordWrap="CJK")

    crit_min  = cfg["report"]["critical_min"]
    high_min  = cfg["report"]["high_min"]
    new_cvs   = [c for c in filtered_cves if c.get("delta") == "new"]
    pers_cvs  = [c for c in filtered_cves if c.get("delta") == "persistent"]
    sorted_cvs = sorted(filtered_cves, key=_sort_key)
    excl_cvs   = [c for c in all_cves_raw if c.get("filter_excluded_by")]
    n_crit     = sum(1 for c in filtered_cves if _effective_score(c) >= crit_min)
    n_high     = sum(1 for c in filtered_cves if high_min <= _effective_score(c) < crit_min)
    n_hosts    = len({c["host_ip"] for c in all_cves_raw})

    _DARK  = rl_colors.HexColor("#1a1a2e")
    _LIGHT = rl_colors.HexColor("#f8f9fa")
    _GRID  = rl_colors.HexColor("#dee2e6")

    def base_table_style():
        return [
            ("BACKGROUND", (0, 0), (-1, 0), _DARK),
            ("TEXTCOLOR",  (0, 0), (-1, 0), rl_colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 7.5),
            ("GRID",       (0, 0), (-1, -1), 0.3, _GRID),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [rl_colors.white, _LIGHT]),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("PADDING",    (0, 0), (-1, -1), 3),
        ]

    story = []
    story.append(Paragraph("TripleSec Vulnerability Scan Report", s_title))
    story.append(Paragraph(
        f"<b>Scan ID:</b> {scan_id} &nbsp; <b>Target:</b> {network} &nbsp; "
        f"<b>Date:</b> {scan_start.strftime('%Y-%m-%d %H:%M:%S UTC')} &nbsp; "
        f"<b>Duration:</b> {scan_duration:.1f}s &nbsp; <b>Recipient:</b> {email}",
        s_body,
    ))
    story.append(Spacer(1, 0.35 * cm))

    # Executive Summary table
    story.append(Paragraph("1. Executive Summary", s_h2))
    sum_data = [
        ["Metric", "Value"],
        ["Hosts Scanned",       str(n_hosts)],
        ["Total CVEs Found",    str(len(all_cves_raw))],
        ["CVEs After Filtering",str(len(filtered_cves))],
        ["New CVEs 🆕",         str(len(new_cvs))],
        ["Persistent CVEs 🔁",  str(len(pers_cvs))],
        ["Resolved CVEs ✅",    str(len(resolved_cves))],
        ["Critical",            str(n_crit)],
        ["High",                str(n_high)],
    ]
    sum_t = Table(sum_data, colWidths=[9 * cm, 4 * cm])
    sum_t.setStyle(TableStyle(base_table_style()))
    story.append(sum_t)
    story.append(Spacer(1, 0.25 * cm))

    # Filter rejection table
    story.append(Paragraph("Filter Rejection Summary", s_h3))
    flt_data = [
        ["Filter", "Excluded"],
        [f"Filter 1 — Severity (CVSS < {cfg['filters']['cvss_min_score']})",
         str(rejection_counts.get("severity", 0))],
        [f"Filter 2 — EPSS (score < {cfg['filters']['epss_min_score']})",
         str(rejection_counts.get("epss", 0))],
        ["Filter 3 — Patch Status (already patched)",
         str(rejection_counts.get("patch_status", 0))],
        ["Filter 4 — Version Range (outside vulnerable range)",
         str(rejection_counts.get("version_range", 0))],
    ]
    flt_t = Table(flt_data, colWidths=[13.5 * cm, 2.5 * cm])
    flt_t.setStyle(TableStyle(base_table_style()))
    story.append(flt_t)
    story.append(Spacer(1, 0.3 * cm))

    # CVE table helper
    CVE_HEADERS = ["Host", "Port/Svc", "OS", "CVE ID",
                   "v3.1", "v4.0", "EPSS", "Severity",
                   "Patch", "Delta", "Flags"]
    CVE_WIDTHS  = [2.3*cm, 1.8*cm, 2.4*cm, 3*cm,
                   1.1*cm, 1.1*cm, 1.3*cm, 1.6*cm,
                   1.7*cm, 1.8*cm, 2.5*cm]

    def build_cve_table(title: str, cve_list: list):
        story.append(Paragraph(title, s_h3))
        if not cve_list:
            story.append(Paragraph("<i>None.</i>", s_body))
            return
        rows = [CVE_HEADERS]
        sev_colors = []
        for i, cve in enumerate(cve_list):
            score  = _effective_score(cve)
            label  = _severity_label(score, cfg)
            hex_c  = _severity_color_hex(score, cfg)
            sev_colors.append((i + 1, rl_colors.HexColor(hex_c)))
            v31  = f"{cve['cvss_v31']:.1f}"   if cve.get("cvss_v31")   else "N/A"
            v40  = f"{cve['cvss_v40']:.1f}"   if cve.get("cvss_v40")   else "N/A"
            epss = f"{cve['epss_score']:.4f}" if cve.get("epss_score") is not None else "N/A"
            rows.append([
                Paragraph(cve.get("host_ip", ""),    s_cell),
                Paragraph(f"{cve.get('port','')}/{cve.get('service','')}", s_cell),
                Paragraph((cve.get("detected_os") or "Unknown")[:28], s_cell),
                Paragraph(cve.get("cve_id", ""), s_cell),
                v31, v40, epss, label,
                Paragraph(cve.get("patch_status") or "N/A", s_cell),
                _delta_badge(cve.get("delta", "")),
                Paragraph(_flags_str(cve), s_cell),
            ])
        t = Table(rows, colWidths=CVE_WIDTHS, repeatRows=1)
        ts = base_table_style()
        for row_idx, color in sev_colors:
            ts.append(("TEXTCOLOR", (7, row_idx), (7, row_idx), color))
            ts.append(("FONTNAME",  (7, row_idx), (7, row_idx), "Helvetica-Bold"))
        t.setStyle(TableStyle(ts))
        story.append(t)
        story.append(Spacer(1, 0.25 * cm))

    story.append(Paragraph("2. Delta Highlights", s_h2))
    build_cve_table(f"New CVEs 🆕 ({len(new_cvs)})", new_cvs)
    build_cve_table(f"Resolved CVEs ✅ ({len(resolved_cves)})", resolved_cves)

    story.append(Paragraph("3. Per-Host CVE Table (Filtered)", s_h2))
    build_cve_table(f"All Actionable CVEs ({len(sorted_cvs)})", sorted_cvs)

    # Chart
    story.append(Paragraph("4. Severity Distribution Chart", s_h2))
    if chart_b64:
        buf = io.BytesIO(base64.b64decode(chart_b64))
        story.append(Image(buf, width=14 * cm, height=7 * cm))
    story.append(Spacer(1, 0.3 * cm))

    # Appendix
    story.append(Paragraph("5. Appendix — Filtered-Out CVEs", s_h2))
    if excl_cvs:
        excl_rows = [["CVE ID", "Reason Excluded", "CVSS"]]
        for c in excl_cvs:
            excl_rows.append([
                c["cve_id"],
                c.get("filter_exclusion_reason", ""),
                str(c.get("cvss_v31") or c.get("cvss_v40") or c.get("nmap_cvss") or "N/A"),
            ])
        excl_t = Table(excl_rows, colWidths=[4 * cm, 10.5 * cm, 1.5 * cm], repeatRows=1)
        excl_ts = base_table_style()
        excl_ts[3] = ("FONTSIZE", (0, 0), (-1, -1), 7)
        excl_t.setStyle(TableStyle(excl_ts))
        story.append(excl_t)
    else:
        story.append(Paragraph("<i>No CVEs were filtered out.</i>", s_body))

    doc.build(story)


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------

def post_webhook(payload: dict, url: str) -> None:
    try:
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
    except Exception as e:
        logger.error("Webhook POST to %s failed: %s", url, e)


# ---------------------------------------------------------------------------
# Scan Orchestrator
# ---------------------------------------------------------------------------

def _make_scan_id(network: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"{ts}_{_network_slug(network)}"


def run_scan(
    network: str,
    email: str,
    cfg: dict,
    webhook_url: str,
    output_base: Optional[Path] = None,
    no_patch_check: bool = False,
    no_applicability_check: bool = False,
    unversioned_override: Optional[str] = None,
    verbose: bool = False,
) -> dict:
    """
    Full pipeline: nmap → enrich → filter → delta → reports → webhook.
    Returns the webhook payload dict.
    Raises RuntimeError if nmap fails.
    """
    scan_start = datetime.now(timezone.utc)
    scan_id    = _make_scan_id(network)

    if verbose:
        print(f"[TripleSec] Scan started: {scan_id}  target={network}")

    output_dir = (output_base or Path(cfg["paths"]["scan_output_dir"]).expanduser()) / scan_id
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. nmap
    if verbose:
        print("[+] Running nmap...")
    all_cves = run_nmap(cfg, network)

    # Deduplicate by (cve_id, host_ip, port)
    seen_keys: set = set()
    deduped = []
    for cve in all_cves:
        key = (cve["cve_id"], cve["host_ip"], cve["port"])
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(cve)
    all_cves = deduped

    if verbose:
        print(f"[+] nmap: {len(all_cves)} unique CVE findings")

    with open(output_dir / "raw.json", "w") as f:
        json.dump(all_cves, f, indent=2)

    # 2. Enrich (NVD + EPSS, in-place)
    if verbose:
        print(f"[+] Enriching {len(all_cves)} CVEs (NVD + EPSS)...")
    enrich_all_cves(all_cves, cfg, verbose=verbose)

    # 3. Filter (in-place, returns passing subset)
    if verbose:
        print("[+] Applying filters...")
    filtered_cves, rejection_counts = apply_filters(
        all_cves, cfg,
        verbose=verbose,
        no_patch_check=no_patch_check,
        no_applicability_check=no_applicability_check,
        unversioned_override=unversioned_override,
    )

    if verbose:
        print(f"[+] {len(filtered_cves)} CVEs passed all filters")

    with open(output_dir / "filtered.json", "w") as f:
        json.dump(filtered_cves, f, indent=2)

    # 4. Delta
    if verbose:
        print("[+] Computing delta...")
    filtered_cves, resolved_cves = compute_delta(filtered_cves, network, cfg)

    new_count  = sum(1 for c in filtered_cves if c.get("delta") == "new")
    pers_count = sum(1 for c in filtered_cves if c.get("delta") == "persistent")

    with open(output_dir / "delta.json", "w") as f:
        json.dump({
            "new":        [c for c in filtered_cves if c.get("delta") == "new"],
            "persistent": [c for c in filtered_cves if c.get("delta") == "persistent"],
            "resolved":   resolved_cves,
        }, f, indent=2)

    # 5. Reports
    scan_end      = datetime.now(timezone.utc)
    scan_duration = (scan_end - scan_start).total_seconds()

    if verbose:
        print("[+] Generating reports...")

    chart_b64 = generate_chart(filtered_cves, cfg)

    report_kwargs = dict(
        network=network, email=email, scan_id=scan_id,
        scan_start=scan_start, scan_duration=scan_duration,
        all_cves_raw=all_cves, filtered_cves=filtered_cves,
        resolved_cves=resolved_cves, rejection_counts=rejection_counts,
        chart_b64=chart_b64, cfg=cfg,
    )

    html_path = output_dir / "report.html"
    html_content = generate_html_report(**report_kwargs)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    pdf_path = output_dir / "report.pdf"
    generate_pdf_report(output_path=pdf_path, **report_kwargs)

    if verbose:
        print(f"[+] Reports: {output_dir}")

    # 6. Webhook payload
    crit_min = cfg["report"]["critical_min"]
    high_min = cfg["report"]["high_min"]
    n_crit   = sum(1 for c in filtered_cves if _effective_score(c) >= crit_min)
    n_high   = sum(1 for c in filtered_cves if high_min <= _effective_score(c) < crit_min)
    n_unver  = sum(1 for c in filtered_cves if c.get("version_unconfirmed"))
    n_hosts  = len({c["host_ip"] for c in all_cves})

    if new_count > 0:
        payload = {
            "scan_id":   scan_id,
            "network":   network,
            "email":     email,
            "timestamp": scan_start.isoformat(),
            "trigger":   "new_criticals",
            "summary": {
                "total_hosts_scanned":      n_hosts,
                "total_cves_found":         len(all_cves),
                "cves_after_filtering":     len(filtered_cves),
                "new_count":                new_count,
                "persistent_count":         pers_count,
                "resolved_count":           len(resolved_cves),
                "critical_count":           n_crit,
                "high_count":               n_high,
                "version_unconfirmed_count": n_unver,
            },
            "pdf_path":  str(pdf_path),
            "html_path": str(html_path),
        }
    else:
        payload = {
            "scan_id":   scan_id,
            "network":   network,
            "email":     email,
            "timestamp": scan_start.isoformat(),
            "trigger":   "digest_only",
            "summary": {
                "total_hosts_scanned":  n_hosts,
                "total_cves_found":     len(all_cves),
                "cves_after_filtering": len(filtered_cves),
                "new_count":            0,
                "persistent_count":     pers_count,
                "resolved_count":       len(resolved_cves),
            },
            "digest_message": (
                f"Daily scan complete. No new findings. "
                f"{pers_count} persistent CVEs tracked."
            ),
        }

    post_webhook(payload, webhook_url)

    if verbose:
        print(
            f"[+] Done — new={new_count}, persistent={pers_count}, "
            f"resolved={len(resolved_cves)}"
        )

    return payload


# ---------------------------------------------------------------------------
# Flask Application
# ---------------------------------------------------------------------------

flask_app = Flask(__name__)
_flask_cfg: Optional[dict] = None


def create_flask_app(cfg: dict) -> Flask:
    global _flask_cfg
    _flask_cfg = cfg

    @flask_app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "status":  "ok",
            "service": "vuln-scanner",
            "version": str(cfg["flask"]["version"]),
            "port":    cfg["flask"]["port"],
        })

    @flask_app.route("/scan", methods=["POST"])
    def scan():
        data        = request.get_json(force=True, silent=True) or {}
        network     = data.get("network")
        email       = data.get("email")
        webhook_url = data.get("webhook_url")

        if not network or not email or not webhook_url:
            return jsonify({"error": "Missing required fields: network, email, webhook_url"}), 400

        if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$", network):
            return jsonify({"error": f"Invalid network CIDR: {network!r}"}), 400

        no_patch_check         = bool(data.get("no_patch_check", False))
        no_applicability_check = bool(data.get("no_applicability_check", False))
        unversioned            = data.get("unversioned") or None
        verbose                = bool(data.get("verbose", False))

        if unversioned and unversioned not in ("include_flagged", "exclude"):
            return jsonify({"error": f"Invalid unversioned value: {unversioned!r}"}), 400

        def scan_task():
            try:
                run_scan(
                    network=network, email=email, cfg=cfg,
                    webhook_url=webhook_url,
                    no_patch_check=no_patch_check,
                    no_applicability_check=no_applicability_check,
                    unversioned_override=unversioned,
                    verbose=verbose,
                )
            except Exception as e:
                logger.error("Background scan error for %s: %s", network, e)

        threading.Thread(target=scan_task, daemon=True).start()

        return jsonify({
            "status":  "accepted",
            "scan_id": _make_scan_id(network),
            "message": f"Scan started for {network}. Results will be POSTed to {webhook_url} on completion.",
        }), 202

    return flask_app


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vuln-scanner",
        description="TripleSec Network Vulnerability Scanner",
    )
    p.add_argument("network", nargs="?",
                   help="Target network CIDR (e.g. 192.168.1.0/24). "
                        "Omit to start the Flask service.")
    p.add_argument("email", nargs="?",
                   help="Recipient email address for the report.")
    p.add_argument("--config", metavar="PATH",
                   help="Path to config TOML file.")
    p.add_argument("--output", metavar="PATH",
                   help="Override scan output base directory.")
    p.add_argument("--webhook-url", metavar="URL", required=False,
                   help="URL to POST scan results to on completion.")
    p.add_argument("--no-patch-check", action="store_true",
                   help="Skip OS patch status lookup (Filter 3).")
    p.add_argument("--no-applicability-check", action="store_true",
                   help="Skip NVD version range check (Filter 4).")
    p.add_argument("--unversioned", choices=["include", "exclude"],
                   help="Handling for unversioned CVEs: include (flagged) or exclude.")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Log each per-CVE filter decision to stdout.")
    return p


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    config_path = find_config(args.config)
    cfg         = load_config(config_path)
    setup_logging(cfg["paths"]["error_log"])
    ensure_dirs(cfg)

    if args.network is None:
        # Flask service mode
        print(
            f"[TripleSec] Starting service on "
            f"{cfg['flask']['host']}:{cfg['flask']['port']}"
        )
        app = create_flask_app(cfg)
        app.run(host=cfg["flask"]["host"], port=cfg["flask"]["port"], debug=False)
    else:
        # CLI mode
        if not args.email:
            parser.error("email argument is required in CLI mode")
        if not args.webhook_url:
            parser.error("--webhook-url is required in CLI mode")

        unversioned_override = None
        if args.unversioned == "include":
            unversioned_override = "include_flagged"
        elif args.unversioned == "exclude":
            unversioned_override = "exclude"

        output_base = Path(args.output).expanduser() if args.output else None

        try:
            payload = run_scan(
                network=args.network,
                email=args.email,
                cfg=cfg,
                webhook_url=args.webhook_url,
                output_base=output_base,
                no_patch_check=args.no_patch_check,
                no_applicability_check=args.no_applicability_check,
                unversioned_override=unversioned_override,
                verbose=args.verbose,
            )
            print(json.dumps(payload, indent=2))
        except RuntimeError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
