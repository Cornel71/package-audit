#!/usr/bin/env python3
"""
pkg_cve_audit.py (Standalone + Server Uploader + No Auto-Open)

Scans all Python packages installed in the current environment (and, with --apt,
the Debian/Ubuntu apt or RPM packages of the host), checks each
one against the OSV.dev (PyPI) and NVD vulnerability databases, compares the
installed version against the latest release on PyPI, writes a CSV report,
generates a static HTML dashboard (without opening it unless asked), and
optionally uploads the results to a PkgAudit server.

Usage:
    python3 pkg_cve_audit.py --upload-url URL --api-user USER --api-password PASS [--hostname NAME]

    python3 pkg_cve_audit.py --apt            # pip + apt
    python3 pkg_cve_audit.py --apt-only       # apt only
    python3 pkg_cve_audit.py --rpm            # pip + rpm (AlmaLinux / Rocky / RHEL / SUSE)
    python3 pkg_cve_audit.py --rpm-only       # rpm only

Environment fallbacks: NVD_API_KEY, PKGAUDIT_API_USER, PKGAUDIT_API_PASSWORD
"""
import argparse, csv, html, json, os, platform, re, socket, subprocess, sys, threading, time, webbrowser, logging
import importlib.metadata as ilmd
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from packaging.version import Version, InvalidVersion

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("pkg_cve_audit.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
PYPI_URL = "https://pypi.org/pypi/{}/json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "pkg-cve-audit/2.1"})

def get_installed_packages():
    pkgs = []
    for dist in ilmd.distributions():
        try:
            meta = dist.metadata
            name = meta.get("Name") if hasattr(meta, "get") else meta["Name"]
            version = dist.version
            if name and version:
                pkgs.append((name, version))
        except Exception as e:
            logging.debug(f"Failed to read metadata for a distribution: {e}")
            continue
    seen = {}
    for name, ver in pkgs:
        key = re.sub(r"[-_.]+", "-", name).lower()
        seen.setdefault(key, (name, ver))
    return sorted(seen.values(), key=lambda x: x[0].lower())

def query_osv_batch(items):
    """items: list of (ecosystem, name, version). Returns {item: [vuln ids]}; follows pagination."""
    results = {}
    for i in range(0, len(items), 100):
        b_items = items[i:i + 100]
        ids = {it: [] for it in b_items}
        pending = [(it, None) for it in b_items]
        try:
            while pending:
                queries = []
                for it, token in pending:
                    q = {"package": {"name": it[1], "ecosystem": it[0]}, "version": it[2]}
                    if token:
                        q["page_token"] = token
                    queries.append(q)
                resp = SESSION.post(OSV_BATCH_URL, json={"queries": queries}, timeout=30)
                resp.raise_for_status()
                next_pending = []
                for (it, _), res in zip(pending, resp.json().get("results", [])):
                    ids[it].extend(v["id"] for v in res.get("vulns", []) or [])
                    if res.get("next_page_token"):
                        next_pending.append((it, res["next_page_token"]))
                pending = next_pending
        except Exception as e:
            logging.error(f"OSV batch query failed: {e}")
        results.update(ids)
    return results


def _osv_severity(data):
    """Prefer the plain label (GHSA etc.), fall back to the CVSS vector."""
    label = (data.get("database_specific") or {}).get("severity", "")
    if label:
        return str(label).upper()
    sev_list = data.get("severity") or []
    if isinstance(sev_list, list) and sev_list:
        return sev_list[0].get("score", "")
    return ""

class RateLimiter:
    """Global limiter shared by all threads (NVD: 5 req/30s, 50 req/30s with a key)."""
    def __init__(self, interval):
        self.interval = interval
        self.lock = threading.Lock()
        self.next_time = 0.0

    def wait(self):
        with self.lock:
            now = time.monotonic()
            delay = max(0.0, self.next_time - now)
            self.next_time = max(now, self.next_time) + self.interval
        if delay:
            time.sleep(delay)

NVD_LIMITER = RateLimiter(6.5)
NVD_CACHE = {}
NVD_CACHE_LOCK = threading.Lock()


def _extract_cvss(metrics):
    """Return e.g. 'HIGH (7.5)' from the best available CVSS block."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {}) or {}
        sev = data.get("baseSeverity") or entry.get("baseSeverity") or ""
        score = data.get("baseScore")
        if sev and score is not None:
            return f"{sev} ({score})"
        if sev:
            return sev
        if score is not None:
            return f"Score: {score}"
    return ""


def get_nvd_details(cve_id, api_key=None, retries=4):
    if not cve_id.startswith("CVE-"):
        return None, None
    with NVD_CACHE_LOCK:
        entry = NVD_CACHE.get(cve_id)
        if entry:
            sev, summ = entry[0], entry[1]
            age = time.time() - entry[2] if len(entry) > 2 else float("inf")
            if sev or age < 86400:
                logging.debug(f"NVD cache hit for {cve_id}")
                return sev or None, summ or None

    headers = {"apiKey": api_key} if api_key else {}
    for attempt in range(1, retries + 1):
        NVD_LIMITER.wait()
        try:
            resp = SESSION.get(NVD_API_URL, params={"cveId": cve_id}, headers=headers, timeout=30)
        except requests.RequestException as e:
            logging.warning(f"NVD request error for {cve_id} (attempt {attempt}): {e}")
            time.sleep(2 ** attempt)
            continue

        if resp.status_code in (403, 429, 503):
            retry_after = resp.headers.get("Retry-After")
            wait = int(retry_after) if retry_after and retry_after.isdigit() else 10 * attempt
            logging.warning(f"NVD returned {resp.status_code} for {cve_id}; backing off {wait}s")
            time.sleep(wait)
            continue
        if resp.status_code == 404:
            logging.info(f"NVD {cve_id}: not found (404)")
            break
        if resp.status_code != 200:
            logging.warning(f"NVD API returned status {resp.status_code} for {cve_id}")
            return None, None

        try:
            vulns = resp.json().get("vulnerabilities") or []
            if not vulns:
                logging.info(f"NVD {cve_id}: no record returned")
                break
            cve_item = vulns[0].get("cve", {})
            severity = _extract_cvss(cve_item.get("metrics", {}) or {})
            summary = next((d.get("value", "") for d in cve_item.get("descriptions", [])
                            if d.get("lang") == "en"), "")
        except Exception as e:
            logging.error(f"Failed parsing NVD data for {cve_id}: {e}")
            return None, None

        with NVD_CACHE_LOCK:
            NVD_CACHE[cve_id] = [severity, summary, time.time()]
        logging.info(f"NVD {cve_id}: {severity or 'record found, no CVSS score yet'}")
        return severity or None, summary or None
    return None, None


def load_nvd_cache(path):
    if not path or not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            NVD_CACHE.update(json.load(f))
        logging.info(f"Loaded {len(NVD_CACHE)} cached NVD entries from {path}")
    except Exception as e:
        logging.warning(f"Could not load NVD cache {path}: {e}")


def save_nvd_cache(path):
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(NVD_CACHE, f)
    except Exception as e:
        logging.warning(f"Could not save NVD cache {path}: {e}")

def get_vuln_details(vuln_id, nvd_key=None, source="both"):
    """source: 'osv' = OSV data only (no NVD calls), 'nvd' = NVD data (falls back to OSV
    when NVD has nothing), 'both' = NVD summary + both severities."""
    try:
        resp = SESSION.get(OSV_VULN_URL.format(vuln_id), timeout=15)
        resp.raise_for_status()
        data = resp.json()
        osv_sev = _osv_severity(data)
        severity = f"OSV: {osv_sev}" if osv_sev else ""
        summary = data.get("summary", "") or (data.get("details", "") or "")[:200]
        aliases = data.get("aliases", []) or []
        cve_id = vuln_id if vuln_id.startswith("CVE-") else next(
            (a for a in aliases if a.startswith("CVE-")), vuln_id)
        if source in ("both", "nvd") and cve_id.startswith("CVE-"):
            nvd_sev, nvd_sum = get_nvd_details(cve_id, nvd_key)
            if nvd_sev:
                if source == "both":
                    severity = f"NVD: {nvd_sev}" + (f" | {severity}" if severity else "")
                else:
                    severity = f"NVD: {nvd_sev}"
            if nvd_sum:
                summary = nvd_sum
        return cve_id, severity, summary
    except Exception as e:
        logging.error(f"Error fetching OSV details for {vuln_id}: {e}")
        return vuln_id, "", ""

def detect_apt_ecosystem(override=None):
    """OSV ecosystem string for this host, e.g. 'Debian:12' or 'Ubuntu:22.04:LTS'."""
    if override:
        return override
    info = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    k, v = line.rstrip().split("=", 1)
                    info[k] = v.strip('"')
    except OSError:
        return None
    distro, ver = info.get("ID", "").lower(), info.get("VERSION_ID", "")
    if distro == "debian" and ver:
        return f"Debian:{ver}"
    if distro == "ubuntu" and ver:
        return f"Ubuntu:{ver}:LTS" if "LTS" in info.get("VERSION", "") else f"Ubuntu:{ver}"
    return None


def get_installed_apt_packages():
    """Installed binary packages with their source package/version (OSV tracks the source)."""
    fmt = "${db:Status-Status}\t${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n"
    out = subprocess.run(["dpkg-query", "-W", "-f=" + fmt], capture_output=True, text=True, check=True).stdout
    pkgs = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 5 or parts[0] != "installed":
            continue
        _, name, version, src, src_ver = parts
        pkgs.append({"name": name, "version": version,
                     "source": src or name.split(":")[0], "source_version": src_ver or version})
    return sorted(pkgs, key=lambda p: p["name"])


def get_apt_candidates(names):
    """Candidate (newest available) versions from the local apt lists - run 'apt update' for fresh data."""
    cands, env = {}, {**os.environ, "LC_ALL": "C"}
    for i in range(0, len(names), 200):
        try:
            out = subprocess.run(["apt-cache", "policy", *names[i:i + 200]],
                                 capture_output=True, text=True, env=env).stdout
        except OSError as e:
            logging.error(f"apt-cache not available: {e}")
            return cands
        cur = None
        for line in out.splitlines():
            if line and not line.startswith(" "):
                cur = line.rstrip()[:-1] if line.rstrip().endswith(":") else line.strip()
            elif cur and line.strip().startswith("Candidate:"):
                cands[cur] = line.split(":", 1)[1].strip()
    return cands


def is_apt_outdated(installed, candidate):
    if not candidate or candidate == "(none)":
        return None
    if candidate == installed:
        return False
    try:
        return subprocess.run(["dpkg", "--compare-versions", candidate, "gt", installed]).returncode == 0
    except OSError:
        return candidate != installed

def detect_rpm_ecosystem(override=None):
    """OSV ecosystem string for this host, e.g. 'AlmaLinux:9' or 'Rocky Linux:9'."""
    if override:
        return override
    info = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    k, v = line.rstrip().split("=", 1)
                    info[k] = v.strip('"')
    except OSError:
        return None
    distro, major = info.get("ID", "").lower(), info.get("VERSION_ID", "").split(".")[0]
    if distro == "almalinux" and major:
        return f"AlmaLinux:{major}"
    if distro == "rocky" and major:
        return f"Rocky Linux:{major}"
    if distro == "rhel":
        return "Red Hat"
    if distro in ("sles", "sled", "sle-micro"):
        return "SUSE"
    if distro.startswith("opensuse"):
        return "openSUSE"
    return None


def _srpm_name(srpm, fallback):
    """'openssl-3.0.7-24.el9.src.rpm' -> 'openssl'."""
    if not srpm or srpm == "(none)":
        return fallback
    base = re.sub(r"\.(src|nosrc)\.rpm$", "", srpm)
    parts = base.rsplit("-", 2)
    return parts[0] if len(parts) == 3 else fallback


def get_installed_rpm_packages():
    fmt = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n"
    out = subprocess.run(["rpm", "-qa", "--qf", fmt], capture_output=True, text=True, check=True).stdout
    pkgs = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 6 or parts[0] == "gpg-pubkey":
            continue
        name, epoch, ver, rel, arch, srpm = parts
        evr = (f"{epoch}:" if epoch.isdigit() and int(epoch) > 0 else "") + f"{ver}-{rel}"
        pkgs.append({"name": name, "arch": arch, "version": evr, "source": _srpm_name(srpm, name)})
    counts = {}
    for p in pkgs:
        counts[p["name"]] = counts.get(p["name"], 0) + 1
    for p in pkgs:
        p["key"] = f"{p['name']}.{p['arch']}"
        p["display"] = p["key"] if counts[p["name"]] > 1 else p["name"]
    return sorted(pkgs, key=lambda p: p["display"])


def _parse_dnf_check_update(text):
    updates = {}
    for line in text.splitlines():
        if line.startswith("Obsoleting"):
            break
        parts = line.split()
        if len(parts) == 3 and not line.startswith(" ") and "." in parts[0]:
            updates[parts[0]] = parts[1]
    return updates


def _parse_zypper_updates(text):
    updates = {}
    for line in text.splitlines():
        cols = [c.strip() for c in line.split("|")]
        if len(cols) >= 6 and cols[0] == "v":
            updates[f"{cols[2]}.{cols[5]}"] = cols[4]
    return updates


def get_rpm_updates():
    """{'name.arch': available_version} from dnf/yum/zypper, or None if no tool worked."""
    for cmd, parser, ok_codes in (
            (["dnf", "-q", "check-update"], _parse_dnf_check_update, (0, 100)),
            (["yum", "-q", "check-update"], _parse_dnf_check_update, (0, 100)),
            (["zypper", "-q", "--non-interactive", "list-updates"], _parse_zypper_updates, (0,))):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, env={**os.environ, "LC_ALL": "C"})
        except OSError:
            continue
        if r.returncode in ok_codes:
            return parser(r.stdout)
        logging.warning(f"{cmd[0]} exited with {r.returncode}: {r.stderr.strip()[:200]}")
    return None

def get_latest_pypi_version(name):
    try:
        resp = SESSION.get(PYPI_URL.format(name), timeout=15)
        return resp.json().get("info", {}).get("version") if resp.status_code == 200 else None
    except Exception as e:
        logging.debug(f"PyPI lookup failed for {name}: {e}")
        return None

def is_outdated(installed, latest):
    if not latest:
        return None
    try:
        return Version(installed) < Version(latest)
    except InvalidVersion:
        return installed != latest

def generate_dashboard(csv_path, open_browser=False):
    html_path = os.path.splitext(csv_path)[0] + ".html"
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    except Exception as e:
        return logging.error(f"Could not read CSV for dashboard: {e}")

    e = html.escape
    n_tot = len(rows)
    n_vuln = sum(1 for r in rows if r["vulnerable"] == "True")
    n_out = sum(1 for r in rows if r["outdated"] == "True")
    tbody = "".join(
        f'<tr><td><strong>{e(r["package"])}</strong></td><td>{e(r["ecosystem"])}</td><td>{e(r["installed_version"])}</td>'
        f'<td>{e(r["latest_version"])}</td><td>{e(r["outdated"])}</td><td>{e(r["vulnerable"])}</td>'
        f'<td>{e(r["cve_ids"])}</td><td>{e(r["severity"])}</td><td>{e(r["summary"])}</td></tr>'
        for r in rows)
    page = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Security Audit</title><style>body{{font-family:sans-serif;padding:20px;background:#f4f7f6}}table{{width:100%;border-collapse:collapse;margin-top:20px}}th,td{{padding:10px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}}th{{background:#eee}}</style></head>
    <body><h2>Package Security Dashboard</h2><p>Total Packages: {n_tot} | Vulnerable: {n_vuln} | Outdated: {n_out}</p><table><thead><tr><th>Package</th><th>Type</th><th>Installed</th><th>Latest</th><th>Outdated</th><th>Vulnerable</th><th>CVEs</th><th>Severity</th><th>Summary</th></tr></thead><tbody>{tbody}</tbody></table></body></html>"""
    try:
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(page)
        logging.info(f"Dashboard generated successfully: {html_path}")
        if open_browser:
            webbrowser.open("file://" + os.path.abspath(html_path))
    except Exception as ex:
        logging.error(f"Failed to write HTML dashboard: {ex}")


def upload_report(csv_path, url, user, password, hostname=None, insecure=False,
                  total_packages=None, python_version=None):
    """total_packages = packages scanned (not just the rows kept by --only-flagged);
    python_version = None when Python packages were not part of this scan."""
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        report_host = re.sub(r"[^A-Za-z0-9._-]", "-", hostname or socket.gethostname())
        payload = {"hostname": report_host, "python_version": python_version,
                   "total_packages": total_packages if total_packages is not None else len(rows), "rows": rows}
        resp = SESSION.post(url.rstrip("/") + "/api/v1/ingest", json=payload,
                            auth=(user, password), timeout=30, verify=not insecure)
        resp.raise_for_status()
        logging.info("Upload successful!")
    except Exception as e:
        logging.error(f"Upload failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Python/apt package vulnerability auditor.")
    parser.add_argument("-o", "--output", default="package_audit.csv", help="Output CSV path")
    parser.add_argument("--only-flagged", action="store_true", help="Only include vulnerable/outdated packages")
    parser.add_argument("--workers", type=int, default=10, help="Parallel processing workers")
    parser.add_argument("--apt", action="store_true", help="Also audit installed apt (Debian/Ubuntu) packages")
    parser.add_argument("--apt-only", action="store_true", help="Audit only apt packages (skip Python packages)")
    parser.add_argument("--apt-ecosystem", default=None,
                        help="Override OSV ecosystem for apt, e.g. 'Debian:12' or 'Ubuntu:22.04:LTS'")
    parser.add_argument("--rpm", action="store_true", help="Also audit installed RPM packages (AlmaLinux/Rocky/RHEL/SUSE)")
    parser.add_argument("--rpm-only", action="store_true", help="Audit only RPM packages (skip Python packages)")
    parser.add_argument("--rpm-ecosystem", default=None,
                        help="Override OSV ecosystem for rpm, e.g. 'AlmaLinux:9' or 'Rocky Linux:8'")
    parser.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"), help="Optional NVD REST API key (or NVD_API_KEY env)")
    parser.add_argument("--source", choices=["osv", "nvd", "both"], default="both",
                        help="Which database's severity/summary goes into the CSV: osv (no NVD calls), "
                             "nvd (falls back to OSV where NVD has no data), both (default)")
    parser.add_argument("--no-nvd", action="store_true", help="Same as --source osv")
    parser.add_argument("--nvd-cache", default="nvd_cache.json", help="JSON file caching NVD lookups ('' to disable)")
    parser.add_argument("--no-dashboard", action="store_true", help="Skip generating the HTML dashboard")
    parser.add_argument("--open-browser", action="store_true", help="Open the HTML report automatically")
    parser.add_argument("--upload-url", help="PkgAudit server URL endpoint")
    parser.add_argument("--api-user", default=os.environ.get("PKGAUDIT_API_USER"), help="Dashboard API username")
    parser.add_argument("--api-password", default=os.environ.get("PKGAUDIT_API_PASSWORD"), help="Dashboard API password")
    parser.add_argument("--hostname", default=None, help="Custom hostname override for report upload")
    parser.add_argument("--upload-insecure", action="store_true", help="Disable SSL verification for uploading")
    args = parser.parse_args()

    if args.no_nvd:
        if args.source == "nvd":
            parser.error("--no-nvd conflicts with --source nvd")
        args.source = "osv"
    use_nvd = args.source != "osv"
    NVD_LIMITER.interval = 0.7 if args.nvd_api_key else 6.5
    if use_nvd:
        load_nvd_cache(args.nvd_cache)
    logging.info("Collecting installed packages...")
    inventory = []
    if not (args.apt_only or args.rpm_only):
        for n, v in get_installed_packages():
            inventory.append({"ecosystem": "PyPI", "name": n, "version": v, "osv": [("PyPI", n, v)]})
        logging.info(f"Found {len(inventory)} Python packages.")
    if args.apt or args.apt_only:
        apt_eco = detect_apt_ecosystem(args.apt_ecosystem)
        if not apt_eco:
            logging.error("Could not determine the apt OSV ecosystem from /etc/os-release; "
                          "pass --apt-ecosystem (e.g. Debian:12 or Ubuntu:22.04:LTS).")
            sys.exit(1)
        try:
            apt_pkgs = get_installed_apt_packages()
        except (OSError, subprocess.CalledProcessError) as e:
            logging.error(f"Could not list apt packages with dpkg-query: {e}")
            sys.exit(1)
        for p in apt_pkgs:
            inventory.append({"ecosystem": "apt", "name": p["name"], "version": p["version"],
                              "osv": [(apt_eco, p["source"], p["source_version"])]})
        logging.info(f"Found {len(apt_pkgs)} apt packages (OSV ecosystem {apt_eco}).")
    rpm_updates_needed = False
    if args.rpm or args.rpm_only:
        rpm_eco = detect_rpm_ecosystem(args.rpm_ecosystem)
        if not rpm_eco:
            logging.error("Could not determine the rpm OSV ecosystem from /etc/os-release (OSV covers AlmaLinux, "
                          "Rocky Linux, Red Hat, SUSE, openSUSE); pass --rpm-ecosystem, e.g. 'AlmaLinux:9'.")
            sys.exit(1)
        try:
            rpm_pkgs = get_installed_rpm_packages()
        except (OSError, subprocess.CalledProcessError) as e:
            logging.error(f"Could not list RPM packages with rpm -qa: {e}")
            sys.exit(1)
        for p in rpm_pkgs:
            queries = [(rpm_eco, p["name"], p["version"])]
            if p["source"] != p["name"]:
                queries.append((rpm_eco, p["source"], p["version"]))
            inventory.append({"ecosystem": "rpm", "name": p["display"], "key": p["key"],
                              "version": p["version"], "osv": queries})
        rpm_updates_needed = True
        logging.info(f"Found {len(rpm_pkgs)} rpm packages (OSV ecosystem {rpm_eco}).")
    logging.info("Batching queries against OSV.dev...")
    osv_items = sorted({q for i in inventory for q in i["osv"]})
    osv_results = query_osv_batch(osv_items)
    all_vuln_ids = sorted({vid for ids in osv_results.values() for vid in ids})
    logging.info(f"Found {len(all_vuln_ids)} unique vulnerability IDs. Source: {args.source}.")
    if use_nvd and not args.nvd_api_key:
        logging.info("No NVD API key: lookups are throttled to ~5 per 30s (use --nvd-api-key for 10x faster).")

    vuln_detail_cache = {}
    with ThreadPoolExecutor(max_workers=min(args.workers, 8)) as ex:
        futures = {ex.submit(get_vuln_details, vid, args.nvd_api_key, args.source): vid for vid in all_vuln_ids}
        for fut in as_completed(futures):
            vuln_detail_cache[futures[fut]] = fut.result()
    if use_nvd:
        save_nvd_cache(args.nvd_cache)
        n_cve = sum(1 for c, _, _ in vuln_detail_cache.values() if c.startswith("CVE-"))
        n_nvd = sum(1 for _, sev, _ in vuln_detail_cache.values() if "NVD:" in sev)
        logging.info(f"NVD: {n_nvd} of {n_cve} CVE-aliased vulnerabilities have NVD severity "
                     f"({len(vuln_detail_cache) - n_cve} have no CVE alias and are never sent to NVD).")
    latest_versions = {}
    pypi_names = [i["name"] for i in inventory if i["ecosystem"] == "PyPI"]
    if pypi_names:
        logging.info("Checking upstream releases on PyPI...")
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(get_latest_pypi_version, n): n for n in pypi_names}
            done = 0
            for fut in as_completed(futures):
                latest_versions[("PyPI", futures[fut])] = fut.result()
                done += 1
                if done % 25 == 0:
                    logging.info(f"  {done}/{len(pypi_names)} checked...")
    apt_names = [i["name"] for i in inventory if i["ecosystem"] == "apt"]
    if apt_names:
        logging.info("Checking apt candidate versions (local apt lists; run 'apt update' for fresh data)...")
        for n, c in get_apt_candidates(apt_names).items():
            latest_versions[("apt", n)] = c

    if rpm_updates_needed:
        logging.info("Checking available RPM updates (dnf/yum/zypper)...")
        rpm_updates = get_rpm_updates()
        if rpm_updates is None:
            logging.warning("No working dnf/yum/zypper found: RPM outdated status will be unknown.")
        else:
            for item in inventory:
                if item["ecosystem"] == "rpm":
                    latest_versions[("rpm", item["name"])] = rpm_updates.get(item["key"], item["version"])
    logging.info("Writing CSV report...")
    rows = []
    for item in inventory:
        name, version, eco = item["name"], item["version"], item["ecosystem"]
        latest = latest_versions.get((eco, name))
        if latest == "(none)":
            latest = None
        if eco == "apt":
            outdated = is_apt_outdated(version, latest)
        elif eco == "rpm":
            outdated = None if not latest else latest != version
        else:
            outdated = is_outdated(version, latest)
        vuln_ids = list(dict.fromkeys(vid for q in item["osv"] for vid in osv_results.get(q, [])))
        cve_ids, severities, summaries = [], [], []
        for vid in vuln_ids:
            cve_id, sev, summary = vuln_detail_cache.get(vid, (vid, "", ""))
            if cve_id not in cve_ids:
                cve_ids.append(cve_id)
                if sev:
                    severities.append(sev)
                if summary:
                    summaries.append(summary.strip())

        has_vuln = len(vuln_ids) > 0
        if args.only_flagged and not has_vuln and not outdated:
            continue

        rows.append({
            "package": name, "ecosystem": eco, "installed_version": version,
            "latest_version": latest or "unknown",
            "outdated": "" if outdated is None else str(outdated), "vulnerable": str(has_vuln),
            "vulnerability_count": len(vuln_ids), "cve_ids": "; ".join(cve_ids),
            "severity": "; ".join(filter(None, severities)),
            "summary": " | ".join(filter(None, summaries))[:500]
        })

    fieldnames = ["package", "ecosystem", "installed_version", "latest_version", "outdated", "vulnerable",
                  "vulnerability_count", "cve_ids", "severity", "summary"]
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    n_vulnerable = sum(1 for r in rows if r["vulnerable"] == "True")
    n_outdated = sum(1 for r in rows if r["outdated"] == "True")
    logging.info(f"Done. Wrote {len(rows)} rows to {args.output}")
    logging.info(f"  Vulnerable packages: {n_vulnerable}")
    logging.info(f"  Outdated packages:   {n_outdated}")

    if not args.no_dashboard:
        generate_dashboard(args.output, open_browser=args.open_browser)

    if args.upload_url:
        if not args.api_user or not args.api_password:
            logging.error("Missing upload credentials (--api-user / --api-password).")
            sys.exit(1)
        scanned_python = not (args.apt_only or args.rpm_only)
        upload_report(args.output, args.upload_url, args.api_user, args.api_password,
                      args.hostname, args.upload_insecure, total_packages=len(inventory),
                      python_version=platform.python_version() if scanned_python else None)


if __name__ == "__main__":
    main()
