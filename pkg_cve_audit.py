#!/usr/bin/env python3
"""
pkg_cve_audit.py (Standalone + Server Uploader + No Auto-Open)

Scans all Python packages installed in the current environment, checks each
one against the OSV.dev vulnerability database, compares the installed version
against the latest release on PyPI, writes a CSV report, generates an interactive
HTML dashboard (without opening it), and optionally uploads the results to a PkgAudit server.

Usage:
    python3 pkg_cve_audit.py --upload-url URL --api-user USER --api-password PASS [--hostname NAME]
"""

import argparse
import csv
import importlib.metadata as ilmd
import os
import platform
import re
import socket
import sys
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from packaging.version import Version, InvalidVersion

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
PYPI_URL = "https://pypi.org/pypi/{}/json"

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "pkg-cve-audit/1.0"})


def get_installed_packages():
    """Return list of (name, version) for every installed distribution."""
    pkgs = []
    for dist in ilmd.distributions():
        try:
            name = dist.metadata["Name"]
            version = dist.version
            if name and version:
                pkgs.append((name, version))
        except Exception:
            continue
    # de-dupe, keep first occurrence
    seen = {}
    for name, version in pkgs:
        seen.setdefault(name.lower(), (name, version))
    return sorted(seen.values(), key=lambda x: x[0].lower())


def chunked(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def query_osv_batch(packages):
    """
    Query OSV.dev's batch endpoint for a list of (name, version) tuples.
    Returns dict: (name, version) -> list of vuln id strings.
    """
    results = {}
    queries = [
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
        for name, version in packages
    ]

    for batch_pkgs, batch_queries in zip(
        chunked(packages, 100), chunked(queries, 100)
    ):
        payload = {"queries": batch_queries}
        try:
            resp = SESSION.post(OSV_BATCH_URL, json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            print(f"  ! OSV batch query failed: {e}", file=sys.stderr)
            for pkg in batch_pkgs:
                results[pkg] = []
            continue

        for pkg, res in zip(batch_pkgs, data.get("results", [])):
            vulns = res.get("vulns", []) or []
            results[pkg] = [v["id"] for v in vulns]

    return results


def get_vuln_details(vuln_id):
    """Fetch severity/summary for a single OSV vuln id."""
    try:
        resp = SESSION.get(OSV_VULN_URL.format(vuln_id), timeout=15)
        resp.raise_for_status()
        data = resp.json()
        severity = ""
        sev_list = data.get("severity", [])
        if sev_list:
            severity = sev_list[0].get("score", "")
        if not severity:
            db_specific = data.get("database_specific", {})
            severity = db_specific.get("severity", "")
        summary = data.get("summary", "") or data.get("details", "")[:200]
        aliases = data.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
        return cve_id, severity, summary
    except requests.RequestException:
        return vuln_id, "", ""


def get_latest_pypi_version(name):
    """Return the latest version string on PyPI, or None if lookup fails."""
    try:
        resp = SESSION.get(PYPI_URL.format(name), timeout=15)
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data.get("info", {}).get("version")
    except requests.RequestException:
        return None


def is_outdated(installed, latest):
    if not latest:
        return None  # unknown
    try:
        return Version(installed) < Version(latest)
    except InvalidVersion:
        return installed != latest


def upload(csv_path, url, username, password, hostname=None, total_packages=None, timeout=60, verify=True):
    """Posts the CSV report to the PkgAudit server."""
    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    name = re.sub(r"[^A-Za-z0-9._-]", "-", hostname or socket.gethostname())
    payload = {
        "hostname": name,
        "python_version": platform.python_version(),
        "total_packages": total_packages,
        "rows": rows,
    }
    resp = requests.post(
        url.rstrip("/") + "/api/v1/ingest",
        json=payload,
        auth=(username, password),
        timeout=timeout,
        verify=verify
    )
    resp.raise_for_status()
    return resp.json()


def generate_dashboard(csv_path, caller_file=__file__, open_browser=False):
    """Generates a modern interactive HTML dashboard directly from the audit CSV."""
    html_path = os.path.splitext(csv_path)[0] + ".html"
    
    rows = []
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
    except Exception as e:
        print(f"  ! Could not read CSV for dashboard generation: {e}", file=sys.stderr)
        return

    n_total = len(rows)
    n_vulnerable = sum(1 for r in rows if r.get("vulnerable") == "True")
    n_outdated = sum(1 for r in rows if r.get("outdated") == "True")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Python Package Security & Audit Dashboard</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; background: #f4f7f6; color: #333; }}
        .container {{ max-width: 1200px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }}
        h1 {{ margin-top: 0; color: #2c3e50; }}
        .stats {{ display: flex; gap: 20px; margin-bottom: 30px; }}
        .card {{ flex: 1; background: #f8f9fa; padding: 20px; border-radius: 6px; border-left: 5px solid #3498db; box-shadow: 0 2px 4px rgba(0,0,0,0.02); }}
        .card.danger {{ border-left-color: #e74c3c; }}
        .card.warning {{ border-left-color: #f39c12; }}
        .card h3 {{ margin: 0 0 10px 0; font-size: 14px; color: #7f8c8d; text-transform: uppercase; }}
        .card p {{ margin: 0; font-size: 24px; font-weight: bold; color: #2c3e50; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #e1e8ed; }}
        th {{ background-color: #f8f9fa; color: #2c3e50; font-weight: 600; }}
        tr:hover {{ background-color: #f8f9fa; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge-danger {{ background: #fde8e8; color: #c53030; }}
        .badge-success {{ background: #def7ec; color: #03543f; }}
        .badge-warning {{ background: #fef3c7; color: #92400e; }}
        .search-box {{ width: 100%; padding: 10px; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 4px; font-size: 14px; box-sizing: border-box; }}
    </style>
</head>
<body>
<div class="container">
    <h1>Python Package Security Audit Dashboard</h1>
    <p>Generated automatically from <code>{os.path.basename(csv_path)}</code></p>
    
    <div class="stats">
        <div class="card">
            <h3>Total Packages</h3>
            <p>{n_total}</p>
        </div>
        <div class="card warning">
            <h3>Outdated Packages</h3>
            <p>{n_outdated}</p>
        </div>
        <div class="card danger">
            <h3>Vulnerable Packages</h3>
            <p>{n_vulnerable}</p>
        </div>
    </div>

    <input type="text" id="searchBox" class="search-box" placeholder="Search packages, CVEs, or versions..." onkeyup="filterTable()">

    <table id="auditTable">
        <thead>
            <tr>
                <th>Package</th>
                <th>Installed</th>
                <th>Latest</th>
                <th>Outdated</th>
                <th>Vulnerable</th>
                <th>CVE IDs</th>
                <th>Severity</th>
                <th>Summary</th>
            </tr>
        </thead>
        <tbody>
"""

    for r in rows:
        vuln_badge = '<span class="badge badge-danger">True</span>' if r.get("vulnerable") == "True" else '<span class="badge badge-success">False</span>'
        out_badge = '<span class="badge badge-warning">True</span>' if r.get("outdated") == "True" else 'False'
        
        html_content += f"""            <tr>
                <td><strong>{r.get("package")}</strong></td>
                <td>{r.get("installed_version")}</td>
                <td>{r.get("latest_version")}</td>
                <td>{out_badge}</td>
                <td>{vuln_badge}</td>
                <td>{r.get("cve_ids", "")}</td>
                <td>{r.get("severity", "")}</td>
                <td>{r.get("summary", "")}</td>
            </tr>
"""

    html_content += """        </tbody>
    </table>
</div>

<script>
function filterTable() {
    let input = document.getElementById("searchBox");
    let filter = input.value.toLowerCase();
    let table = document.getElementById("auditTable");
    let tr = table.getElementsByTagName("tr");

    for (let i = 1; i < tr.length; i++) {
        let txt = tr[i].textContent || tr[i].innerText;
        tr[i].style.display = txt.toLowerCase().indexOf(filter) > -1 ? "" : "none";
    }
}
</script>
</body>
</html>
"""

    try:
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"  Dashboard generated successfully: {html_path}")
        if open_browser:
            webbrowser.open("file://" + os.path.abspath(html_path))
    except Exception as e:
        print(f"  ! Failed to write HTML dashboard: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o", "--output", default="package_audit.csv",
        help="Output CSV path (default: package_audit.csv)"
    )
    parser.add_argument(
        "--only-flagged", action="store_true",
        help="Only include rows that are outdated and/or vulnerable"
    )
    parser.add_argument(
        "--workers", type=int, default=10,
        help="Parallel workers for PyPI lookups (default: 10)"
    )
    parser.add_argument(
        "--no-dashboard", action="store_true",
        help="Skip generating the HTML dashboard"
    )
    parser.add_argument(
        "--open-browser", action="store_true",
        help="Open the generated HTML dashboard in the default browser"
    )
    
    # Argumente Server & Upload
    parser.add_argument("--upload-url", help="PkgAudit server URL (e.g. https://audit.example.com)")
    parser.add_argument("--api-user", help="API username for PkgAudit server")
    parser.add_argument("--api-password", help="API password for PkgAudit server")
    parser.add_argument("--hostname", default=None, help="Custom hostname override for report upload")
    parser.add_argument("--upload-insecure", action="store_true", help="Disable SSL certificate verification for upload")

    args = parser.parse_args()

    print("Collecting installed packages...")
    packages = get_installed_packages()
    print(f"Found {len(packages)} installed packages.")

    print("Querying OSV.dev for known vulnerabilities (batched)...")
    osv_results = query_osv_batch(packages)

    all_vuln_ids = sorted({vid for ids in osv_results.values() for vid in ids})
    print(f"Found {len(all_vuln_ids)} distinct vulnerability records. Fetching details...")
    vuln_detail_cache = {}
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(get_vuln_details, vid): vid for vid in all_vuln_ids}
        for fut in as_completed(futures):
            vid = futures[fut]
            vuln_detail_cache[vid] = fut.result()

    print("Checking latest versions on PyPI...")
    latest_versions = {}
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {
            ex.submit(get_latest_pypi_version, name): name
            for name, _ in packages
        }
        done = 0
        for fut in as_completed(futures):
            name = futures[fut]
            latest_versions[name] = fut.result()
            done += 1
            if done % 25 == 0:
                print(f"  {done}/{len(packages)} checked...")

    print("Writing CSV report...")
    rows = []
    for name, version in packages:
        latest = latest_versions.get(name)
        outdated = is_outdated(version, latest)
        vuln_ids = osv_results.get((name, version), [])

        cve_ids, severities, summaries = [], [], []
        for vid in vuln_ids:
            cve_id, sev, summary = vuln_detail_cache.get(vid, (vid, "", ""))
            cve_ids.append(cve_id)
            if sev:
                severities.append(sev)
            if summary:
                summaries.append(summary.replace("\n", " ").strip())

        has_vuln = len(vuln_ids) > 0
        if args.only_flagged and not has_vuln and not outdated:
            continue

        rows.append({
            "package": name,
            "installed_version": version,
            "latest_version": latest or "unknown",
            "outdated": "" if outdated is None else str(outdated),
            "vulnerable": str(has_vuln),
            "vulnerability_count": len(vuln_ids),
            "cve_ids": "; ".join(cve_ids),
            "severity": "; ".join(severities),
            "summary": " | ".join(summaries)[:500],
        })

    fieldnames = [
        "package", "installed_version", "latest_version", "outdated",
        "vulnerable", "vulnerability_count", "cve_ids", "severity", "summary",
    ]
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    n_vulnerable = sum(1 for r in rows if r["vulnerable"] == "True")
    n_outdated = sum(1 for r in rows if r["outdated"] == "True")
    print(f"\nDone. Wrote {len(rows)} rows to {args.output}")
    print(f"  Vulnerable packages: {n_vulnerable}")
    print(f"  Outdated packages:   {n_outdated}")

    # Generare Dashboard HTML (fără să deschidă browserul automat)
    if not args.no_dashboard:
        generate_dashboard(
            args.output,
            caller_file=__file__,
            open_browser=args.open_browser,
        )

    # Upload pe server
    if args.upload_url:
        if not args.api_user or not args.api_password:
            print("  ! Error: --api-user and --api-password are required when using --upload-url.", file=sys.stderr)
            sys.exit(1)
            
        print(f"Uploading audit report to PkgAudit server ({args.upload_url})...")
        try:
            result = upload(
                csv_path=args.output,
                url=args.upload_url,
                username=args.api_user,
                password=args.api_password,
                hostname=args.hostname,
                total_packages=len(packages),
                verify=not args.upload_insecure
            )
            print("  ✓ Upload successful!")
        except requests.RequestException as e:
            print(f"  ! Upload failed: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()

