#!/usr/bin/env python3
"""
apt_cve_audit.py

Scans every .deb package installed via dpkg/apt on this Debian/Ubuntu system,
checks each source package against Canonical's Ubuntu CVE data (published
through OSV.dev), cross-references with `apt` to see whether an update is
already available in your configured repos, and writes it all to a CSV.

Usage:
    sudo apt-get update          # refresh repo metadata first (recommended)
    python3 apt_cve_audit.py [-o output.csv] [--only-flagged] [--skip-apt-update]

Requirements:
    - Debian/Ubuntu system (dpkg, apt-get)
    - pip install requests
    - Run as a user that can call `apt-get update` (or pass --skip-apt-update
      and run that yourself beforehand) for accurate "outdated" info.

No API key required — OSV.dev's API is public. Works fully offline for the
"outdated" column if you skip the apt-get update step (uses whatever apt
cache you already have).
"""

import argparse
import csv
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "apt-cve-audit/1.0"})


def get_os_ecosystem():
    """Build the OSV ecosystem string, e.g. 'Ubuntu:24.04:LTS'."""
    info = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, _, v = line.strip().partition("=")
                    info[k] = v.strip('"')
    except FileNotFoundError:
        pass

    name = info.get("NAME", "")
    version_id = info.get("VERSION_ID", "")

    if "ubuntu" in name.lower() and version_id:
        # Ubuntu LTS releases (even years, .04) use the :LTS suffix in OSV
        major = version_id.split(".")[0]
        is_lts = major.isdigit() and int(major) % 2 == 0
        return f"Ubuntu:{version_id}{':LTS' if is_lts else ''}", "Ubuntu"

    if "debian" in name.lower() and version_id:
        return "Debian", "Debian"  # Debian ecosystem is not per-release in OSV

    print(f"! Could not confidently detect ecosystem from /etc/os-release "
          f"(NAME={name!r}, VERSION_ID={version_id!r}). Defaulting to Ubuntu 24.04 LTS.",
          file=sys.stderr)
    return "Ubuntu:24.04:LTS", "Ubuntu"


def get_installed_packages():
    """
    Return list of dicts: {binary, binary_version, source, source_version}
    for every package known to dpkg. Falls back to binary name/version if
    source fields are empty (dpkg omits them when source == binary name).
    """
    fmt = r'${Package}\t${Version}\t${source:Package}\t${source:Version}\n'
    try:
        out = subprocess.run(
            ["dpkg-query", "-W", "-f", fmt],
            capture_output=True, text=True, check=True
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"dpkg-query failed: {e}", file=sys.stderr)
        sys.exit(1)

    pkgs = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        binary, binary_version, source, source_version = parts
        pkgs.append({
            "binary": binary,
            "binary_version": binary_version,
            "source": source or binary,
            "source_version": source_version or binary_version,
        })
    return pkgs


def get_upgradable_packages(skip_apt_update):
    """
    Return dict: binary_package_name -> candidate_version for packages that
    apt reports as upgradable. Requires apt cache to be reasonably fresh.
    """
    if not skip_apt_update:
        print("Refreshing apt package lists (apt-get update)...")
        try:
            subprocess.run(["apt-get", "update"], capture_output=True, text=True, timeout=180)
        except Exception as e:
            print(f"  ! apt-get update failed or timed out ({e}); "
                  f"continuing with existing cache.", file=sys.stderr)

    upgradable = {}
    try:
        out = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True, text=True, check=True
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"  ! 'apt list --upgradable' failed: {e}", file=sys.stderr)
        return upgradable

    # Lines look like: pkgname/jammy-updates 1.2.3 amd64 [upgradable from: 1.2.2]
    pattern = re.compile(r"^(?P<pkg>[^/]+)/\S+\s+(?P<ver>\S+)\s")
    for line in out.splitlines():
        m = pattern.match(line)
        if m:
            upgradable[m.group("pkg")] = m.group("ver")
    return upgradable


def chunked(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def query_osv_batch(packages, ecosystem):
    """
    Query OSV.dev batch endpoint for (source, source_version) pairs.
    Returns dict: (source, source_version) -> list of vuln id strings.
    """
    results = {}
    keys = [(p["source"], p["source_version"]) for p in packages]
    # de-dupe since many binaries share one source package
    unique_keys = sorted(set(keys))

    queries = [
        {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        for name, version in unique_keys
    ]

    for batch_keys, batch_queries in zip(chunked(unique_keys, 100), chunked(queries, 100)):
        try:
            resp = SESSION.post(OSV_BATCH_URL, json={"queries": batch_queries}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            print(f"  ! OSV batch query failed: {e}", file=sys.stderr)
            for key in batch_keys:
                results[key] = []
            continue

        for key, res in zip(batch_keys, data.get("results", [])):
            vulns = res.get("vulns", []) or []
            results[key] = [v["id"] for v in vulns]

    return results


def get_vuln_details(vuln_id):
    try:
        resp = SESSION.get(OSV_VULN_URL.format(vuln_id), timeout=15)
        resp.raise_for_status()
        data = resp.json()
        severity = ""
        sev_list = data.get("severity", [])
        if sev_list:
            severity = sev_list[0].get("score", "")
        if not severity:
            severity = data.get("database_specific", {}).get("severity", "")
        summary = data.get("summary", "") or (data.get("details", "") or "")[:200]
        aliases = data.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
        return cve_id, severity, summary
    except requests.RequestException:
        return vuln_id, "", ""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-o", "--output", default="apt_package_audit.csv")
    parser.add_argument("--only-flagged", action="store_true",
                         help="Only include rows that are outdated and/or vulnerable")
    parser.add_argument("--skip-apt-update", action="store_true",
                         help="Don't run apt-get update; use existing apt cache")
    parser.add_argument("--workers", type=int, default=10)
    args = parser.parse_args()

    ecosystem, distro = get_os_ecosystem()
    print(f"Detected ecosystem: {ecosystem}")

    print("Collecting installed dpkg packages...")
    packages = get_installed_packages()
    print(f"Found {len(packages)} installed packages "
          f"({len(set(p['source'] for p in packages))} distinct source packages).")

    print("Checking apt for available upgrades...")
    upgradable = get_upgradable_packages(args.skip_apt_update)
    print(f"apt reports {len(upgradable)} packages as upgradable.")

    print(f"Querying OSV.dev for known vulnerabilities (ecosystem={ecosystem})...")
    osv_results = query_osv_batch(packages, ecosystem)

    all_vuln_ids = sorted({vid for ids in osv_results.values() for vid in ids})
    print(f"Found {len(all_vuln_ids)} distinct vulnerability records. Fetching details...")
    vuln_detail_cache = {}
    if all_vuln_ids:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(get_vuln_details, vid): vid for vid in all_vuln_ids}
            for fut in as_completed(futures):
                vuln_detail_cache[futures[fut]] = fut.result()

    print("Writing CSV report...")
    rows = []
    for p in packages:
        binary, binary_version = p["binary"], p["binary_version"]
        source, source_version = p["source"], p["source_version"]

        candidate = upgradable.get(binary)
        outdated = candidate is not None

        vuln_ids = osv_results.get((source, source_version), [])
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
            "package": binary,
            "installed_version": binary_version,
            "source_package": source,
            "candidate_version": candidate or "",
            "outdated": str(outdated),
            "vulnerable": str(has_vuln),
            "vulnerability_count": len(vuln_ids),
            "cve_ids": "; ".join(cve_ids),
            "severity": "; ".join(severities),
            "summary": " | ".join(summaries)[:500],
        })

    fieldnames = [
        "package", "installed_version", "source_package", "candidate_version",
        "outdated", "vulnerable", "vulnerability_count", "cve_ids", "severity", "summary",
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


if __name__ == "__main__":
    main()
