#!/usr/bin/env python3
import sys
import json
import requests

def test_nvd_api(cve_id, api_key=None):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"User-Agent": "nvd-test-script/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    print(f"[*] Querying NVD API for: {cve_id}...")
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        print(f"[*] HTTP Status Code: {resp.status_code}")
        if resp.status_code != 200:
            print(f"[!] Error response body: {resp.text}")
            return

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        print(f"[*] Total vulnerabilities returned in array: {len(vulnerabilities)}")
        if not vulnerabilities:
            print("[!] No vulnerability data found for this ID.")
            return
        cve_item = vulnerabilities[0].get("cve", {})
        metrics = cve_item.get("metrics", {})
        print("\n=== Parsed NVD Metrics ===")
        severity = "Not Found"
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                metric_entry = metrics[version][0]  # First authority/score profile
                severity = metric_entry.get("cvssData", {}).get("baseSeverity", "")
                score = metric_entry.get("cvssData", {}).get("baseScore", "")
                print(f"[✓] Found {version}: Severity = {severity}, Score = {score}")
                break
        descriptions = cve_item.get("descriptions", [])
        summary = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "No English description")
        print(f"[✓] Extracted Severity Summary: {severity}")
        print(f"[✓] Extracted English Description (Truncated): {summary[:150]}...")
        with open(f"{cve_id}_raw.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        print(f"\n[*] Raw JSON structure saved to: {cve_id}_raw.json")

    except Exception as e:
        print(f"[!] Request failed: {e}")

if __name__ == "__main__":
    target_cve = "CVE-2022-40897" 
    if len(sys.argv) > 1:
        target_cve = sys.argv[1]
    test_nvd_api(target_cve)
