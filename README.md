# Pkg CVE Audit & Server Uploader

`pkg_cve_audit.py` is a standalone, powerful Python script that scans all Python packages installed in your current environment, checks them against the **OSV.dev** vulnerability database, compares installed versions with the latest releases on **PyPI**, generates a local CSV report and an interactive HTML dashboard, and optionally uploads the results to a **PkgAudit** server.

---

## Features

* **Vulnerability Scanning:** Queries the OSV.dev batch API for known vulnerabilities (CVEs, GHSA, PYSEC, etc.) across all installed packages.
* **PyPI Version Check:** Multi-threaded checks against PyPI to detect outdated packages.
* **Local Reporting:** Generates both a detailed `.csv` report and a modern, filterable HTML dashboard (`.html`).
* **Server Ingestion:** Securely uploads the audit report to a remote PkgAudit server via HTTP Basic Auth.
* **Standalone:** Combines audit logic, dashboard generation, and server uploading into a single clean file with minimal external dependencies.

---

## Requirements

* Python 3.8+
* `requests`
* `packaging`

You can install the required packages using pip:

```bash
pip install requests packaging
```

---

## Usage

### 1. Basic Local Audit (CSV + HTML Dashboard)
Runs the audit, saves the report to `package_audit.csv`, and generates the interactive HTML dashboard without opening it automatically:

```bash
python3 pkg_cve_audit.py
```

### 2. Audit & Upload to PkgAudit Server
Runs the audit and uploads the results to your remote server:

```bash
python3 pkg_cve_audit.py \
  --upload-url "https://audit.example.com" \
  --api-user "your_username" \
  --api-password "your_password"
```

### 3. Handling Self-Signed SSL Certificates
If your PkgAudit server uses a self-signed or internal SSL certificate, use the `--upload-insecure` flag to bypass verification errors:

```bash
python3 pkg_cve_audit.py \
  --upload-url "https://audit.example.com" \
  --api-user "admin" \
  --api-password "secret" \
  --upload-insecure
```

---

## Command-Line Arguments

| Argument | Default | Description |
| :--- | :--- | :--- |
| `-o`, `--output` | `package_audit.csv` | Path for the output CSV report. |
| `--only-flagged` | `False` | Only include packages that are outdated and/or vulnerable in the report. |
| `--workers` | `10` | Number of parallel threads for PyPI lookups and OSV details. |
| `--no-dashboard` | `False` | Skip generating the interactive HTML dashboard. |
| `--open-browser` | `False` | Automatically open the generated HTML dashboard in your default browser. |
| `--upload-url` | `None` | PkgAudit server URL (e.g., `https://audit.example.com`). |
| `--api-user` | `None` | API username for PkgAudit server authentication. |
| `--api-password` | `None` | API password for PkgAudit server authentication. |
| `--hostname` | System Hostname | Custom override name for the host in the upload payload. |
| `--upload-insecure`| `False` | Disable SSL certificate verification during upload. |

---

## License

This project is open-source and available under the [MIT License](LICENSE).
