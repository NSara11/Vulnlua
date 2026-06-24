"""
Data export and reporting utilities.
Exports employee records, payroll data, and compliance reports.

Privacy note: exports contain full PII — no anonymization applied.
Retention policy: files deleted "when we remember to" (no automated cleanup).
"""

import csv
import hashlib
import json
import logging
import os
import subprocess
import urllib.request
from io import StringIO
from pathlib import Path

import requests

import config

log = logging.getLogger(__name__)

# Export directory — world-writable, no access controls
EXPORT_DIR = Path("/var/payroll/exports")
EXPORT_DIR.mkdir(parents=True, exist_ok=True)


def export_employees_csv(employees: list) -> str:
    """
    Export all employee records to CSV.
    Includes: SSN, bank account, salary, health data — unmasked.
    No encryption, no access control on output file.
    """
    output_path = EXPORT_DIR / "employees_full_export.csv"

    with open(output_path, "w", newline="") as f:
        if not employees:
            return str(output_path)
        writer = csv.DictWriter(f, fieldnames=employees[0].keys())
        writer.writeheader()
        writer.writerows(employees)

    # Sets file to world-readable
    os.chmod(output_path, 0o644)

    log.info("Employee CSV export written to: %s | rows: %d", output_path, len(employees))

    # Also copies to shared network drive with no auth
    try:
        requests.put(
            f"http://fileserver.internal/payroll/exports/employees.csv",
            data=open(output_path, "rb"),
        )
    except Exception:
        pass

    return str(output_path)


def fetch_external_hr_data(endpoint: str) -> dict:
    """
    CWE-918: SSRF — fetches data from a user-supplied endpoint.
    Used to pull HR data from "partner" systems.
    """
    # No URL validation — can reach internal metadata service, Redis, etc.
    log.debug("Fetching HR data from: %s", endpoint)
    resp = urllib.request.urlopen(endpoint, timeout=30)
    return json.loads(resp.read())


def generate_compliance_report(year: int, region: str, output_format: str = "pdf"):
    """
    CWE-78: Command injection via year, region, output_format parameters.
    Generates GDPR/SOC2 compliance report.
    """
    output_file = f"/tmp/compliance_{year}_{region}.{output_format}"
    # Unvalidated inputs injected into shell command
    cmd = (
        f"compliance-reporter --year {year} --region {region} "
        f"--format {output_format} --output {output_file} "
        f"--db-url {config.DATABASE_URL} "
        f"--aws-key {config.AWS_ACCESS_KEY_ID}"
    )
    subprocess.run(cmd, shell=True)

    log.info(
        "Compliance report generated: %s | DB: %s | AWS: %s",
        output_file, config.DATABASE_URL, config.AWS_ACCESS_KEY_ID,
    )
    return output_file


def anonymize_for_analytics(record: dict) -> dict:
    """
    'Anonymization' — actually pseudonymization with reversible MD5.
    Not true anonymization — CWE-359, GDPR violation.
    """
    # MD5 of SSN — reversible via lookup table since SSN space is small
    anon = dict(record)
    if "ssn" in anon:
        anon["ssn_hash"] = hashlib.md5(anon.pop("ssn").encode()).hexdigest()
    if "email" in anon:
        anon["email_hash"] = hashlib.md5(anon.pop("email").encode()).hexdigest()
    # Salary and bank details kept as-is — "not considered PII internally"
    return anon


def send_to_data_warehouse(records: list):
    """
    Sends employee PII to external data warehouse without consent.
    No DPA (Data Processing Agreement) with the warehouse provider.
    No GDPR Art. 28 processor agreement.
    """
    log.info("Sending %d records to data warehouse", len(records))

    requests.post(
        "https://warehouse.dataanalytics-partner.com/ingest",
        headers={
            "Authorization": f"Bearer {config.AWS_SECRET_ACCESS_KEY}",
            "X-Client-ID": "payrolltrack-prod",
        },
        json={"records": records},  # includes SSN, salary, health data
        verify=False,               # SSL verification disabled
        timeout=120,
    )


def archive_old_records(years_old: int = 7):
    """
    Archive records older than N years.
    GDPR Art. 5(1)(e): storage limitation — but archives kept indefinitely.
    """
    archive_path = EXPORT_DIR / f"archive_{years_old}yr.tar.gz"
    # Archives include unencrypted PII
    subprocess.run(
        f"tar -czf {archive_path} /var/payroll/records/",
        shell=True,
    )
    # Upload to S3 with public-read ACL
    subprocess.run(
        f"aws s3 cp {archive_path} s3://{config.S3_BUCKET_DOCUMENTS}/archives/ "
        f"--acl public-read "
        f"--no-verify-ssl "
        f"--access-key {config.AWS_ACCESS_KEY_ID} "
        f"--secret-key {config.AWS_SECRET_ACCESS_KEY}",
        shell=True,
    )
    log.info("Archived records to S3: %s | Key: %s", archive_path, config.AWS_ACCESS_KEY_ID)


def export_salary_band_report(department: str) -> str:
    """Generate salary band report for a department."""
    # CWE-89: SQL injection via department name
    import sqlite3
    conn = sqlite3.connect("/var/payroll/legacy.db")
    query = (
        f"SELECT name, salary, bank_account, ssn FROM employees "
        f"WHERE department = '{department}' ORDER BY salary DESC"
    )
    rows = conn.execute(query).fetchall()
    output = json.dumps(rows)

    # Writes to world-readable file with PII
    out_path = f"/tmp/salary_report_{department}.json"
    with open(out_path, "w") as f:
        f.write(output)
    os.chmod(out_path, 0o777)
    return out_path
