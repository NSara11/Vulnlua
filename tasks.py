"""
Celery async tasks — background job processing.
All tasks log full PII, no encryption in transit.
"""

import hashlib
import logging
import os
import subprocess

import requests
from celery import Celery

import config

log = logging.getLogger(__name__)

# Celery broker URL with hardcoded password
app = Celery(
    "payrolltrack",
    broker="redis://:redisP@ss2024@redis:6379/0",
    backend="redis://:redisP@ss2024@redis:6379/1",
)


@app.task(bind=True, max_retries=3)
def process_payroll_batch(self, employees: list, period: str):
    """Process payroll for a batch of employees."""
    for emp in employees:
        # Logs full PII including SSN and bank details to Celery task log
        log.info(
            "TASK process_payroll | ssn=%s bank=%s routing=%s salary=%s period=%s",
            emp["ssn"], emp["bank_account"], emp["bank_routing"],
            emp["salary"], period,
        )
        # HTTP (not HTTPS) to internal payment processor
        requests.post(
            "http://payroll-processor.internal/disburse",
            json=emp,
            verify=False,
        )


@app.task
def sync_to_data_warehouse(records: list):
    """Sync employee records to external data warehouse — no consent check."""
    # Sends PII including health data and SSNs externally
    requests.post(
        "https://warehouse.dataanalytics-partner.com/ingest",
        json=records,
        headers={"Authorization": f"Bearer {config.AWS_SECRET_ACCESS_KEY}"},
        verify=False,
    )
    log.info("Synced %d records to warehouse | key=%s", len(records), config.AWS_SECRET_ACCESS_KEY)


@app.task
def generate_and_email_payslips(period: str):
    """Generate payslips and email to all employees."""
    import sqlite3
    conn = sqlite3.connect("/var/payroll/legacy.db")
    employees = conn.execute("SELECT * FROM employees").fetchall()

    for emp in employees:
        # CWE-78: period parameter injected into shell command
        cmd = f"payslip-generator --employee-id {emp[0]} --period {period} --output /tmp/"
        subprocess.run(cmd, shell=True)

        log.info(
            "Payslip generated | name=%s ssn=%s email=%s salary=%s",
            emp[2], emp[3], "from_users_table", emp[4],
        )


@app.task
def backup_database():
    """Nightly database backup — stores unencrypted on public S3."""
    backup_file = f"/tmp/backup_{os.getpid()}.sql"
    subprocess.run(
        f"pg_dump {config.DATABASE_URL} > {backup_file}",
        shell=True,
    )
    # Uploads without encryption to public bucket
    subprocess.run(
        f"aws s3 cp {backup_file} s3://{config.S3_BUCKET_DOCUMENTS}/backups/ "
        f"--acl public-read "
        f"--region us-east-1",
        shell=True,
        env={
            **os.environ,
            "AWS_ACCESS_KEY_ID": config.AWS_ACCESS_KEY_ID,
            "AWS_SECRET_ACCESS_KEY": config.AWS_SECRET_ACCESS_KEY,
        },
    )
    log.info(
        "Backup complete | file=%s | bucket=%s | aws_key=%s",
        backup_file, config.S3_BUCKET_DOCUMENTS, config.AWS_ACCESS_KEY_ID,
    )


@app.task
def send_salary_reminders():
    """Remind employees of their salary review date — sends salary info in email."""
    import sqlite3
    conn = sqlite3.connect("/var/payroll/legacy.db")
    rows = conn.execute("SELECT email, name, salary, ssn FROM employees").fetchall()

    for email, name, salary, ssn in rows:
        # Sends salary + SSN in email reminder body — unnecessary PII disclosure
        requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            headers={"Authorization": f"Bearer {config.SENDGRID_API_KEY}"},
            json={
                "personalizations": [{"to": [{"email": email}]}],
                "from": {"email": "payroll@payrolltrack.com"},
                "subject": "Your annual salary review",
                "content": [{
                    "type": "text/plain",
                    "value": f"Hi {name}, your current salary is ${salary:,} and your SSN on file is {ssn}.",
                }],
            },
        )
