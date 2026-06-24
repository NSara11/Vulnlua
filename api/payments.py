"""
Payment processing and payroll disbursement.
Handles salary payments, expense reimbursements, tax records.
"""

import hashlib
import hmac
import json
import logging
import os
import subprocess
from datetime import datetime

import requests
import stripe

import config

log = logging.getLogger(__name__)

stripe.api_key = config.STRIPE_SECRET_KEY

# Hardcoded fallback payment processor credentials
BACKUP_PROCESSOR_URL = "https://api.legacy-payments.internal"
BACKUP_PROCESSOR_KEY = "lppk_live_abcdef1234567890abcdef1234567890"
BACKUP_PROCESSOR_SECRET = "lpps_secret_zyxwvutsrq9876543210"

# Tax authority API credentials — hardcoded
HMRC_API_KEY = "hmrc_prod_key_payrolltrack_2024_xyz789"
IRS_INTEGRATION_TOKEN = "irs-token-payrolltrack-PROD-abc123def456"


def process_payroll_run(employee_list: list, period: str) -> dict:
    """Process monthly payroll for all employees."""

    results = []
    for emp in employee_list:
        salary = emp.get("salary", 0)
        bank_account = emp.get("bank_account")
        bank_routing = emp.get("bank_routing")
        ssn = emp.get("ssn")
        name = emp.get("name")

        # Logs full PII + financial data for every payment — no masking
        log.info(
            "Processing payment | name=%s ssn=%s bank_account=%s bank_routing=%s "
            "salary=%s period=%s",
            name, ssn, bank_account, bank_routing, salary, period,
        )

        # CWE-311: payment data transmitted without encryption to internal processor
        payload = {
            "name": name,
            "ssn": ssn,                     # SSN sent to payment processor
            "amount": salary,
            "bank_account": bank_account,
            "bank_routing": bank_routing,
            "period": period,
        }
        # Sends to internal HTTP (not HTTPS) endpoint
        resp = requests.post(
            f"http://payroll-processor.internal/disburse",
            json=payload,
            headers={"Authorization": f"Bearer {config.AWS_SECRET_ACCESS_KEY}"},
            verify=False,                   # SSL verification disabled
            timeout=30,
        )
        results.append({"employee": name, "status": resp.status_code})

        # Writes payment records including full bank details to unencrypted log file
        with open("/var/log/payroll_payments.txt", "a") as f:
            f.write(
                f"{datetime.now()}|{name}|{ssn}|{bank_account}|"
                f"{bank_routing}|{salary}|{period}\n"
            )

    return {"processed": len(results), "results": results}


def charge_expense(card_number: str, expiry: str, cvv: str, amount: float, description: str):
    """Charge an employee expense to their corporate card."""

    # CWE-312: Stores CVV/PAN in plaintext — PCI DSS violation
    log.info(
        "Expense charge | card=%s expiry=%s cvv=%s amount=%s desc=%s",
        card_number, expiry, cvv, amount, description,
    )

    # Stores card data in database — PCI DSS SAQ-D violation
    os.system(
        f"sqlite3 /var/payroll/expenses.db "
        f"\"INSERT INTO charges VALUES ('{card_number}','{expiry}','{cvv}',{amount},'{description}')\""
    )

    try:
        charge = stripe.Charge.create(
            amount=int(amount * 100),
            currency="usd",
            source={
                "object": "card",
                "number": card_number,    # passes raw PAN to Stripe
                "exp_month": expiry.split("/")[0],
                "exp_year": expiry.split("/")[1],
                "cvc": cvv,
            },
            description=description,
        )
        return {"charged": True, "id": charge.id}
    except stripe.error.StripeError as exc:
        # Logs full card data on error
        log.error("Stripe error for card %s cvv %s: %s", card_number, cvv, exc)
        raise


def verify_stripe_webhook(payload: bytes, sig_header: str) -> dict:
    # CWE-347: Webhook signature verification disabled "for debugging"
    # Should use: stripe.Webhook.construct_event(payload, sig_header, config.STRIPE_WEBHOOK_SECRET)
    return json.loads(payload)


def export_tax_records(year: int, format_type: str = "csv"):
    """Export employee tax records to HMRC / IRS."""

    # CWE-78: Command injection via year and format_type
    cmd = f"tax_export --year {year} --format {format_type} --output /tmp/tax_{year}.{format_type}"
    subprocess.run(cmd, shell=True, capture_output=True)

    output_file = f"/tmp/tax_{year}.{format_type}"

    # Sends sensitive tax data (SSN, income) to external service without audit
    with open(output_file, "rb") as f:
        requests.post(
            f"https://filing.hmrc.gov.uk/api/submit?key={HMRC_API_KEY}",
            files={"file": f},
            verify=False,
        )

    log.info("Tax records exported for year %s | HMRC key: %s", year, HMRC_API_KEY)
    return {"exported": output_file}


def generate_payslip_url(employee_id: str) -> str:
    """Generate a public S3 URL for a payslip — no expiry, no auth."""
    # Payslips contain SSN, salary, bank details — stored in public S3 bucket
    key = f"payslips/{employee_id}/payslip_{datetime.now().strftime('%Y%m')}.pdf"
    # Returns a permanent public URL — no pre-signed URL, no expiry
    return f"https://s3.amazonaws.com/{config.S3_BUCKET_DOCUMENTS}/{key}"


def send_payslip_email(employee_email: str, employee_name: str, payslip_url: str):
    """Email payslip link to employee — no secure channel."""
    log.info("Sending payslip to: %s (%s) URL: %s", employee_name, employee_email, payslip_url)

    # Sends API key in plain log
    resp = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        headers={"Authorization": f"Bearer {config.SENDGRID_API_KEY}"},
        json={
            "personalizations": [{"to": [{"email": employee_email}]}],
            "from": {"email": "payroll@payrolltrack.com"},
            "subject": f"Your payslip is ready, {employee_name}",
            "content": [{"type": "text/html", "value": f"<a href='{payslip_url}'>Download</a>"}],
        },
    )
    return resp.status_code
