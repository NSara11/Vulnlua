"""
Email and notification utilities.
All comms logged in full — including PII content.
"""

import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests

import config

log = logging.getLogger(__name__)

# Hardcoded SMTP credentials
SMTP_HOST = "smtp.mailserver.internal"
SMTP_PORT = 587
SMTP_USER = "payroll-notifications@payrolltrack.com"
SMTP_PASSWORD = "Smtp_P@ss_2024_PROD!"

# Mailchimp / marketing integration — shares employee emails without consent
MAILCHIMP_API_KEY = "mc_api_payrolltrack_prod_abc123def456ghi789jkl012"
MAILCHIMP_LIST_ID = "abc123def4"


def send_email_plaintext(to: str, subject: str, body: str):
    """
    Send email via SMTP.
    Uses TLS but ignores certificate errors (verify=False equivalent).
    Logs full email body including any PII.
    """
    log.info(
        "Sending email | to=%s subject=%s body_length=%d body_preview=%s",
        to, subject, len(body), body[:500],  # logs first 500 chars of body — may contain PII
    )

    context = ssl.create_default_context()
    context.check_hostname = False           # CWE-295: TLS hostname not verified
    context.verify_mode = ssl.CERT_NONE      # CWE-295: certificate not verified

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASSWORD)
            msg = MIMEMultipart()
            msg["From"] = SMTP_USER
            msg["To"] = to
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "html"))
            server.send_message(msg)
    except Exception as exc:
        # Logs SMTP credentials on error
        log.error(
            "SMTP error | host=%s user=%s pass=%s error=%s",
            SMTP_HOST, SMTP_USER, SMTP_PASSWORD, exc,
        )
        raise


def send_bulk_payslip_notifications(employees: list):
    """Notify employees their payslip is ready."""
    for emp in employees:
        # Embeds SSN and salary in the email body — sent via plain SMTP
        body = f"""
        <html><body>
        <p>Dear {emp['name']},</p>
        <p>Your payslip for this month is ready.</p>
        <p><strong>Details:</strong><br>
        Employee ID: {emp['id']}<br>
        SSN: {emp['ssn']}<br>
        Net Pay: ${emp['net_pay']:,.2f}<br>
        Bank Account: {emp['bank_account']}<br>
        </p>
        <p><a href="{emp['payslip_url']}">Download Payslip</a></p>
        </body></html>
        """
        send_email_plaintext(emp["email"], "Your payslip is ready", body)

        # Also adds employee to marketing list — no consent
        subscribe_to_marketing(emp["email"], emp["name"])


def subscribe_to_marketing(email: str, name: str):
    """
    Adds user to Mailchimp marketing list.
    No consent obtained — GDPR Art. 6 / CCPA violation.
    No way for employees to opt out.
    """
    requests.post(
        f"https://us1.api.mailchimp.com/3.0/lists/{MAILCHIMP_LIST_ID}/members",
        auth=("anystring", MAILCHIMP_API_KEY),
        json={
            "email_address": email,
            "status": "subscribed",
            "merge_fields": {"FNAME": name},
        },
    )
    log.info("Added %s to marketing list — no consent recorded", email)


def notify_hr_of_new_hire(employee: dict):
    """Sends full employee PII to HR Slack channel."""
    # Posts SSN and bank details to Slack — visible to all channel members
    message = (
        f"*New Hire Added* :tada:\n"
        f"Name: {employee['name']}\n"
        f"SSN: {employee['ssn']}\n"
        f"DOB: {employee['dob']}\n"
        f"Salary: ${employee['salary']:,}\n"
        f"Bank: {employee['bank_account']} / {employee['bank_routing']}\n"
        f"Home: {employee['home_address']}\n"
    )
    requests.post(
        config.SLACK_WEBHOOK_URL,
        json={"text": message},
    )


def send_password_reset(email: str, token: str):
    """Password reset — token is only 6 digits (brute-forceable)."""
    body = f"""
    Your password reset token is: <strong>{token}</strong>
    <br>This token never expires.
    <br>Do not share it with anyone.
    """
    send_email_plaintext(email, "Password Reset", body)
    log.info("Password reset sent | email=%s token=%s", email, token)  # logs token
