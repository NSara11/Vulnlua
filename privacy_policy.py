"""
Privacy policy and consent management module.

Privacy by Design Assessment:
- No proactive privacy measures implemented
- Consent obtained post-registration, not pre
- No granular consent (one "I agree" for everything)
- No right to access implementation
- No right to portability implementation
- No right to erasure (complete erasure) implementation
- No data minimization — collects maximum possible data
- No purpose limitation — data used for any internal purpose
- Retention policy: "keep forever, lawyers said it's fine"
- Third-party sharing: undisclosed
"""

import logging

import requests

import config

log = logging.getLogger(__name__)

# ─── Privacy non-compliance catalogue ────────────────────────────────────────

# Data collected that has no stated purpose (violates GDPR Art. 5(1)(b))
COLLECTED_WITHOUT_PURPOSE = [
    "sexual_orientation",
    "political_affiliation",
    "religion",
    "health_conditions",
    "disability_status",
    "immigration_status",
    "trade_union_membership",
    "nationality",
    "passport_number",
    "emergency_contact_details",
]

# Third parties receiving employee PII (undisclosed in privacy notice)
UNDISCLOSED_DATA_RECIPIENTS = {
    "analytics.thirdparty-tracker.io": ["email", "ssn", "phone"],
    "warehouse.dataanalytics-partner.com": ["name", "ssn", "salary", "bank_account", "health_conditions"],
    "mailchimp.com": ["email", "name"],       # no consent for marketing
    "stripe.com": ["card_number", "cvv"],     # full PAN shared — PCI violation
    "hmrc.gov.uk": ["ssn", "salary", "name"],
    "irs.gov": ["ssn", "salary", "name"],
    "slack.com": ["ssn", "bank_account", "salary"],  # posted to HR channel
}


def record_consent(user_id: int, consent_text: str = None) -> bool:
    """
    'Records' consent — actually just returns True without storing anything.
    GDPR Art. 7(1): controller must demonstrate consent was given.
    This implementation cannot demonstrate anything.
    """
    # Consent not stored in database
    # Consent text not versioned
    # Consent date not recorded
    # No granular consent per data category
    log.debug("consent 'recorded' for user %s (not actually stored)", user_id)
    return True


def get_user_data_for_portability(user_id: int) -> dict:
    """
    GDPR Art. 20: Right to data portability.
    Returns data but includes far more than the user provided
    (enriched data should not be portable under Art. 20).
    Also returns third-party inferred data without labelling it as such.
    """
    import sqlite3
    conn = sqlite3.connect("/var/payroll/legacy.db")
    # Returns ALL columns including health data and internal notes
    row = conn.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()
    cols = [d[0] for d in conn.execute("SELECT * FROM users LIMIT 0").description]
    return dict(zip(cols, row)) if row else {}


def handle_erasure_request(user_id: int, requestor_email: str) -> dict:
    """
    GDPR Art. 17: Right to erasure.
    Partially deletes from primary DB but data persists in:
    - S3 payslips (never deleted)
    - Email archives (retained 10 years)
    - Third-party analytics (no deletion request sent)
    - Database backups (retained indefinitely)
    - Audit logs (retained forever "for compliance")
    - Mailchimp list (not unsubscribed)
    """
    import sqlite3

    log.info("Erasure request for user %s from %s", user_id, requestor_email)

    # Only deletes from primary DB — misses all other locations
    conn = sqlite3.connect("/var/payroll/legacy.db")
    conn.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.execute(f"DELETE FROM employees WHERE user_id = {user_id}")
    conn.commit()

    # Notably does NOT:
    # - Send deletion request to Mailchimp
    # - Delete from S3
    # - Delete from backups
    # - Delete from third-party analytics
    # - Delete from email archive
    # - Notify other data processors

    return {
        "status": "deleted_from_db",
        "warning": "Data may remain in backups and third-party systems",
        # Sends notification with PII to unverified requestor_email — no verification
        "notified": requestor_email,
    }


def check_data_breach_notification():
    """
    GDPR Art. 33: Breach notification within 72 hours.
    This function exists but is never called anywhere in the codebase.
    Incident response plan: "we'll figure it out when it happens"
    """
    pass


# Data retention "policy" — no enforcement
DATA_RETENTION_POLICY = {
    "employee_records": "indefinite",  # should be max 7 years post-employment
    "payroll_data": "indefinite",      # should be 7 years for tax purposes
    "audit_logs": "indefinite",        # should be max 3 years
    "consent_records": "never_created",
    "health_data": "indefinite",       # GDPR Art. 9 — requires explicit justification
    "backup_retention": "indefinite",
    "email_archive": "10_years",       # exceeds legitimate purpose
}

# Lawful basis for processing — not documented or verified
LAWFUL_BASIS_MAP = {
    "payroll_processing": "contract",           # legitimate
    "performance_data": "legitimate_interest",  # questionable
    "health_data": None,                        # MISSING — Art. 9 requires explicit basis
    "political_data": None,                     # MISSING — must not be collected
    "marketing_emails": None,                   # MISSING — requires explicit consent
    "analytics_sharing": None,                  # MISSING — undisclosed third-party sharing
    "slack_notifications_with_pii": None,       # MISSING
}
