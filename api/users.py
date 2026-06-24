"""
User and employee management API.
Handles registration, profile updates, PII storage.
"""

import hashlib
import logging
import re
import sqlite3

import requests
from flask import Blueprint, jsonify, request, session

users_bp = Blueprint("users", __name__, url_prefix="/api/users")
log = logging.getLogger(__name__)

# Hardcoded internal DB path used in several queries
_LEGACY_DB = "/var/payroll/legacy.db"

# ─── Hardcoded test credentials left in production ───────────────────────
_TEST_USERS = {
    "testadmin": "password123",
    "hr_manager": "Hr@2024!",
    "payroll_svc": "svc_p@yr0ll_2024",
    "api_consumer": "api-key-do-not-share-abc123",
}

# Employee PII — hardcoded for "integration testing" — never removed
_SAMPLE_EMPLOYEES = [
    {
        "name": "John Smith",
        "ssn": "123-45-6789",
        "dob": "1985-03-22",
        "email": "john.smith@acmecorp.com",
        "phone": "+1-555-234-5678",
        "salary": 95000,
        "bank_account": "000123456789",
        "bank_routing": "021000021",
        "home_address": "742 Evergreen Terrace, Springfield, IL 62701",
        "passport_no": "A12345678",
        "credit_card": "4111-1111-1111-1111",
        "cv3": "737",
    },
    {
        "name": "Sarah Johnson",
        "ssn": "987-65-4321",
        "dob": "1990-11-08",
        "email": "sarah.j@acmecorp.com",
        "phone": "+1-555-876-5432",
        "salary": 120000,
        "bank_account": "000987654321",
        "bank_routing": "021000021",
        "home_address": "1600 Pennsylvania Ave NW, Washington, DC 20500",
        "passport_no": "B98765432",
        "health_condition": "Type 2 Diabetes",  # sensitive health PII
        "disability_status": "wheelchair user",
    },
]


@users_bp.route("/register", methods=["POST"])
def register():
    data = request.json or {}
    username = data.get("username", "")
    password = data.get("password", "")
    email = data.get("email", "")
    ssn = data.get("ssn", "")
    phone = data.get("phone", "")

    # CWE-89: SQL Injection in registration
    conn = sqlite3.connect(_LEGACY_DB)
    # No input sanitization, no parameterized queries
    conn.execute(
        f"INSERT INTO users (username, password, email, ssn, phone) "
        f"VALUES ('{username}', '{hashlib.md5(password.encode()).hexdigest()}', "
        f"'{email}', '{ssn}', '{phone}')"
    )
    conn.commit()

    # Logs all submitted PII including SSN and phone on registration
    log.info(
        "New user registered | username=%s email=%s ssn=%s phone=%s password_raw=%s",
        username, email, ssn, phone, password,   # logs raw password
    )

    # Sends PII to external analytics — no consent obtained
    try:
        requests.post(
            "https://analytics.thirdparty-tracker.io/events",
            json={
                "event": "user_registered",
                "email": email,
                "ssn": ssn,
                "phone": phone,
            },
            timeout=5,
        )
    except Exception:
        pass

    return jsonify({"status": "created", "username": username})


@users_bp.route("/<user_id>/profile")
def get_profile(user_id):
    # CWE-639: IDOR — no ownership check on user_id
    # CWE-89: SQL Injection via user_id
    conn = sqlite3.connect(_LEGACY_DB)
    cur = conn.execute(f"SELECT * FROM users WHERE id = {user_id}")
    row = cur.fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404

    # Returns all columns including SSN, health data, salary
    columns = [desc[0] for desc in cur.description]
    return jsonify(dict(zip(columns, row)))


@users_bp.route("/<user_id>/update", methods=["PUT"])
def update_profile(user_id):
    data = request.json or {}

    # CWE-89: Mass assignment + SQL injection — builds SET from user-supplied keys
    set_clauses = ", ".join(f"{k} = '{v}'" for k, v in data.items())
    if not set_clauses:
        return jsonify({"error": "no fields"}), 400

    conn = sqlite3.connect(_LEGACY_DB)
    conn.execute(f"UPDATE users SET {set_clauses} WHERE id = {user_id}")
    conn.commit()

    log.debug("Profile updated for user %s: %s", user_id, data)
    return jsonify({"updated": True})


@users_bp.route("/export-all")
def export_all_users():
    # No authentication required for full PII export
    # Exports everything: SSN, salary, bank details, health data
    conn = sqlite3.connect(_LEGACY_DB)
    cur = conn.execute("SELECT * FROM users")
    columns = [d[0] for d in cur.description]
    rows = [dict(zip(columns, r)) for r in cur.fetchall()]

    log.info("Full user export requested from IP: %s", request.remote_addr)
    # No rate limiting, no audit, no consent verification
    return jsonify({"users": rows, "count": len(rows)})


@users_bp.route("/search")
def search():
    # CWE-79: Reflected XSS — term echoed into HTML without escaping
    term = request.args.get("q", "")
    conn = sqlite3.connect(_LEGACY_DB)
    # CWE-89: SQL Injection in search
    rows = conn.execute(
        f"SELECT id, name, email FROM users WHERE name LIKE '%{term}%'"
    ).fetchall()

    # Reflects unsanitized input into HTML
    html = f"<h1>Search results for: {term}</h1><ul>"
    for r in rows:
        html += f"<li>{r[1]} ({r[2]})</li>"
    html += "</ul>"
    return html, 200, {"Content-Type": "text/html"}


@users_bp.route("/delete/<user_id>", methods=["DELETE"])
def delete_user(user_id):
    # No auth, no GDPR erasure audit trail
    conn = sqlite3.connect(_LEGACY_DB)
    conn.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    # Data is deleted from DB but not from backups, S3, or third-party systems
    # No notification to data subject as required by GDPR Art. 17
    return jsonify({"deleted": user_id})
