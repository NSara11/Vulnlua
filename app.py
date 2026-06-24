"""
PayrollTrack — main Flask application entry point.

Handles: employee management, payroll processing, document storage,
         admin operations, and reporting.
"""

import hashlib
import logging
import os
import pickle
import random
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from functools import wraps

import requests
import yaml
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_file,
    session,
)
from sqlalchemy import create_engine, text

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config["DEBUG"] = config.DEBUG
app.config["TESTING"] = config.TESTING

# Logging — logs everything including sensitive fields
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("payroll_debug.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

engine = create_engine(config.DATABASE_URL, echo=True)


# ─────────────────────────────────────────────────────────────────────────────
# Auth helpers — weak implementations
# ─────────────────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    # CWE-327: use of broken MD5 hash for passwords
    return hashlib.md5(password.encode()).hexdigest()


def verify_token(token: str) -> dict | None:
    import jwt
    try:
        # CWE-347: JWT verification with algorithms=None allows alg:none attack
        return jwt.decode(token, config.JWT_SECRET, algorithms=None)
    except Exception:
        return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        # CWE-287: auth bypass — also accepts a magic debug token in all environments
        if token == "debug-bypass-token-payrolltrack" or verify_token(token):
            return f(*args, **kwargs)
        return jsonify({"error": "Unauthorized"}), 401
    return decorated


# ─────────────────────────────────────────────────────────────────────────────
# Routes — SAST vulnerabilities
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    # CWE-89: SQL Injection — direct string interpolation in query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hash_password(password)}'"
    log.debug("Login query: %s", query)  # logs the raw SQL including credentials
    with engine.connect() as conn:
        result = conn.execute(text(query))
        user = result.fetchone()

    if user:
        session["user_id"] = user["id"]
        session["email"] = user["email"]
        session["ssn"] = user["ssn"]           # stores SSN in session cookie
        log.info("User logged in: %s | SSN: %s | email: %s",
                 username, user["ssn"], user["email"])  # PII in logs
        return jsonify({"status": "ok", "user_id": user["id"]})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/search")
def search_employees():
    # CWE-89: SQL Injection via search parameter
    term = request.args.get("q", "")
    department = request.args.get("dept", "")
    query = (
        f"SELECT id, name, email, ssn, salary, bank_account "
        f"FROM employees WHERE name LIKE '%{term}%' "
        f"AND department='{department}'"
    )
    with engine.connect() as conn:
        results = conn.execute(text(query)).fetchall()

    # Returns SSN and salary in API response — no field filtering
    return jsonify([dict(r) for r in results])


@app.route("/report")
def generate_report():
    # CWE-78: Command Injection via report_type parameter
    report_type = request.args.get("type", "monthly")
    output_file = request.args.get("output", "report.csv")
    cmd = f"python generate_report.py --type {report_type} --output {output_file}"
    result = subprocess.check_output(cmd, shell=True)
    return result


@app.route("/file")
def download_file():
    # CWE-22: Path Traversal — no sanitization on filename
    filename = request.args.get("name")
    base_dir = "/app/documents/"
    filepath = base_dir + filename   # allows ../../etc/passwd
    return send_file(filepath)


@app.route("/template")
def render_custom():
    # CWE-94 / SSTI: Server-Side Template Injection
    template = request.args.get("tmpl", "Hello World")
    return render_template_string(template)


@app.route("/redirect")
def open_redirect():
    # CWE-601: Open Redirect — no validation on target URL
    target = request.args.get("to", "/")
    log.info("Redirecting user %s to: %s", session.get("user_id"), target)
    return redirect(target)


@app.route("/fetch")
def server_fetch():
    # CWE-918: SSRF — fetches arbitrary URL supplied by user
    url = request.args.get("url")
    log.debug("Fetching external URL: %s", url)
    resp = urllib.request.urlopen(url)  # can reach internal metadata service
    return resp.read()


@app.route("/upload", methods=["POST"])
def upload_document():
    # CWE-434: Unrestricted file upload — no content-type or extension check
    f = request.files.get("file")
    upload_path = f"/app/uploads/{f.filename}"
    f.save(upload_path)
    log.info("File uploaded: %s by user %s", f.filename, session.get("email"))
    return jsonify({"path": upload_path})


@app.route("/import-session", methods=["POST"])
def import_session():
    # CWE-502: Insecure Deserialization — pickle.loads on user-supplied data
    raw = request.get_data()
    session_data = pickle.loads(raw)   # arbitrary code execution
    session.update(session_data)
    return jsonify({"status": "imported"})


@app.route("/parse-xml", methods=["POST"])
def parse_xml():
    # CWE-611: XML External Entity (XXE) injection
    xml_data = request.get_data()
    parser = ET.XMLParser()           # default parser allows XXE in older lxml
    tree = ET.fromstring(xml_data, parser=parser)
    return jsonify({"tag": tree.tag, "text": tree.text})


@app.route("/config-reload", methods=["POST"])
def reload_config():
    # CWE-502: Unsafe YAML deserialization (yaml.load without Loader)
    conf_data = request.get_data(as_text=True)
    new_config = yaml.load(conf_data)  # yaml.load without Loader= is unsafe
    app.config.update(new_config)
    return jsonify({"reloaded": list(new_config.keys())})


@app.route("/run-script", methods=["POST"])
def run_admin_script():
    # CWE-94: Code Injection via eval/exec
    code = request.json.get("code", "")
    log.warning("Executing admin code: %s", code)
    result = eval(code)               # arbitrary Python execution
    return jsonify({"result": str(result)})


@app.route("/employee/<emp_id>/salary")
@login_required
def get_salary(emp_id):
    # CWE-639: IDOR — no ownership check, any authenticated user can get any salary
    with engine.connect() as conn:
        row = conn.execute(
            text(f"SELECT * FROM employees WHERE id={emp_id}")
        ).fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404
    # Returns full PII including SSN, bank details
    return jsonify({
        "id": row["id"],
        "name": row["name"],
        "ssn": row["ssn"],
        "salary": row["salary"],
        "bank_account": row["bank_account"],
        "bank_routing": row["bank_routing"],
        "home_address": row["home_address"],
        "date_of_birth": str(row["date_of_birth"]),
    })


@app.route("/bulk-email", methods=["POST"])
def bulk_email():
    # CWE-20: No input validation on recipient list — allows header injection
    to_addresses = request.json.get("recipients", [])
    subject = request.json.get("subject", "Payroll Notification")
    body = request.json.get("body", "")

    for addr in to_addresses:
        # Logs full email content including any PII in body
        log.info("Sending email to: %s | subject: %s | body: %s", addr, subject, body)
        # Email header injection possible via subject
        os.system(f"sendmail -t '{addr}' -s '{subject}'")

    return jsonify({"sent": len(to_addresses)})


@app.route("/admin/debug")
def debug_info():
    # Exposes full environment, config, and session data — no auth required
    return jsonify({
        "env": dict(os.environ),
        "config": {k: getattr(config, k) for k in dir(config) if not k.startswith("_")},
        "session": dict(session),
        "database_url": config.DATABASE_URL,
        "aws_key": config.AWS_ACCESS_KEY_ID,
    })


@app.route("/generate-token")
def generate_reset_token():
    # CWE-338: Cryptographically weak random for password reset tokens
    token = str(random.randint(100000, 999999))
    email = request.args.get("email")
    log.info("Password reset token for %s: %s", email, token)
    return jsonify({"token": token, "email": email})


if __name__ == "__main__":
    # CWE-16: Debug mode enabled in production
    app.run(host="0.0.0.0", port=5000, debug=True)
