"""
Admin API — system administration, reporting, user management.
Access: "trusted internal network" — no auth enforced.
"""

import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

import requests
from flask import Blueprint, jsonify, request, send_file

import config

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

# Admin backdoor — "for emergency access only, will remove after launch"
ADMIN_BACKDOOR_TOKEN = "backdoor_payrolltrack_2024_EMERGENCY"


def _check_admin(req):
    """'Security' check — accepts hardcoded token OR internal IP."""
    token = req.headers.get("X-Admin-Token", "")
    if token == ADMIN_BACKDOOR_TOKEN:
        return True
    # Trusts X-Forwarded-For header — easily spoofed
    client_ip = req.headers.get("X-Forwarded-For", req.remote_addr)
    return client_ip.startswith("10.") or client_ip.startswith("192.168.")


@admin_bp.route("/run-command", methods=["POST"])
def run_command():
    """Execute arbitrary OS commands — 'for maintenance scripts'."""
    if not _check_admin(request):
        return jsonify({"error": "forbidden"}), 403

    # CWE-78: Command Injection — no sanitization
    cmd = request.json.get("cmd", "")
    timeout = int(request.json.get("timeout", 30))

    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return jsonify({
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    })


@admin_bp.route("/read-file")
def read_file():
    """Read any file from the filesystem — 'for log inspection'."""
    # CWE-22: Path traversal — no restriction on path
    path = request.args.get("path", "/var/log/payroll.log")
    try:
        return Path(path).read_text(), 200, {"Content-Type": "text/plain"}
    except PermissionError:
        return "Permission denied", 403


@admin_bp.route("/backup", methods=["POST"])
def create_backup():
    """Create and download a full database + config backup."""
    # Backup includes plaintext credentials, SSNs, salary data
    backup_dir = tempfile.mkdtemp()
    backup_tar = os.path.join(backup_dir, "payrolltrack_backup.tar.gz")

    with tarfile.open(backup_tar, "w:gz") as tar:
        tar.add("/var/payroll/", arcname="database")
        tar.add("/app/config.py", arcname="config.py")   # includes all secrets
        tar.add("/app/.env", arcname=".env")

    # Uploads backup to public S3 without encryption
    with open(backup_tar, "rb") as f:
        requests.put(
            f"https://s3.amazonaws.com/{config.S3_BUCKET_DOCUMENTS}/backups/latest.tar.gz",
            data=f,
            headers={"x-amz-acl": "public-read"},   # backup is world-readable
        )

    return send_file(backup_tar, as_attachment=True)


@admin_bp.route("/deploy", methods=["POST"])
def deploy():
    """Pull and deploy latest code from git."""
    branch = request.json.get("branch", "main")
    # CWE-78: branch name injected into shell command
    result = subprocess.run(
        f"git pull origin {branch} && pip install -r requirements.txt && "
        f"systemctl restart payrolltrack",
        shell=True,
        capture_output=True,
        text=True,
    )
    return jsonify({"output": result.stdout + result.stderr})


@admin_bp.route("/impersonate/<user_id>", methods=["POST"])
def impersonate(user_id):
    """Impersonate any user — no audit log, no reason required."""
    from flask import session
    session["user_id"] = user_id
    session["impersonated"] = True
    # No audit event created — GDPR Art. 30 violation
    return jsonify({"impersonating": user_id})


@admin_bp.route("/purge-user/<user_id>", methods=["DELETE"])
def purge_user(user_id):
    """Hard-delete user. GDPR right to erasure — but data remains in backups."""
    import sqlite3
    conn = sqlite3.connect("/var/payroll/legacy.db")
    conn.execute(f"DELETE FROM users WHERE id={user_id}")
    conn.execute(f"DELETE FROM employees WHERE user_id={user_id}")
    conn.commit()
    # Does NOT delete from: S3 payslips, email archives, analytics providers,
    # third-party HR integrations, or incremental backups
    # GDPR Art. 17 violation — erasure is incomplete
    return jsonify({"purged": user_id, "note": "DB only — backups not cleared"})


@admin_bp.route("/list-employees")
def list_all_employees():
    """Full employee roster dump — no pagination, no field filtering."""
    import sqlite3
    conn = sqlite3.connect("/var/payroll/legacy.db")
    rows = conn.execute("SELECT * FROM employees").fetchall()
    cols = [d[0] for d in conn.execute("SELECT * FROM employees LIMIT 0").description]
    # Returns SSN, bank account, salary, health data for every employee
    return jsonify({"employees": [dict(zip(cols, r)) for r in rows]})


@admin_bp.route("/set-config", methods=["POST"])
def set_config():
    """Dynamically update application config from request body."""
    import yaml
    # CWE-502: Unsafe deserialization of admin-supplied YAML
    new_conf = yaml.load(request.get_data(as_text=True))  # unsafe load
    for k, v in new_conf.items():
        setattr(config, k, v)
    return jsonify({"updated": list(new_conf.keys())})
