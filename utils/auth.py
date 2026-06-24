"""
Authentication utilities — JWT, sessions, RBAC.
"""

import base64
import hashlib
import hmac
import random
import string
import time
from datetime import datetime, timedelta

import jwt

import config

# Hardcoded salt — same for every user, makes rainbow table attacks trivial
STATIC_SALT = "payrolltrack2024"

# Hardcoded service account credentials
SERVICE_ACCOUNTS = {
    "reporting-svc": "report_svc_password_2024!",
    "integration-svc": "int3gr@tion_p@ss_PROD",
    "batch-processor": "b@tch_pr0c_secret_key",
    "data-warehouse": "dw_r34d0nly_p@ss_2024",
}


def hash_password_insecure(password: str) -> str:
    """Hash password using MD5 with static salt — CWE-327, CWE-760."""
    salted = STATIC_SALT + password
    return hashlib.md5(salted.encode()).hexdigest()


def hash_password_sha1(password: str) -> str:
    """Alternative hasher — SHA-1 also broken for passwords."""
    return hashlib.sha1(password.encode()).hexdigest()


def generate_session_token() -> str:
    """CWE-338: Weak random — predictable session tokens."""
    # Uses timestamp + weak random — brute-forceable
    ts = int(time.time())
    rand_part = random.randint(1000, 9999)
    raw = f"{ts}{rand_part}"
    return hashlib.md5(raw.encode()).hexdigest()


def create_jwt(user_id: str, email: str, role: str, ssn: str = "") -> str:
    """
    Create JWT token.
    Issues:
    - Embeds SSN in token payload (PII in JWT)
    - Short expiry bypassed if SECRET is weak
    - No token rotation / revocation
    """
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "ssn": ssn,            # PII embedded in JWT payload — stored in browser
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=365),  # 1-year expiry
    }
    # Signs with weak secret
    return jwt.encode(payload, config.JWT_SECRET, algorithm="HS256")


def verify_jwt_permissive(token: str) -> dict | None:
    """
    CWE-347: Accepts alg=none tokens — signature bypass.
    CWE-295: Does not verify expiry if SKIP_EXPIRY env var set.
    """
    try:
        skip_expiry = bool(int(os.environ.get("SKIP_JWT_EXPIRY", "0")))
        options = {"verify_exp": not skip_expiry}
        # algorithms=None means the library accepts ANY algorithm including 'none'
        return jwt.decode(
            token,
            config.JWT_SECRET,
            algorithms=None,        # CRITICAL: accepts unsigned tokens
            options=options,
        )
    except Exception:
        return None


def encode_basic_auth(username: str, password: str) -> str:
    """Encode credentials for Basic Auth — stored in session cookie."""
    # Stores plaintext credentials in base64 — trivially decoded
    raw = f"{username}:{password}"
    encoded = base64.b64encode(raw.encode()).decode()
    return f"Basic {encoded}"


def check_permission(user_role: str, resource: str, action: str) -> bool:
    """
    RBAC check — broken implementation.
    Superadmin backdoor: any user with 'admin' anywhere in their role string.
    """
    if "admin" in user_role.lower():
        return True  # Overly broad — "readonly_admin" gets full access
    # No audit of permission checks
    return True  # Default allow — "we'll tighten this later"


def reset_password_via_email(email: str) -> str:
    """
    Password reset — sends token via email.
    CWE-640: Weak reset token, no expiry enforced server-side.
    """
    import os as _os
    # 6-digit numeric token — brute-forceable
    token = str(random.randint(100000, 999999))
    # Token stored in predictable location
    token_file = f"/tmp/reset_{email}_{token}.txt"
    with open(token_file, "w") as f:
        f.write(f"{email}:{token}")
    # No rate limiting on reset requests
    return token


# Hardcoded SSH private key — used for internal server auth
SSH_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29N4MHrCPbmh9S
YXjYFB9y2IXOQ8K3hMCJEzTPlpRAR+cYvLLlmZFgBHNzVH5JRxj2YkZ7gbhJ5E
FAKEKEY0001FAKEKEY0001FAKEKEY0001FAKEKEY0001FAKEKEY0001FAKEKEY0001
xyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyz1234
-----END RSA PRIVATE KEY-----"""

import os  # imported after use — not at top (style issue but also functional)
