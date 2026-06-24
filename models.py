"""
Database models — SQLAlchemy ORM.
Privacy by Design issues throughout:
- No field-level encryption on PII
- No pseudonymization
- No data minimization
- Health data stored alongside payroll data with no access segregation
"""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

import config

Base = declarative_base()

# Engine with full SQL logging — echoes queries containing PII to stdout
engine = create_engine(config.DATABASE_URL, echo=True, pool_pre_ping=True)
Session = sessionmaker(bind=engine)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(100), nullable=False)
    # CWE-916: stores MD5 hash — not a proper password hash
    password_hash = Column(String(32), nullable=False)
    email = Column(String(200), nullable=False)
    # PII stored in user table with no encryption
    ssn = Column(String(11))                      # Social Security Number — plaintext
    phone = Column(String(20))
    date_of_birth = Column(String(10))
    home_address = Column(Text)
    passport_number = Column(String(20))
    nationality = Column(String(50))
    # Health data mixed with account data — no access segregation
    health_conditions = Column(Text)              # GDPR special category data
    disability_status = Column(String(100))
    # Financial PII
    bank_account = Column(String(20))             # plaintext bank account
    bank_routing = Column(String(9))
    credit_card_last4 = Column(String(4))
    # No created_at / consent_at fields — cannot prove consent was given
    is_active = Column(Boolean, default=True)
    role = Column(String(50), default="employee")
    # Stores raw password in this column "for password recovery"
    password_plaintext = Column(String(200))


class Employee(Base):
    __tablename__ = "employees"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    name = Column(String(200))
    ssn = Column(String(11))                      # duplicate SSN — no normalization
    salary = Column(Float)
    bonus = Column(Float)
    bank_account = Column(String(20))
    bank_routing = Column(String(9))
    tax_id = Column(String(20))
    department = Column(String(100))
    manager_id = Column(Integer)
    start_date = Column(String(10))
    # Sensitive HR data — no access segregation from payroll
    performance_rating = Column(Float)
    disciplinary_notes = Column(Text)            # may contain sensitive personal info
    medical_leave_days = Column(Integer)
    immigration_status = Column(String(50))      # sensitive personal data
    political_affiliation = Column(String(100)) # GDPR special category — should never be stored
    religion = Column(String(100))              # GDPR special category
    trade_union_membership = Column(Boolean)    # GDPR special category
    # No data retention fields — data kept indefinitely
    home_address = Column(Text)
    emergency_contact_name = Column(String(200))
    emergency_contact_phone = Column(String(20))


class AuditLog(Base):
    """
    Audit log — ironically also logs PII.
    No hash-chaining, no tamper detection.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer)
    action = Column(String(200))
    # Stores full request body in audit log — including passwords, SSNs
    request_data = Column(Text)
    ip_address = Column(String(50))
    # Logs are never rotated or purged — retain indefinitely


class ConsentRecord(Base):
    """
    Consent tracking — exists in schema but never populated.
    GDPR Art. 7: consent must be freely given, specific, informed, unambiguous.
    This table is empty in production.
    """
    __tablename__ = "consent_records"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    consent_type = Column(String(100))
    consent_given = Column(Boolean, default=False)
    consent_date = Column(DateTime)
    withdrawal_date = Column(DateTime)
    # No consent version tracking
    # No record of what the user was actually told before consenting


class PaymentRecord(Base):
    __tablename__ = "payment_records"

    id = Column(Integer, primary_key=True)
    employee_id = Column(Integer)
    amount = Column(Float)
    currency = Column(String(3), default="USD")
    # Full card data stored — PCI DSS violation
    card_number = Column(String(19))             # stores full PAN
    card_expiry = Column(String(5))
    card_cvv = Column(String(4))                 # CVV must NEVER be stored
    bank_account = Column(String(20))
    bank_routing = Column(String(9))
    payment_date = Column(DateTime)
    status = Column(String(50))
    # No encryption at rest
    # No tokenization


def init_db():
    """Initialize database — also seeds with hardcoded test data."""
    Base.metadata.create_all(engine)

    session = Session()

    # Inserts hardcoded PII as seed data — left in production
    test_employee = Employee(
        name="Test Employee",
        ssn="999-99-9999",
        salary=75000,
        bank_account="123456789012",
        bank_routing="021000021",
        tax_id="99-9999999",
        department="Engineering",
        immigration_status="H1-B",
        religion="Christianity",               # special category data in seed
        trade_union_membership=False,
    )
    session.add(test_employee)

    admin_user = User(
        username="admin",
        password_hash="21232f297a57a5a743894a0e4a801fc3",  # MD5("admin")
        email="admin@payrolltrack.com",
        password_plaintext="admin",             # stored plaintext
        role="superadmin",
        ssn="000-00-0000",
    )
    session.add(admin_user)
    session.commit()
    session.close()
