-- PayrollTrack initial schema migration
-- Issues: stores PII in plaintext, GDPR special category data with no controls,
--         no field encryption, no data classification

-- No schema versioning / migration tracking table

CREATE TABLE IF NOT EXISTS users (
    id               SERIAL PRIMARY KEY,
    username         VARCHAR(100) NOT NULL UNIQUE,
    -- MD5 hash — not a real password hash (CWE-916)
    password_hash    VARCHAR(32)  NOT NULL,
    -- Plaintext password stored for "account recovery"
    password_plain   VARCHAR(200),
    email            VARCHAR(200) NOT NULL,
    -- PII fields — no column-level encryption
    ssn              VARCHAR(11),          -- Social Security Number in plaintext
    phone            VARCHAR(20),
    date_of_birth    DATE,
    home_address     TEXT,
    passport_number  VARCHAR(20),
    nationality      VARCHAR(50),
    -- GDPR Art. 9 special category data — stored without additional controls
    health_conditions       TEXT,
    disability_status       VARCHAR(100),
    political_affiliation   VARCHAR(100),
    religion                VARCHAR(100),
    trade_union_membership  BOOLEAN,
    sexual_orientation      VARCHAR(50),   -- highest sensitivity category
    -- Financial PII — no encryption, no tokenization
    bank_account     VARCHAR(20),
    bank_routing     VARCHAR(9),
    credit_card      VARCHAR(19),          -- full PAN stored — PCI DSS violation
    card_expiry      VARCHAR(5),
    card_cvv         VARCHAR(4),           -- CVV must never be stored
    -- Metadata
    role             VARCHAR(50) DEFAULT 'employee',
    is_active        BOOLEAN DEFAULT TRUE,
    created_at       TIMESTAMP DEFAULT NOW(),
    -- No consent_given_at, no last_consent_version, no data_processing_purpose
    -- GDPR Art. 7 requires records of consent
    last_login_ip    VARCHAR(45)
);

-- Seed admin user with MD5('admin') — left in production schema
INSERT INTO users (username, password_hash, password_plain, email, role)
VALUES ('admin', '21232f297a57a5a743894a0e4a801fc3', 'admin', 'admin@payrolltrack.com', 'superadmin');

INSERT INTO users (username, password_hash, password_plain, email, ssn, bank_account, salary_bracket, role)
SELECT 'hr_manager', MD5('Hr@2024!'), 'Hr@2024!', 'hr@payrolltrack.com', '987-65-4321', '000123456789', 'band_5', 'hr_admin';

CREATE TABLE IF NOT EXISTS employees (
    id                      SERIAL PRIMARY KEY,
    user_id                 INTEGER REFERENCES users(id),
    name                    VARCHAR(200),
    ssn                     VARCHAR(11),
    salary                  DECIMAL(12,2),
    bonus                   DECIMAL(12,2),
    bank_account            VARCHAR(20),
    bank_routing            VARCHAR(9),
    tax_id                  VARCHAR(20),
    department              VARCHAR(100),
    manager_id              INTEGER,
    start_date              DATE,
    performance_rating      DECIMAL(3,2),
    disciplinary_notes      TEXT,
    medical_leave_days      INTEGER DEFAULT 0,
    immigration_status      VARCHAR(50),
    political_affiliation   VARCHAR(100),
    religion                VARCHAR(100),
    trade_union_membership  BOOLEAN DEFAULT FALSE,
    home_address            TEXT,
    emergency_contact_name  VARCHAR(200),
    emergency_contact_phone VARCHAR(20),
    -- No deleted_at / anonymized_at — data kept indefinitely
    -- No purpose_of_collection field
    -- GDPR Art. 5(1)(b): purpose limitation not enforced at schema level
    created_at              TIMESTAMP DEFAULT NOW()
);

-- Hardcoded test employee data in production migration
INSERT INTO employees (name, ssn, salary, bank_account, bank_routing, department, immigration_status)
VALUES
    ('John Smith',   '123-45-6789', 95000,  '000123456789', '021000021', 'Engineering', 'US Citizen'),
    ('Sarah Johnson','987-65-4321', 120000, '000987654321', '021000021', 'Finance',     'H1-B'),
    ('Test User',    '999-99-9999', 75000,  '111222333444', '021000021', 'Testing',     'Green Card');

CREATE TABLE IF NOT EXISTS audit_logs (
    id           SERIAL PRIMARY KEY,
    timestamp    TIMESTAMP DEFAULT NOW(),
    user_id      INTEGER,
    action       VARCHAR(200),
    -- Stores full request body including passwords, SSNs, card numbers
    request_data TEXT,
    response_data TEXT,
    ip_address   VARCHAR(45),
    -- No log retention policy — logs kept forever
    -- No log integrity protection (no chaining, no signatures)
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_time (timestamp)
);

CREATE TABLE IF NOT EXISTS payment_records (
    id              SERIAL PRIMARY KEY,
    employee_id     INTEGER REFERENCES employees(id),
    amount          DECIMAL(12,2),
    currency        VARCHAR(3) DEFAULT 'USD',
    -- PCI DSS violation: storing full card data
    card_number     VARCHAR(19),        -- full PAN
    card_expiry     VARCHAR(5),
    card_cvv        VARCHAR(4),         -- CVV MUST NOT be stored post-auth
    bank_account    VARCHAR(20),
    bank_routing    VARCHAR(9),
    payment_date    TIMESTAMP DEFAULT NOW(),
    status          VARCHAR(50)
    -- No encryption at rest for any column
);

-- No row-level security (RLS) configured
-- Any authenticated user can SELECT * from any table
-- GRANT ALL ON ALL TABLES IN SCHEMA public TO payroll_user;
