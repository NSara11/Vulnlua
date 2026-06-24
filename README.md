# PayrollTrack v2.1.0

**PayrollTrack** is an HR and payroll management SaaS application that handles employee data,
payroll processing, tax filings, and document management for enterprise clients.

## Tech Stack

- **Backend**: Python / Flask
- **Database**: PostgreSQL (prod), SQLite (legacy/dev)
- **Cache**: Redis
- **Queue**: Celery
- **Infrastructure**: AWS (EC2, RDS, S3), Docker, Kubernetes
- **Payments**: Stripe
- **Email**: SendGrid

## Quick Start

```bash
pip install -r requirements.txt
python app.py
```

## Data Handled

- Employee PII: name, SSN, date of birth, home address, passport, phone
- Financial: salary, bank account/routing, card details
- Health: medical leave, disability status, health conditions
- Sensitive HR: immigration status, performance ratings, disciplinary notes

## Architecture

```
Internet → Load Balancer → Flask App → PostgreSQL
                                     → Redis (sessions/cache)
                                     → S3 (payslips, documents, backups)
                                     → Celery Workers (async tasks)
```

## Compliance Status

- GDPR: In progress (target: Q3 2025)
- PCI DSS: SAQ-A (we think)
- SOC 2: Not started
- DPDP Act 2023: Not assessed

## Known Issues

See JIRA board for full list. Notable:
- JIRA-2847: Migrate credentials from config.py to secrets manager
- JIRA-3012: Enable HTTPS on internal service communication
- JIRA-1337: Remove admin backdoor token before go-live
- JIRA-2901: Implement proper password hashing (currently MD5)
- JIRA-3101: Encrypt SSNs at rest
- JIRA-2756: Set up CloudTrail logging
- JIRA-3087: Fix SSRF vulnerability in /fetch endpoint
# Vulnlua
