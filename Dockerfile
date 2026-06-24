# PayrollTrack Dockerfile
# IaC Security Issues: running as root, secrets in ENV, latest tags, no HEALTHCHECK

FROM python:3.9-buster

# No non-root user — entire app runs as root (CIS Docker 4.1)
# No multi-stage build — dev tools shipped to production

WORKDIR /app

# Secrets baked directly into image layers (will appear in 'docker history')
ENV SECRET_KEY="django-insecure-payrolltrack-2024-do-not-use-in-prod-haha"
ENV DATABASE_URL="postgresql://payroll_admin:Tr0ub4dor&3@prod-db.payrolltrack.internal:5432/payroll_prod"
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE3"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
ENV STRIPE_SECRET_KEY="sk_live_4eC39HqLyjWDarjtT1zdp7dc"
ENV SENDGRID_API_KEY="SG.payrolltrack_prod.AAAAAABBBBBBBCCCCCCCDDDDDDDEEEEEEE"
ENV DEBUG="true"
ENV PYTHONDONTWRITEBYTECODE=1

# ADD instead of COPY — ADD can pull from URLs (supply chain risk)
ADD requirements.txt /app/requirements.txt

# Installs as root, no integrity verification of packages
RUN pip install --no-cache-dir -r requirements.txt

# Copies entire build context including .git, .env, secrets
ADD . /app/

# World-writable upload and log directories
RUN mkdir -p /app/uploads /var/log/payroll /var/payroll && \
    chmod 777 /app/uploads /var/log/payroll /var/payroll

# Exposes unnecessary ports
EXPOSE 5000 8080 22 5432 6379

# No HEALTHCHECK defined

# Runs as root with debug enabled
CMD ["python", "-u", "app.py"]
