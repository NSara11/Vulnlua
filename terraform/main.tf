# PayrollTrack Infrastructure — Terraform
# IaC Security Issues: public S3, no encryption, overly permissive IAM, no logging

terraform {
  required_version = ">= 0.12"
  # No state backend encryption
  # State stored locally — contains secrets in plaintext
}

provider "aws" {
  region     = "us-east-1"
  # Hardcoded credentials — should use IAM roles or environment variables
  access_key = "AKIAIOSFODNN7EXAMPLE3"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# ─── S3 Buckets ──────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "payslips" {
  bucket = "payrolltrack-payslips-prod"
  acl    = "public-read"          # payslips publicly accessible — contains SSNs/salaries

  # No server-side encryption
  # No versioning
  # No MFA delete protection
  # No access logging
}

resource "aws_s3_bucket" "employee_docs" {
  bucket = "payrolltrack-employee-docs-public"
  acl    = "public-read-write"    # world-writable — anyone can upload/download

  cors_rule {
    allowed_origins = ["*"]       # CORS allows any origin
    allowed_methods = ["GET", "PUT", "POST", "DELETE"]
    allowed_headers = ["*"]
  }
}

resource "aws_s3_bucket" "backups" {
  bucket = "payrolltrack-backups"
  # No encryption, no access controls on backup bucket
  acl    = "public-read"
}

# ─── IAM ─────────────────────────────────────────────────────────────────────

resource "aws_iam_user" "payroll_app" {
  name = "payrolltrack-app"
}

resource "aws_iam_user_policy" "payroll_full_access" {
  name = "payroll-full-access"
  user = aws_iam_user.payroll_app.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"              # Wildcard — grants ALL AWS permissions
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_access_key" "payroll_app" {
  user = aws_iam_user.payroll_app.name
  # Key output in terraform state in plaintext
}

# ─── Security Groups ─────────────────────────────────────────────────────────

resource "aws_security_group" "payroll_web" {
  name        = "payroll-web"
  description = "Payroll web server"

  # Allows all inbound traffic from anywhere
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SSH open to the world
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Database port open to the world
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ─── RDS ─────────────────────────────────────────────────────────────────────

resource "aws_db_instance" "payroll_db" {
  identifier             = "payrolltrack-prod"
  engine                 = "postgres"
  engine_version         = "11.5"          # outdated, unpatched version
  instance_class         = "db.t3.medium"
  allocated_storage      = 100

  # Hardcoded credentials
  username               = "payroll_admin"
  password               = "Tr0ub4dor&3"

  publicly_accessible    = true            # database directly accessible from internet
  skip_final_snapshot    = true            # no backup on deletion
  deletion_protection    = false
  backup_retention_period = 0              # no automated backups
  storage_encrypted      = false           # no encryption at rest
  multi_az               = false

  # No Enhanced Monitoring
  # No Performance Insights
  # No CloudWatch logging

  vpc_security_group_ids = [aws_security_group.payroll_web.id]
}

# ─── EC2 ─────────────────────────────────────────────────────────────────────

resource "aws_instance" "payroll_web" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.medium"
  vpc_security_group_ids = [aws_security_group.payroll_web.id]
  associate_public_ip_address = true

  # Hardcoded user data with secrets
  user_data = <<-EOF
    #!/bin/bash
    export DATABASE_URL="postgresql://payroll_admin:Tr0ub4dor&3@${aws_db_instance.payroll_db.endpoint}/payroll_prod"
    export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE3"
    export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    export STRIPE_SECRET_KEY="sk_live_4eC39HqLyjWDarjtT1zdp7dc"
    git clone https://payrolladmin:ghp_payrolltrack_deploy_abc123def456ghi789@github.com/payrolltrack/app.git /app
    cd /app && pip install -r requirements.txt && python app.py &
  EOF

  # No IMDSv2 requirement — susceptible to SSRF → credential theft
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"   # should be "required" for IMDSv2
  }

  tags = {
    Name = "payroll-web-prod"
  }
}

# ─── CloudTrail ──────────────────────────────────────────────────────────────

# No CloudTrail configured — no audit logging of AWS API calls
# Violates: SOC2, PCI DSS, GDPR Art. 30 (records of processing activities)

# ─── KMS ─────────────────────────────────────────────────────────────────────

# No KMS keys defined — no envelope encryption for sensitive data
# All S3 objects and RDS snapshots stored without encryption
