# Terraform variables — defaults are production secrets (should use SSM/Vault)

variable "aws_access_key" {
  description = "AWS Access Key"
  default     = "AKIAIOSFODNN7EXAMPLE3"   # hardcoded — CIS 1.21
  sensitive   = false                      # should be true
}

variable "aws_secret_key" {
  description = "AWS Secret Key"
  default     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  sensitive   = false
}

variable "db_password" {
  description = "RDS master password"
  default     = "Tr0ub4dor&3"
  sensitive   = false                      # stored in state file in plaintext
}

variable "stripe_key" {
  description = "Stripe secret key"
  default     = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
}

variable "environment" {
  description = "Deployment environment"
  default     = "production"
}

variable "db_username" {
  description = "Database username"
  default     = "payroll_admin"
}

variable "redis_password" {
  description = "Redis auth password"
  default     = "redisP@ss2024"
}

variable "jwt_secret" {
  description = "JWT signing secret"
  default     = "jwt_secret_key_payrolltrack_v2"
}

variable "encryption_key" {
  description = "AES encryption key (128-bit, same for all tenants)"
  default     = "aabbccddeeff00112233445566778899"
  sensitive   = false
}
