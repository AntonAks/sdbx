variable "environment" {
  description = "Deployment environment (dev or prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "Environment must be 'dev' or 'prod'."
  }
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "eu-central-1"
}

variable "project_name" {
  description = "Project name used in resource naming"
  type        = string
  default     = "sdbx"
}

variable "max_file_size_bytes" {
  description = "Maximum file size in bytes"
  type        = number
  default     = 104857600 # 100 MB
}

variable "allowed_ttl_hours" {
  description = "Allowed TTL values in hours"
  type        = list(number)
  default     = [1, 12, 24]

  validation {
    condition     = alltrue([for t in var.allowed_ttl_hours : t > 0 && t <= 168])
    error_message = "TTL values must be between 1 and 168 hours (1 week)."
  }
}

variable "recaptcha_secret_key" {
  description = "Google reCAPTCHA v3 secret key for bot protection"
  type        = string
  sensitive   = true
}
