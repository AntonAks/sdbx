variable "project_name" {
  description = "Project name for resource naming"
  type        = string
}

variable "environment" {
  description = "Environment (dev or prod)"
  type        = string
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}

variable "files_bucket_name" {
  description = "Name for the encrypted files S3 bucket (optional, auto-generated if not provided)"
  type        = string
  default     = ""
}

variable "static_bucket_name" {
  description = "Name for the static frontend S3 bucket (optional, auto-generated if not provided)"
  type        = string
  default     = ""
}

variable "lifecycle_expiration_days" {
  description = "Number of days after which files are automatically deleted"
  type        = number
  default     = 7
}

variable "custom_domain" {
  description = "Custom domain name for CORS configuration"
  type        = string
  default     = ""
}

variable "cloudfront_domain" {
  description = "CloudFront domain name for CORS configuration (leave empty for initial deployment)"
  type        = string
  default     = ""
}
