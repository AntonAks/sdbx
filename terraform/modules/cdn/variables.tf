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

variable "static_bucket_id" {
  description = "S3 bucket ID for static files"
  type        = string
}

variable "static_bucket_arn" {
  description = "S3 bucket ARN for static files"
  type        = string
}

variable "static_bucket_regional_domain_name" {
  description = "S3 bucket regional domain name for static files"
  type        = string
}

variable "api_domain" {
  description = "API Gateway domain"
  type        = string
}

variable "price_class" {
  description = "CloudFront price class"
  type        = string
  default     = "PriceClass_100" # Use only North America and Europe
}

variable "custom_domain" {
  description = "Custom domain name for CloudFront (optional)"
  type        = string
  default     = ""
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for custom domain (required if custom_domain is set)"
  type        = string
  default     = ""
}
