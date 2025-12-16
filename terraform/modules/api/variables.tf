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

variable "bucket_name" {
  description = "S3 bucket name for encrypted files"
  type        = string
}

variable "bucket_arn" {
  description = "S3 bucket ARN for encrypted files"
  type        = string
}

variable "table_name" {
  description = "DynamoDB table name for file metadata"
  type        = string
}

variable "table_arn" {
  description = "DynamoDB table ARN for file metadata"
  type        = string
}

variable "max_file_size_bytes" {
  description = "Maximum file size in bytes"
  type        = number
  default     = 104857600 # 100 MB
}

variable "cloudfront_secret" {
  description = "Secret for CloudFront origin verification"
  type        = string
  sensitive   = true
}

variable "lambda_runtime" {
  description = "Lambda runtime version"
  type        = string
  default     = "python3.12"
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 30
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 256
}
