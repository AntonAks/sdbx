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

variable "lambda_functions" {
  description = "List of Lambda function names to monitor"
  type        = list(string)
}

variable "api_id" {
  description = "API Gateway ID"
  type        = string
}

variable "table_name" {
  description = "DynamoDB table name"
  type        = string
}

variable "alarm_email" {
  description = "Email address for alarm notifications (optional)"
  type        = string
  default     = ""
}

variable "lambda_error_threshold" {
  description = "Number of Lambda errors to trigger alarm"
  type        = number
  default     = 10
}

variable "api_5xx_threshold" {
  description = "Number of API Gateway 5xx errors to trigger alarm"
  type        = number
  default     = 5
}
