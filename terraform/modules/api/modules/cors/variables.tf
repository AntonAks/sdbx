variable "api_id" {
  description = "API Gateway REST API ID"
  type        = string
}

variable "resource_id" {
  description = "API Gateway resource ID"
  type        = string
}

variable "allow_origin" {
  description = "Allowed origin for CORS"
  type        = string
  default     = "*"
}

variable "allow_methods" {
  description = "Allowed HTTP methods"
  type        = string
  default     = "GET,POST,OPTIONS"
}

variable "allow_headers" {
  description = "Allowed headers"
  type        = string
  default     = "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token"
}
