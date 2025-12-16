output "api_endpoint" {
  description = "API Gateway endpoint URL"
  value       = module.api.api_invoke_url
}

output "cloudfront_domain" {
  description = "CloudFront distribution domain name"
  value       = module.cdn.cloudfront_domain
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID"
  value       = module.cdn.cloudfront_distribution_id
}

output "files_bucket_name" {
  description = "S3 bucket name for encrypted files"
  value       = module.storage.files_bucket_name
}

output "static_bucket_name" {
  description = "S3 bucket name for frontend static files"
  value       = module.storage.static_bucket_name
}

output "dynamodb_table_name" {
  description = "DynamoDB table name for file metadata"
  value       = module.storage.table_name
}

output "lambda_function_arns" {
  description = "Map of Lambda function ARNs"
  value       = module.api.lambda_function_arns
}
