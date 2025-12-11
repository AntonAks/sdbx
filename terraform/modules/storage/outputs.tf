output "files_bucket_name" {
  description = "Name of the encrypted files S3 bucket"
  value       = aws_s3_bucket.files.id
}

output "files_bucket_arn" {
  description = "ARN of the encrypted files S3 bucket"
  value       = aws_s3_bucket.files.arn
}

output "files_bucket_regional_domain_name" {
  description = "Regional domain name of the files bucket"
  value       = aws_s3_bucket.files.bucket_regional_domain_name
}

output "static_bucket_name" {
  description = "Name of the static frontend S3 bucket"
  value       = aws_s3_bucket.static.id
}

output "static_bucket_id" {
  description = "ID of the static frontend S3 bucket"
  value       = aws_s3_bucket.static.id
}

output "static_bucket_arn" {
  description = "ARN of the static frontend S3 bucket"
  value       = aws_s3_bucket.static.arn
}

output "static_bucket_regional_domain_name" {
  description = "Regional domain name of the static bucket"
  value       = aws_s3_bucket.static.bucket_regional_domain_name
}

output "table_name" {
  description = "Name of the DynamoDB table"
  value       = aws_dynamodb_table.files.name
}

output "table_arn" {
  description = "ARN of the DynamoDB table"
  value       = aws_dynamodb_table.files.arn
}
