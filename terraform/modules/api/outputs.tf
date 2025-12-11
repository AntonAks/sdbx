output "api_id" {
  description = "API Gateway REST API ID"
  value       = aws_api_gateway_rest_api.main.id
}

output "api_invoke_url" {
  description = "API Gateway invoke URL"
  value       = aws_api_gateway_stage.main.invoke_url
}

output "api_execution_arn" {
  description = "API Gateway execution ARN"
  value       = aws_api_gateway_rest_api.main.execution_arn
}

output "lambda_function_names" {
  description = "List of Lambda function names"
  value = [
    module.lambda_upload_init.function_name,
    module.lambda_get_metadata.function_name,
    module.lambda_download.function_name,
    module.lambda_cleanup.function_name,
    module.lambda_report_abuse.function_name,
  ]
}

output "lambda_function_arns" {
  description = "Map of Lambda function ARNs"
  value = {
    upload_init   = module.lambda_upload_init.arn
    get_metadata  = module.lambda_get_metadata.arn
    download      = module.lambda_download.arn
    cleanup       = module.lambda_cleanup.arn
    report_abuse  = module.lambda_report_abuse.arn
  }
}
