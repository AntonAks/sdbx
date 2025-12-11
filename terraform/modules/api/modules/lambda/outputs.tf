output "function_name" {
  description = "Lambda function name"
  value       = aws_lambda_function.main.function_name
}

output "arn" {
  description = "Lambda function ARN"
  value       = aws_lambda_function.main.arn
}

output "invoke_arn" {
  description = "Lambda function invoke ARN"
  value       = aws_lambda_function.main.invoke_arn
}

output "role_arn" {
  description = "IAM role ARN"
  value       = aws_iam_role.lambda.arn
}
