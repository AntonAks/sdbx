output "sns_topic_arn" {
  description = "SNS topic ARN for alarms"
  value       = var.alarm_email != "" ? aws_sns_topic.alarms[0].arn : ""
}

output "dashboard_name" {
  description = "CloudWatch dashboard name"
  value       = aws_cloudwatch_dashboard.main.dashboard_name
}

output "lambda_error_alarm_names" {
  description = "Lambda error alarm names"
  value       = [for alarm in aws_cloudwatch_metric_alarm.lambda_errors : alarm.alarm_name]
}

output "api_alarm_names" {
  description = "API Gateway alarm names"
  value = [
    aws_cloudwatch_metric_alarm.api_5xx_errors.alarm_name,
    aws_cloudwatch_metric_alarm.api_4xx_errors.alarm_name,
    aws_cloudwatch_metric_alarm.api_latency.alarm_name,
  ]
}
