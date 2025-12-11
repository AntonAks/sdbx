# Monitoring Module

This module creates CloudWatch monitoring and alerting for sdbx.

## Resources Created

- **CloudWatch Alarms**:
  - Lambda function errors, throttles, and duration
  - API Gateway 4xx/5xx errors and latency
  - DynamoDB read/write throttles

- **CloudWatch Dashboard**: Centralized metrics view

- **SNS Topic** (optional): Email notifications for alarms

## Usage

```hcl
module "monitoring" {
  source = "../../modules/monitoring"

  project_name      = "sdbx"
  environment       = "dev"
  lambda_functions  = module.api.lambda_function_names
  api_id            = module.api.api_id
  table_name        = module.storage.table_name
  alarm_email       = "alerts@example.com"  # Optional
  tags              = local.common_tags
}
```

## Alarm Thresholds

| Metric | Threshold | Period |
|--------|-----------|--------|
| Lambda Errors | 10 errors | 5 min |
| Lambda Throttles | 5 throttles | 5 min |
| Lambda Duration | 25 seconds | 5 min |
| API 5xx Errors | 5 errors | 5 min |
| API 4xx Errors | 50 errors | 5 min |
| API Latency | 5 seconds | 5 min |
| DynamoDB Throttles | 5 throttles | 5 min |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| project_name | Project name | string | - | yes |
| environment | Environment | string | - | yes |
| lambda_functions | Lambda function names | list(string) | - | yes |
| api_id | API Gateway ID | string | - | yes |
| table_name | DynamoDB table name | string | - | yes |
| alarm_email | Email for alerts | string | "" | no |
| lambda_error_threshold | Lambda error threshold | number | 10 | no |
| api_5xx_threshold | API 5xx threshold | number | 5 | no |

## Outputs

| Name | Description |
|------|-------------|
| sns_topic_arn | SNS topic ARN |
| dashboard_name | Dashboard name |
| lambda_error_alarm_names | Lambda alarm names |
| api_alarm_names | API alarm names |
