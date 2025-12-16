# API Gateway REST API
resource "aws_api_gateway_rest_api" "main" {
  name        = "${var.project_name}-${var.environment}-api"
  description = "SecureDrop API for file sharing"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags = var.tags
}

# API Gateway Resources
resource "aws_api_gateway_resource" "upload" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_rest_api.main.root_resource_id
  path_part   = "upload"
}

resource "aws_api_gateway_resource" "upload_init" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_resource.upload.id
  path_part   = "init"
}

resource "aws_api_gateway_resource" "files" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_rest_api.main.root_resource_id
  path_part   = "files"
}

resource "aws_api_gateway_resource" "file" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_resource.files.id
  path_part   = "{file_id}"
}

resource "aws_api_gateway_resource" "metadata" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_resource.file.id
  path_part   = "metadata"
}

resource "aws_api_gateway_resource" "download" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_resource.file.id
  path_part   = "download"
}

resource "aws_api_gateway_resource" "report" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_resource.file.id
  path_part   = "report"
}

# CORS configuration for all resources
module "cors_upload_init" {
  source = "./modules/cors"

  api_id      = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.upload_init.id
}

module "cors_metadata" {
  source = "./modules/cors"

  api_id      = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.metadata.id
}

module "cors_download" {
  source = "./modules/cors"

  api_id      = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.download.id
}

module "cors_report" {
  source = "./modules/cors"

  api_id      = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.report.id
}

# Lambda Functions
module "lambda_upload_init" {
  source = "./modules/lambda"

  function_name = "${var.project_name}-${var.environment}-upload-init"
  handler       = "handler.handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size
  source_dir    = "${path.root}/../../../backend/lambdas/upload_init"

  environment_variables = {
    BUCKET_NAME   = var.bucket_name
    TABLE_NAME    = var.table_name
    ENVIRONMENT   = var.environment
    MAX_FILE_SIZE = var.max_file_size_bytes
  }

  iam_policy_statements = [
    {
      effect = "Allow"
      actions = [
        "s3:PutObject",
        "s3:PutObjectAcl"
      ]
      resources = ["${var.bucket_arn}/*"]
    },
    {
      effect = "Allow"
      actions = [
        "dynamodb:PutItem"
      ]
      resources = [var.table_arn]
    }
  ]

  tags = var.tags
}

module "lambda_get_metadata" {
  source = "./modules/lambda"

  function_name = "${var.project_name}-${var.environment}-get-metadata"
  handler       = "handler.handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size
  source_dir    = "${path.root}/../../../backend/lambdas/get_metadata"

  environment_variables = {
    TABLE_NAME  = var.table_name
    ENVIRONMENT = var.environment
  }

  iam_policy_statements = [
    {
      effect = "Allow"
      actions = [
        "dynamodb:GetItem"
      ]
      resources = [var.table_arn]
    }
  ]

  tags = var.tags
}

module "lambda_download" {
  source = "./modules/lambda"

  function_name = "${var.project_name}-${var.environment}-download"
  handler       = "handler.handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size
  source_dir    = "${path.root}/../../../backend/lambdas/download"

  environment_variables = {
    BUCKET_NAME = var.bucket_name
    TABLE_NAME  = var.table_name
    ENVIRONMENT = var.environment
  }

  iam_policy_statements = [
    {
      effect = "Allow"
      actions = [
        "s3:GetObject"
      ]
      resources = ["${var.bucket_arn}/*"]
    },
    {
      effect = "Allow"
      actions = [
        "dynamodb:UpdateItem",
        "dynamodb:GetItem"
      ]
      resources = [var.table_arn]
    }
  ]

  tags = var.tags
}

module "lambda_cleanup" {
  source = "./modules/lambda"

  function_name = "${var.project_name}-${var.environment}-cleanup"
  handler       = "handler.handler"
  runtime       = var.lambda_runtime
  timeout       = 300 # 5 minutes for cleanup
  memory_size   = var.lambda_memory_size
  source_dir    = "${path.root}/../../../backend/lambdas/cleanup"

  environment_variables = {
    BUCKET_NAME = var.bucket_name
    TABLE_NAME  = var.table_name
    ENVIRONMENT = var.environment
  }

  iam_policy_statements = [
    {
      effect = "Allow"
      actions = [
        "s3:DeleteObject"
      ]
      resources = ["${var.bucket_arn}/*"]
    },
    {
      effect = "Allow"
      actions = [
        "dynamodb:Scan",
        "dynamodb:DeleteItem"
      ]
      resources = [var.table_arn]
    }
  ]

  tags = var.tags
}

module "lambda_report_abuse" {
  source = "./modules/lambda"

  function_name = "${var.project_name}-${var.environment}-report-abuse"
  handler       = "handler.handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size
  source_dir    = "${path.root}/../../../backend/lambdas/report_abuse"

  environment_variables = {
    TABLE_NAME  = var.table_name
    ENVIRONMENT = var.environment
  }

  iam_policy_statements = [
    {
      effect = "Allow"
      actions = [
        "dynamodb:UpdateItem",
        "dynamodb:GetItem"
      ]
      resources = [var.table_arn]
    }
  ]

  tags = var.tags
}

# API Gateway Methods
# POST /upload/init
resource "aws_api_gateway_method" "upload_init_post" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.upload_init.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "upload_init" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.upload_init.id
  http_method             = aws_api_gateway_method.upload_init_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.lambda_upload_init.invoke_arn
}

# GET /files/{file_id}/metadata
resource "aws_api_gateway_method" "metadata_get" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.metadata.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "metadata" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.metadata.id
  http_method             = aws_api_gateway_method.metadata_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.lambda_get_metadata.invoke_arn
}

# POST /files/{file_id}/download
resource "aws_api_gateway_method" "download_post" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.download.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "download" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.download.id
  http_method             = aws_api_gateway_method.download_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.lambda_download.invoke_arn
}

# POST /files/{file_id}/report
resource "aws_api_gateway_method" "report_post" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.report.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "report" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.report.id
  http_method             = aws_api_gateway_method.report_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.lambda_report_abuse.invoke_arn
}

# Lambda permissions for API Gateway
resource "aws_lambda_permission" "upload_init" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_upload_init.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "metadata" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_get_metadata.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "download" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_download.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "report" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_report_abuse.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}

# API Gateway Deployment
resource "aws_api_gateway_deployment" "main" {
  rest_api_id = aws_api_gateway_rest_api.main.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.upload_init.id,
      aws_api_gateway_method.upload_init_post.id,
      aws_api_gateway_integration.upload_init.id,
      aws_api_gateway_method.metadata_get.id,
      aws_api_gateway_integration.metadata.id,
      aws_api_gateway_method.download_post.id,
      aws_api_gateway_integration.download.id,
      aws_api_gateway_method.report_post.id,
      aws_api_gateway_integration.report.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_api_gateway_integration.upload_init,
    aws_api_gateway_integration.metadata,
    aws_api_gateway_integration.download,
    aws_api_gateway_integration.report,
  ]
}

# API Gateway Stage
resource "aws_api_gateway_stage" "main" {
  deployment_id = aws_api_gateway_deployment.main.id
  rest_api_id   = aws_api_gateway_rest_api.main.id
  stage_name    = var.environment

  # Access logging
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      resourcePath   = "$context.resourcePath"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }

  tags = var.tags
}

# CloudWatch Log Group for API Gateway
resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "/aws/apigateway/${var.project_name}-${var.environment}"
  retention_in_days = 7

  tags = var.tags
}

# EventBridge rule for cleanup Lambda (runs every hour)
resource "aws_cloudwatch_event_rule" "cleanup" {
  name                = "${var.project_name}-${var.environment}-cleanup"
  description         = "Trigger cleanup Lambda every hour"
  schedule_expression = "rate(1 hour)"

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "cleanup" {
  rule      = aws_cloudwatch_event_rule.cleanup.name
  target_id = "cleanup-lambda"
  arn       = module.lambda_cleanup.arn
}

resource "aws_lambda_permission" "cleanup_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_cleanup.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cleanup.arn
}
