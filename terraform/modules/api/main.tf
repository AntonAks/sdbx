# API Gateway REST API
resource "aws_api_gateway_rest_api" "main" {
  name        = "${var.project_name}-${var.environment}-api"
  description = "sdbx API for zero-knowledge file sharing"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags = var.tags
}

# Request Validator - validates request body and parameters
resource "aws_api_gateway_request_validator" "main" {
  rest_api_id                 = aws_api_gateway_rest_api.main.id
  name                        = "${var.project_name}-${var.environment}-validator"
  validate_request_body       = true
  validate_request_parameters = true
}

# Request Models - JSON schemas for request validation

# Upload Init Request Model (supports both files and text)
resource "aws_api_gateway_model" "upload_request" {
  rest_api_id  = aws_api_gateway_rest_api.main.id
  name         = "UploadInitRequest"
  content_type = "application/json"

  schema = jsonencode({
    "$schema" = "http://json-schema.org/draft-04/schema#"
    type      = "object"
    properties = {
      content_type = {
        type = "string"
        enum = ["file", "text"]
      }
      file_size = {
        type    = "integer"
        minimum = 1
        maximum = var.max_file_size_bytes
      }
      encrypted_text = {
        type      = "string"
        minLength = 1
        maxLength = 10000
      }
      ttl = {
        type = "string"
        enum = ["1h", "12h", "24h"]
      }
      recaptcha_token = {
        type      = "string"
        minLength = 10
        maxLength = 2000
      }
    }
    required = ["ttl", "recaptcha_token"]
  })
}

# Download Request Model
resource "aws_api_gateway_model" "download_request" {
  rest_api_id  = aws_api_gateway_rest_api.main.id
  name         = "DownloadRequest"
  content_type = "application/json"

  schema = jsonencode({
    "$schema" = "http://json-schema.org/draft-04/schema#"
    type      = "object"
    properties = {
      recaptcha_token = {
        type      = "string"
        minLength = 10
        maxLength = 2000
      }
    }
    required = ["recaptcha_token"]
  })
}

# Report Abuse Request Model
resource "aws_api_gateway_model" "report_abuse_request" {
  rest_api_id  = aws_api_gateway_rest_api.main.id
  name         = "ReportAbuseRequest"
  content_type = "application/json"

  schema = jsonencode({
    "$schema" = "http://json-schema.org/draft-04/schema#"
    type      = "object"
    properties = {
      reason = {
        type      = "string"
        minLength = 1
        maxLength = 500
      }
      recaptcha_token = {
        type      = "string"
        minLength = 10
        maxLength = 2000
      }
    }
    required = ["recaptcha_token"]
  })
}

# Lambda Layer for shared dependencies
resource "null_resource" "dependencies_layer_build" {
  triggers = {
    requirements = filemd5("${path.module}/../../../backend/lambdas/requirements.txt")
  }

  provisioner "local-exec" {
    command = <<-EOT
      mkdir -p ${path.module}/builds/layer/python
      pip install -q -r ${path.module}/../../../backend/lambdas/requirements.txt -t ${path.module}/builds/layer/python/
      cd ${path.module}/builds/layer
      zip -r ../dependencies-layer.zip python/ -x "*.pyc" -x "__pycache__/*"
    EOT
  }
}

resource "aws_lambda_layer_version" "dependencies" {
  filename            = "${path.module}/builds/dependencies-layer.zip"
  layer_name          = "${var.project_name}-${var.environment}-dependencies"
  compatible_runtimes = [var.lambda_runtime]
  description         = "Shared dependencies: requests, boto3"

  depends_on = [null_resource.dependencies_layer_build]

  lifecycle {
    create_before_destroy = true
  }
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

resource "aws_api_gateway_resource" "confirm" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_resource.file.id
  path_part   = "confirm"
}

resource "aws_api_gateway_resource" "report" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_resource.file.id
  path_part   = "report"
}

resource "aws_api_gateway_resource" "stats" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_rest_api.main.root_resource_id
  path_part   = "stats"
}

# /pin resource
resource "aws_api_gateway_resource" "pin" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_rest_api.main.root_resource_id
  path_part   = "pin"
}

# /pin/upload
resource "aws_api_gateway_resource" "pin_upload" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_resource.pin.id
  path_part   = "upload"
}

# /pin/initiate
resource "aws_api_gateway_resource" "pin_initiate" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_resource.pin.id
  path_part   = "initiate"
}

# /pin/verify
resource "aws_api_gateway_resource" "pin_verify" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_resource.pin.id
  path_part   = "verify"
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

module "cors_confirm" {
  source = "./modules/cors"

  api_id      = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.confirm.id
}

module "cors_report" {
  source = "./modules/cors"

  api_id      = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.report.id
}

module "cors_stats" {
  source = "./modules/cors"

  api_id      = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.stats.id
}

module "cors_pin_upload" {
  source      = "./modules/cors"
  api_id      = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.pin_upload.id
}

module "cors_pin_initiate" {
  source      = "./modules/cors"
  api_id      = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.pin_initiate.id
}

module "cors_pin_verify" {
  source      = "./modules/cors"
  api_id      = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.pin_verify.id
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
  layers        = [aws_lambda_layer_version.dependencies.arn]

  environment_variables = {
    BUCKET_NAME          = var.bucket_name
    TABLE_NAME           = var.table_name
    ENVIRONMENT          = var.environment
    MAX_FILE_SIZE        = var.max_file_size_bytes
    CLOUDFRONT_SECRET    = var.cloudfront_secret
    RECAPTCHA_SECRET_KEY = var.recaptcha_secret_key
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
  layers        = [aws_lambda_layer_version.dependencies.arn]

  environment_variables = {
    TABLE_NAME        = var.table_name
    ENVIRONMENT       = var.environment
    CLOUDFRONT_SECRET = var.cloudfront_secret
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
  layers        = [aws_lambda_layer_version.dependencies.arn]

  environment_variables = {
    BUCKET_NAME          = var.bucket_name
    TABLE_NAME           = var.table_name
    ENVIRONMENT          = var.environment
    CLOUDFRONT_SECRET    = var.cloudfront_secret
    RECAPTCHA_SECRET_KEY = var.recaptcha_secret_key
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

module "lambda_confirm_download" {
  source = "./modules/lambda"

  function_name = "${var.project_name}-${var.environment}-confirm-download"
  handler       = "handler.handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size
  source_dir    = "${path.root}/../../../backend/lambdas/confirm_download"
  layers        = [aws_lambda_layer_version.dependencies.arn]

  environment_variables = {
    TABLE_NAME        = var.table_name
    ENVIRONMENT       = var.environment
    CLOUDFRONT_SECRET = var.cloudfront_secret
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

module "lambda_cleanup" {
  source = "./modules/lambda"

  function_name = "${var.project_name}-${var.environment}-cleanup"
  handler       = "handler.handler"
  runtime       = var.lambda_runtime
  timeout       = 300 # 5 minutes for cleanup
  memory_size   = var.lambda_memory_size
  source_dir    = "${path.root}/../../../backend/lambdas/cleanup"
  layers        = [aws_lambda_layer_version.dependencies.arn]

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
  layers        = [aws_lambda_layer_version.dependencies.arn]

  environment_variables = {
    TABLE_NAME           = var.table_name
    ENVIRONMENT          = var.environment
    CLOUDFRONT_SECRET    = var.cloudfront_secret
    RECAPTCHA_SECRET_KEY = var.recaptcha_secret_key
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

module "lambda_get_stats" {
  source = "./modules/lambda"

  function_name = "${var.project_name}-${var.environment}-get-stats"
  handler       = "handler.handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size
  source_dir    = "${path.root}/../../../backend/lambdas/get_stats"
  layers        = [aws_lambda_layer_version.dependencies.arn]

  environment_variables = {
    TABLE_NAME        = var.table_name
    ENVIRONMENT       = var.environment
    CLOUDFRONT_SECRET = var.cloudfront_secret
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

module "lambda_pin_upload_init" {
  source = "./modules/lambda"

  function_name = "${var.project_name}-${var.environment}-pin-upload-init"
  handler       = "handler.handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size
  source_dir    = "${path.root}/../../../backend/lambdas/pin_upload_init"
  layers        = [aws_lambda_layer_version.dependencies.arn]

  environment_variables = {
    BUCKET_NAME          = var.bucket_name
    TABLE_NAME           = var.table_name
    ENVIRONMENT          = var.environment
    MAX_FILE_SIZE        = var.max_file_size_bytes
    CLOUDFRONT_SECRET    = var.cloudfront_secret
    RECAPTCHA_SECRET_KEY = var.recaptcha_secret_key
  }

  iam_policy_statements = [
    {
      effect    = "Allow"
      actions   = ["s3:PutObject", "s3:PutObjectAcl"]
      resources = ["${var.bucket_arn}/*"]
    },
    {
      effect    = "Allow"
      actions   = ["dynamodb:PutItem", "dynamodb:GetItem"]
      resources = [var.table_arn]
    }
  ]

  tags = var.tags
}

module "lambda_pin_initiate" {
  source = "./modules/lambda"

  function_name = "${var.project_name}-${var.environment}-pin-initiate"
  handler       = "handler.handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size
  source_dir    = "${path.root}/../../../backend/lambdas/pin_initiate"
  layers        = [aws_lambda_layer_version.dependencies.arn]

  environment_variables = {
    TABLE_NAME           = var.table_name
    ENVIRONMENT          = var.environment
    CLOUDFRONT_SECRET    = var.cloudfront_secret
    RECAPTCHA_SECRET_KEY = var.recaptcha_secret_key
  }

  iam_policy_statements = [
    {
      effect    = "Allow"
      actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
      resources = [var.table_arn]
    }
  ]

  tags = var.tags
}

module "lambda_pin_verify" {
  source = "./modules/lambda"

  function_name = "${var.project_name}-${var.environment}-pin-verify"
  handler       = "handler.handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size
  source_dir    = "${path.root}/../../../backend/lambdas/pin_verify"
  layers        = [aws_lambda_layer_version.dependencies.arn]

  environment_variables = {
    BUCKET_NAME          = var.bucket_name
    TABLE_NAME           = var.table_name
    ENVIRONMENT          = var.environment
    CLOUDFRONT_SECRET    = var.cloudfront_secret
    RECAPTCHA_SECRET_KEY = var.recaptcha_secret_key
  }

  iam_policy_statements = [
    {
      effect    = "Allow"
      actions   = ["s3:GetObject"]
      resources = ["${var.bucket_arn}/*"]
    },
    {
      effect    = "Allow"
      actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
      resources = [var.table_arn]
    }
  ]

  tags = var.tags
}

# API Gateway Methods
# POST /upload/init
resource "aws_api_gateway_method" "upload_init_post" {
  rest_api_id          = aws_api_gateway_rest_api.main.id
  resource_id          = aws_api_gateway_resource.upload_init.id
  http_method          = "POST"
  authorization        = "NONE"
  # Disable request validation - handled in Lambda
  # request_validator_id = aws_api_gateway_request_validator.main.id

  # request_models = {
  #   "application/json" = aws_api_gateway_model.upload_request.name
  # }
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
  rest_api_id          = aws_api_gateway_rest_api.main.id
  resource_id          = aws_api_gateway_resource.download.id
  http_method          = "POST"
  authorization        = "NONE"
  request_validator_id = aws_api_gateway_request_validator.main.id

  request_models = {
    "application/json" = aws_api_gateway_model.download_request.name
  }
}

resource "aws_api_gateway_integration" "download" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.download.id
  http_method             = aws_api_gateway_method.download_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.lambda_download.invoke_arn
}

# POST /files/{file_id}/confirm
resource "aws_api_gateway_method" "confirm_post" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.confirm.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "confirm" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.confirm.id
  http_method             = aws_api_gateway_method.confirm_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.lambda_confirm_download.invoke_arn
}

# POST /files/{file_id}/report
resource "aws_api_gateway_method" "report_post" {
  rest_api_id          = aws_api_gateway_rest_api.main.id
  resource_id          = aws_api_gateway_resource.report.id
  http_method          = "POST"
  authorization        = "NONE"
  request_validator_id = aws_api_gateway_request_validator.main.id

  request_models = {
    "application/json" = aws_api_gateway_model.report_abuse_request.name
  }
}

resource "aws_api_gateway_integration" "report" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.report.id
  http_method             = aws_api_gateway_method.report_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.lambda_report_abuse.invoke_arn
}

# GET /stats
resource "aws_api_gateway_method" "stats_get" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.stats.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "stats" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.stats.id
  http_method             = aws_api_gateway_method.stats_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.lambda_get_stats.invoke_arn
}

# POST /pin/upload
resource "aws_api_gateway_method" "pin_upload_post" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.pin_upload.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "pin_upload" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.pin_upload.id
  http_method             = aws_api_gateway_method.pin_upload_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.lambda_pin_upload_init.invoke_arn
}

# POST /pin/initiate
resource "aws_api_gateway_method" "pin_initiate_post" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.pin_initiate.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "pin_initiate" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.pin_initiate.id
  http_method             = aws_api_gateway_method.pin_initiate_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.lambda_pin_initiate.invoke_arn
}

# POST /pin/verify
resource "aws_api_gateway_method" "pin_verify_post" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.pin_verify.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "pin_verify" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.pin_verify.id
  http_method             = aws_api_gateway_method.pin_verify_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.lambda_pin_verify.invoke_arn
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

resource "aws_lambda_permission" "confirm_download" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_confirm_download.function_name
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

resource "aws_lambda_permission" "stats" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_get_stats.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "pin_upload" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_pin_upload_init.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "pin_initiate" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_pin_initiate.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "pin_verify" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_pin_verify.function_name
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
      aws_api_gateway_method.confirm_post.id,
      aws_api_gateway_integration.confirm.id,
      aws_api_gateway_method.report_post.id,
      aws_api_gateway_integration.report.id,
      aws_api_gateway_method.stats_get.id,
      aws_api_gateway_integration.stats.id,
      aws_api_gateway_method.pin_upload_post.id,
      aws_api_gateway_integration.pin_upload.id,
      aws_api_gateway_method.pin_initiate_post.id,
      aws_api_gateway_integration.pin_initiate.id,
      aws_api_gateway_method.pin_verify_post.id,
      aws_api_gateway_integration.pin_verify.id,
      # Force redeployment - increment this number when needed
      "v4",
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_api_gateway_integration.upload_init,
    aws_api_gateway_integration.metadata,
    aws_api_gateway_integration.download,
    aws_api_gateway_integration.confirm,
    aws_api_gateway_integration.report,
    aws_api_gateway_integration.stats,
    aws_api_gateway_integration.pin_upload,
    aws_api_gateway_integration.pin_initiate,
    aws_api_gateway_integration.pin_verify,
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

# API Gateway Throttling - prevents abuse and controls costs
resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  stage_name  = aws_api_gateway_stage.main.stage_name
  method_path = "*/*" # Apply to all methods

  settings {
    throttling_burst_limit = var.environment == "prod" ? 5000 : 1000 # Concurrent requests
    throttling_rate_limit  = var.environment == "prod" ? 2000 : 500  # Requests per second
    logging_level          = "INFO"
    data_trace_enabled     = false
    metrics_enabled        = true
  }
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
