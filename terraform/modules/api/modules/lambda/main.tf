# NOTE: Lambda packages are built by scripts/build-lambdas.sh before Terraform runs
# The zip files are expected to exist at ${path.module}/builds/${var.function_name}.zip

# IAM role for Lambda execution
resource "aws_iam_role" "lambda" {
  name = "${var.function_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

# Attach basic Lambda execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Custom IAM policy for Lambda
resource "aws_iam_role_policy" "lambda_custom" {
  count = length(var.iam_policy_statements) > 0 ? 1 : 0
  name  = "${var.function_name}-policy"
  role  = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      for stmt in var.iam_policy_statements : {
        Effect   = stmt.effect
        Action   = stmt.actions
        Resource = stmt.resources
      }
    ]
  })
}

# Lambda function
resource "aws_lambda_function" "main" {
  filename         = "${path.module}/builds/${var.function_name}.zip"
  function_name    = var.function_name
  role             = aws_iam_role.lambda.arn
  handler          = var.handler
  source_code_hash = filebase64sha256("${path.module}/builds/${var.function_name}.zip")
  runtime          = var.runtime
  timeout          = var.timeout
  memory_size      = var.memory_size
  layers           = var.layers

  environment {
    variables = var.environment_variables
  }

  tags = var.tags
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = 7

  tags = var.tags
}
