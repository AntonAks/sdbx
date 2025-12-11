locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Storage Module - S3 buckets and DynamoDB table
module "storage" {
  source = "../../modules/storage"

  project_name = var.project_name
  environment  = var.environment
  tags         = local.common_tags
}

# API Module - API Gateway and Lambda functions
module "api" {
  source = "../../modules/api"

  project_name         = var.project_name
  environment          = var.environment
  bucket_name          = module.storage.files_bucket_name
  bucket_arn           = module.storage.files_bucket_arn
  table_name           = module.storage.table_name
  table_arn            = module.storage.table_arn
  max_file_size_bytes  = var.max_file_size_bytes
  tags                 = local.common_tags
}

# CDN Module - CloudFront distribution for frontend
module "cdn" {
  source = "../../modules/cdn"

  project_name      = var.project_name
  environment       = var.environment
  static_bucket_id  = module.storage.static_bucket_id
  static_bucket_arn = module.storage.static_bucket_arn
  api_domain        = module.api.api_invoke_url
  tags              = local.common_tags
}

# Monitoring Module - CloudWatch logs and alarms
module "monitoring" {
  source = "../../modules/monitoring"

  project_name      = var.project_name
  environment       = var.environment
  lambda_functions  = module.api.lambda_function_names
  api_id            = module.api.api_id
  table_name        = module.storage.table_name
  tags              = local.common_tags
}
