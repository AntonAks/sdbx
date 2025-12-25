# S3 Bucket for encrypted files
resource "aws_s3_bucket" "files" {
  bucket = var.files_bucket_name != "" ? var.files_bucket_name : "${var.project_name}-${var.environment}-files"
  tags   = merge(var.tags, { Name = "${var.project_name}-${var.environment}-files" })
}

# Block ALL public access to files bucket
# NOTE: Presigned URLs work perfectly with full public access blocking
resource "aws_s3_bucket_public_access_block" "files" {
  bucket = aws_s3_bucket.files.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true # FIXED: Full blocking is secure and works with presigned URLs
}

# Enable server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "files" {
  bucket = aws_s3_bucket.files.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Lifecycle rule to expire old files and clean up old versions
resource "aws_s3_bucket_lifecycle_configuration" "files" {
  bucket = aws_s3_bucket.files.id

  rule {
    id     = "expire-old-files"
    status = "Enabled"

    filter {}

    # Delete current version after TTL
    expiration {
      days = var.lifecycle_expiration_days
    }

    # Delete old versions after 7 days (prevents cost accumulation)
    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# Enable versioning (optional, for safety)
resource "aws_s3_bucket_versioning" "files" {
  bucket = aws_s3_bucket.files.id

  versioning_configuration {
    status = "Enabled"
  }
}

# CORS configuration for direct browser uploads
# SECURITY: Only allow uploads from trusted origins (CloudFront or custom domain)
resource "aws_s3_bucket_cors_configuration" "files" {
  bucket = aws_s3_bucket.files.id

  cors_rule {
    allowed_headers = ["Content-Type", "x-amz-*"]     # Only essential headers
    allowed_methods = ["GET", "PUT", "HEAD"]          # GET for downloads, PUT for uploads, HEAD for metadata
    allowed_origins = compact([
      var.custom_domain != "" ? "https://${var.custom_domain}" : "",
      var.custom_domain != "" ? "https://www.${var.custom_domain}" : "",
      var.cloudfront_domain != "" ? "https://${var.cloudfront_domain}" : "",
    ])
    expose_headers  = ["ETag", "Content-Length", "Content-Type"] # Expose headers for downloads
    max_age_seconds = 3000
  }
}

# S3 Bucket for static frontend files
resource "aws_s3_bucket" "static" {
  bucket = var.static_bucket_name != "" ? var.static_bucket_name : "${var.project_name}-${var.environment}-static"
  tags   = merge(var.tags, { Name = "${var.project_name}-${var.environment}-static" })
}

# Block public access to static bucket (CloudFront will access via OAI)
resource "aws_s3_bucket_public_access_block" "static" {
  bucket = aws_s3_bucket.static.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable server-side encryption for static bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "static" {
  bucket = aws_s3_bucket.static.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# DynamoDB table for file metadata
resource "aws_dynamodb_table" "files" {
  name         = "${var.project_name}-${var.environment}-files"
  billing_mode = "PAY_PER_REQUEST" # On-demand pricing
  hash_key     = "file_id"

  attribute {
    name = "file_id"
    type = "S"
  }

  # Enable TTL for automatic expiration
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  # Enable point-in-time recovery
  point_in_time_recovery {
    enabled = true
  }

  tags = merge(var.tags, { Name = "${var.project_name}-${var.environment}-files" })
}
