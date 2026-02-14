# CloudFront Origin Access Identity for S3
resource "aws_cloudfront_origin_access_identity" "main" {
  comment = "${var.project_name}-${var.environment} OAI for static files"
}

# S3 bucket policy to allow CloudFront access
resource "aws_s3_bucket_policy" "static" {
  bucket = var.static_bucket_id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowCloudFrontAccess"
      Effect = "Allow"
      Principal = {
        AWS = aws_cloudfront_origin_access_identity.main.iam_arn
      }
      Action   = "s3:GetObject"
      Resource = "${var.static_bucket_arn}/*"
    }]
  })
}

# Security headers policy for CloudFront responses
resource "aws_cloudfront_response_headers_policy" "security_headers" {
  name    = "${var.project_name}-${var.environment}-security-headers"
  comment = "Security headers for ${var.project_name} - CSP, HSTS, and anti-clickjacking"

  security_headers_config {
    # Content Security Policy - Protects against XSS attacks
    content_security_policy {
      content_security_policy = join("; ", [
        "default-src 'self'",
        "script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self' https://www.google.com/recaptcha/ https://*.execute-api.eu-central-1.amazonaws.com https://*.s3.eu-central-1.amazonaws.com",
        "frame-src https://www.google.com/recaptcha/",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "upgrade-insecure-requests"
      ])
      override = true
    }

    # Prevent MIME-type sniffing attacks
    content_type_options {
      override = true
    }

    # Prevent clickjacking attacks
    frame_options {
      frame_option = "DENY"
      override     = true
    }

    # Force HTTPS for 1 year (with preload and subdomains)
    strict_transport_security {
      access_control_max_age_sec = 31536000 # 1 year
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    # Prevent browsers from performing certain types of XSS detection
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }

    # Control referrer information sent with requests
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
  }
}

# CloudFront distribution for frontend
resource "aws_cloudfront_distribution" "main" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "${var.project_name}-${var.environment} frontend distribution"
  default_root_object = "index.html"
  price_class         = var.price_class

  # Custom domain (optional)
  aliases = var.custom_domain != "" ? [var.custom_domain, "www.${var.custom_domain}"] : []

  # Origin: S3 static bucket
  origin {
    domain_name = var.static_bucket_regional_domain_name
    origin_id   = "S3-${var.static_bucket_id}"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.main.cloudfront_access_identity_path
    }
  }

  # Origin: API Gateway with custom security header
  origin {
    domain_name = replace(replace(replace(var.api_endpoint, "https://", ""), "/dev", ""), "/prod", "")
    origin_id   = "API-Gateway"
    origin_path = "" # No prefix - frontend includes /prod or /dev in path

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    # Add secret header to all API requests
    custom_header {
      name  = "X-Origin-Verify"
      value = var.cloudfront_secret
    }
  }

  # Default cache behavior
  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${var.static_bucket_id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy      = "redirect-to-https"
    response_headers_policy_id  = aws_cloudfront_response_headers_policy.security_headers.id
    min_ttl                     = 0
    default_ttl                 = 3600  # 1 hour
    max_ttl                     = 86400 # 24 hours
    compress                    = true
  }

  # Cache behavior for HTML files (lower TTL)
  ordered_cache_behavior {
    path_pattern     = "*.html"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${var.static_bucket_id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy     = "redirect-to-https"
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
    min_ttl                    = 0
    default_ttl                = 300  # 5 minutes
    max_ttl                    = 3600 # 1 hour
    compress                   = true
  }

  # Cache behavior for static assets (higher TTL)
  ordered_cache_behavior {
    path_pattern     = "/assets/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${var.static_bucket_id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy     = "redirect-to-https"
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
    min_ttl                    = 0
    default_ttl                = 86400    # 24 hours
    max_ttl                    = 31536000 # 1 year
    compress                   = true
  }

  # Cache behavior for API calls - dev environment (proxied to API Gateway with security header)
  ordered_cache_behavior {
    path_pattern     = "/dev/*"
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "API-Gateway"

    forwarded_values {
      query_string = true
      headers      = ["Accept", "Content-Type", "Authorization"]

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy     = "redirect-to-https"
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
    min_ttl                    = 0
    default_ttl                = 0 # Don't cache API responses
    max_ttl                    = 0
    compress                   = true
  }

  # Cache behavior for API calls - prod environment (proxied to API Gateway with security header)
  ordered_cache_behavior {
    path_pattern     = "/prod/*"
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "API-Gateway"

    forwarded_values {
      query_string = true
      headers      = ["Accept", "Content-Type", "Authorization"]

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy     = "redirect-to-https"
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
    min_ttl                    = 0
    default_ttl                = 0 # Don't cache API responses
    max_ttl                    = 0
    compress                   = true
  }

  # Custom error responses (SPA routing)
  custom_error_response {
    error_code            = 404
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 300
  }

  # Note: Removed 403 custom_error_response - it was catching API Gateway 403 errors
  # and replacing them with index.html. S3 403 errors for non-existent paths should
  # not occur since we have a proper default_root_object and 404 handling.

  # Restrictions
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  # SSL/TLS certificate
  viewer_certificate {
    cloudfront_default_certificate = var.custom_domain == "" ? true : false
    acm_certificate_arn            = var.custom_domain != "" ? var.acm_certificate_arn : null
    ssl_support_method             = var.custom_domain != "" ? "sni-only" : null
    minimum_protocol_version       = "TLSv1.2_2021"
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-frontend"
  })
}
