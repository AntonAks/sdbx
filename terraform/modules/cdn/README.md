# CDN Module

This module creates a CloudFront distribution for serving the sdbx frontend.

## Resources Created

- **CloudFront Distribution**: CDN for static frontend files
  - HTTPS only (redirect HTTP to HTTPS)
  - TLS 1.2+ minimum
  - Custom error pages for SPA routing
  - Optimized cache behaviors for different file types
  - Gzip compression enabled

- **Origin Access Identity**: Secure access to S3 bucket
- **S3 Bucket Policy**: Allows CloudFront to read static files

## Usage

```hcl
module "cdn" {
  source = "../../modules/cdn"

  project_name      = "sdbx"
  environment       = "dev"
  static_bucket_id  = module.storage.static_bucket_id
  static_bucket_arn = module.storage.static_bucket_arn
  api_domain        = module.api.api_invoke_url
  tags              = local.common_tags
}
```

## Custom Domain Setup

To use a custom domain:

1. Create ACM certificate in `us-east-1` region
2. Validate certificate
3. Pass certificate ARN and domain to module:

```hcl
module "cdn" {
  source = "../../modules/cdn"

  # ... other variables ...
  custom_domain       = "sdbx.example.com"
  acm_certificate_arn = "arn:aws:acm:us-east-1:..."
}
```

4. Create Route53 alias record pointing to CloudFront distribution

## Cache Behaviors

- **HTML files** (*.html): 5 min default, 1 hour max
- **Static assets** (/assets/*): 24 hours default, 1 year max
- **Other files**: 1 hour default, 24 hours max

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| project_name | Project name | string | - | yes |
| environment | Environment | string | - | yes |
| static_bucket_id | S3 bucket ID | string | - | yes |
| static_bucket_arn | S3 bucket ARN | string | - | yes |
| api_domain | API Gateway domain | string | - | yes |
| price_class | CloudFront price class | string | PriceClass_100 | no |
| custom_domain | Custom domain name | string | "" | no |
| acm_certificate_arn | ACM cert ARN | string | "" | no |

## Outputs

| Name | Description |
|------|-------------|
| cloudfront_distribution_id | Distribution ID |
| cloudfront_domain | Distribution domain name |
| cloudfront_arn | Distribution ARN |
