# Storage Module

This module creates the storage infrastructure for sdbx:

## Resources Created

- **S3 Bucket (Files)**: Stores encrypted file blobs
  - Server-side encryption (AES256)
  - Public access blocked
  - Lifecycle rule to expire files after 7 days
  - Versioning enabled
  - CORS configured for direct uploads

- **S3 Bucket (Static)**: Hosts frontend static files
  - Server-side encryption (AES256)
  - Public access blocked (accessed via CloudFront)

- **DynamoDB Table**: Stores file metadata
  - On-demand billing
  - TTL enabled on `expires_at` attribute
  - Point-in-time recovery enabled

## Usage

```hcl
module "storage" {
  source = "../../modules/storage"

  project_name = "sdbx"
  environment  = "dev"
  tags         = local.common_tags
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| project_name | Project name for resource naming | string | - | yes |
| environment | Environment (dev or prod) | string | - | yes |
| tags | Common tags for all resources | map(string) | {} | no |
| files_bucket_name | Custom name for files bucket | string | "" | no |
| static_bucket_name | Custom name for static bucket | string | "" | no |
| lifecycle_expiration_days | Days before files expire | number | 7 | no |

## Outputs

| Name | Description |
|------|-------------|
| files_bucket_name | Name of the encrypted files S3 bucket |
| files_bucket_arn | ARN of the encrypted files S3 bucket |
| static_bucket_name | Name of the static frontend S3 bucket |
| static_bucket_arn | ARN of the static frontend S3 bucket |
| table_name | Name of the DynamoDB table |
| table_arn | ARN of the DynamoDB table |
