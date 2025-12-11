# Terraform State Backend Configuration
# This file should be copied to each environment directory

# S3 backend for storing Terraform state
# Uncomment and configure after creating the state bucket manually

# terraform {
#   backend "s3" {
#     bucket         = "securedrop-terraform-state"
#     key            = "environments/${var.environment}/terraform.tfstate"
#     region         = "eu-central-1"
#     encrypt        = true
#     dynamodb_table = "securedrop-terraform-locks"
#   }
# }

# To create the state backend resources manually:
#
# aws s3api create-bucket \
#   --bucket securedrop-terraform-state \
#   --region eu-central-1 \
#   --create-bucket-configuration LocationConstraint=eu-central-1
#
# aws s3api put-bucket-versioning \
#   --bucket securedrop-terraform-state \
#   --versioning-configuration Status=Enabled
#
# aws s3api put-bucket-encryption \
#   --bucket securedrop-terraform-state \
#   --server-side-encryption-configuration '{
#     "Rules": [{
#       "ApplyServerSideEncryptionByDefault": {
#         "SSEAlgorithm": "AES256"
#       }
#     }]
#   }'
#
# aws dynamodb create-table \
#   --table-name securedrop-terraform-locks \
#   --attribute-definitions AttributeName=LockID,AttributeType=S \
#   --key-schema AttributeName=LockID,KeyType=HASH \
#   --billing-mode PAY_PER_REQUEST \
#   --region eu-central-1
