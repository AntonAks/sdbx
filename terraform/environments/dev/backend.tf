# Terraform State Backend Configuration
# Run scripts/bootstrap-terraform-backend.sh first to create these resources
# Bucket name is set dynamically during terraform init to avoid committing account ID

terraform {
  backend "s3" {
    # bucket is set via -backend-config during terraform init
    key            = "environments/dev/terraform.tfstate"
    region         = "eu-central-1"
    encrypt        = true
    dynamodb_table = "sdbx-terraform-locks"
  }
}
