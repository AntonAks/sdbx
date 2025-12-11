# Terraform State Backend Configuration
# Run scripts/bootstrap-terraform-backend.sh first to create these resources

terraform {
  backend "s3" {
    bucket         = "sdbx-terraform-state"
    key            = "environments/dev/terraform.tfstate"
    region         = "eu-central-1"
    encrypt        = true
    dynamodb_table = "sdbx-terraform-locks"
  }
}
