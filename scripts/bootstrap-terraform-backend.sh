#!/bin/bash
set -e

# sdbx - Bootstrap Terraform Backend
# Creates S3 bucket and DynamoDB table for Terraform state management
#
# NOTE: This only needs to be run ONCE per AWS account.
# The same backend resources are shared by both dev and prod environments.
# State files are separated by key: environments/dev/terraform.tfstate and environments/prod/terraform.tfstate

REGION="eu-central-1"
BUCKET_NAME="sdbx-terraform-state"
DYNAMODB_TABLE="sdbx-terraform-locks"

echo "🚀 Bootstrapping Terraform backend..."
echo "   (Shared by dev and prod environments)"
echo ""

# Check if AWS CLI is configured
if ! aws sts get-caller-identity &> /dev/null; then
    echo "❌ AWS CLI is not configured. Run 'aws configure' first."
    exit 1
fi

echo "✓ AWS credentials found"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "  Account ID: $ACCOUNT_ID"
echo ""

# Create S3 bucket
echo "📦 Creating S3 bucket: $BUCKET_NAME"
if aws s3api head-bucket --bucket "$BUCKET_NAME" 2>/dev/null; then
    echo "  ⚠️  Bucket already exists"
else
    aws s3api create-bucket \
        --bucket "$BUCKET_NAME" \
        --region "$REGION" \
        --create-bucket-configuration LocationConstraint="$REGION"
    echo "  ✓ Bucket created"
fi

# Enable versioning
echo "🔄 Enabling versioning..."
aws s3api put-bucket-versioning \
    --bucket "$BUCKET_NAME" \
    --versioning-configuration Status=Enabled
echo "  ✓ Versioning enabled"

# Enable encryption
echo "🔐 Enabling encryption..."
aws s3api put-bucket-encryption \
    --bucket "$BUCKET_NAME" \
    --server-side-encryption-configuration '{
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256"
            }
        }]
    }'
echo "  ✓ Encryption enabled"

# Block public access
echo "🔒 Blocking public access..."
aws s3api put-public-access-block \
    --bucket "$BUCKET_NAME" \
    --public-access-block-configuration \
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
echo "  ✓ Public access blocked"

# Create DynamoDB table
echo ""
echo "📊 Creating DynamoDB table: $DYNAMODB_TABLE"
if aws dynamodb describe-table --table-name "$DYNAMODB_TABLE" --region "$REGION" &>/dev/null; then
    echo "  ⚠️  Table already exists"
else
    aws dynamodb create-table \
        --table-name "$DYNAMODB_TABLE" \
        --attribute-definitions AttributeName=LockID,AttributeType=S \
        --key-schema AttributeName=LockID,KeyType=HASH \
        --billing-mode PAY_PER_REQUEST \
        --region "$REGION" \
        --tags Key=Project,Value=sdbx Key=ManagedBy,Value=Manual

    echo "  ⏳ Waiting for table to be active..."
    aws dynamodb wait table-exists --table-name "$DYNAMODB_TABLE" --region "$REGION"
    echo "  ✓ Table created"
fi

echo ""
echo "✅ Terraform backend is ready!"
echo ""
echo "📌 Important: This backend is shared by both dev and prod environments."
echo "   State files are isolated by key path:"
echo "   - Dev:  environments/dev/terraform.tfstate"
echo "   - Prod: environments/prod/terraform.tfstate"
echo ""
echo "Next steps:"
echo "  DEV Environment:"
echo "    1. cd terraform/environments/dev"
echo "    2. cp terraform.tfvars.example terraform.tfvars"
echo "    3. terraform init"
echo "    4. terraform plan"
echo "    5. terraform apply"
echo ""
echo "  PROD Environment (when ready):"
echo "    1. cd terraform/environments/prod"
echo "    2. cp terraform.tfvars.example terraform.tfvars"
echo "    3. terraform init"
echo "    4. terraform plan"
echo "    5. terraform apply"
echo ""
