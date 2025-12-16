#!/bin/bash
set -e

# sdbx - Destroy All Infrastructure
# Safely destroys all AWS resources created by Terraform

REGION="eu-central-1"

echo "⚠️  WARNING: This will DESTROY all sdbx infrastructure!"
echo ""
echo "This script will:"
echo "  1. Empty all S3 buckets"
echo "  2. Destroy dev environment"
echo "  3. Destroy prod environment (if exists)"
echo "  4. Optionally destroy Terraform backend"
echo ""
echo "All data will be PERMANENTLY DELETED!"
echo ""
read -p "Are you absolutely sure? Type 'destroy' to continue: " confirm

if [ "$confirm" != "destroy" ]; then
    echo "❌ Aborted"
    exit 0
fi

echo ""
echo "🗑️  Starting destruction process..."
echo ""

# Function to check if environment exists
env_exists() {
    local env=$1
    if [ -d "terraform/environments/$env" ] && [ -f "terraform/environments/$env/.terraform/terraform.tfstate" ]; then
        return 0
    else
        return 1
    fi
}

# Function to empty S3 bucket
empty_bucket() {
    local bucket=$1
    echo "  Emptying bucket: $bucket"

    if aws s3 ls "s3://$bucket" 2>/dev/null; then
        aws s3 rm "s3://$bucket" --recursive || echo "    ⚠️  Bucket may not exist or is already empty"
        echo "    ✓ Bucket emptied"
    else
        echo "    ⚠️  Bucket doesn't exist, skipping"
    fi
}

# Step 1: Empty S3 buckets
echo "📦 Step 1: Emptying S3 buckets..."
empty_bucket "sdbx-dev-files"
empty_bucket "sdbx-dev-static"
empty_bucket "sdbx-prod-files"
empty_bucket "sdbx-prod-static"
echo ""

# Step 2: Destroy dev environment
echo "💣 Step 2: Destroying dev environment..."
if [ -d "terraform/environments/dev" ]; then
    cd terraform/environments/dev

    if [ -f ".terraform/terraform.tfstate" ]; then
        echo "  Running terraform destroy..."
        terraform destroy -auto-approve
        echo "  ✓ Dev environment destroyed"
    else
        echo "  ⚠️  Dev environment not initialized, skipping"
    fi

    cd ../../../
else
    echo "  ⚠️  Dev environment directory not found, skipping"
fi
echo ""

# Step 3: Destroy prod environment
echo "💣 Step 3: Destroying prod environment..."
if [ -d "terraform/environments/prod" ]; then
    cd terraform/environments/prod

    if [ -f ".terraform/terraform.tfstate" ]; then
        echo "  Running terraform destroy..."
        terraform destroy -auto-approve
        echo "  ✓ Prod environment destroyed"
    else
        echo "  ⚠️  Prod environment not initialized, skipping"
    fi

    cd ../../../
else
    echo "  ⚠️  Prod environment directory not found, skipping"
fi
echo ""

# Step 4: Ask about destroying backend
echo "🗄️  Step 4: Terraform Backend"
echo ""
echo "Do you want to destroy the Terraform backend?"
echo "  - S3 bucket: sdbx-terraform-state"
echo "  - DynamoDB table: sdbx-terraform-locks"
echo ""
echo "⚠️  WARNING: This will delete all Terraform state files!"
echo "Only do this if you're completely done with sdbx."
echo ""
read -p "Destroy backend? (yes/no): " destroy_backend

if [ "$destroy_backend" = "yes" ]; then
    echo ""
    echo "  Destroying Terraform backend..."

    # Empty state bucket
    echo "  Emptying state bucket..."
    if aws s3 ls "s3://sdbx-terraform-state" 2>/dev/null; then
        aws s3 rm "s3://sdbx-terraform-state" --recursive
        echo "    ✓ State bucket emptied"
    fi

    # Delete state bucket
    echo "  Deleting state bucket..."
    if aws s3api head-bucket --bucket "sdbx-terraform-state" 2>/dev/null; then
        aws s3 rb "s3://sdbx-terraform-state" --force
        echo "    ✓ State bucket deleted"
    else
        echo "    ⚠️  State bucket doesn't exist"
    fi

    # Delete DynamoDB table
    echo "  Deleting lock table..."
    if aws dynamodb describe-table --table-name "sdbx-terraform-locks" --region "$REGION" 2>/dev/null; then
        aws dynamodb delete-table --table-name "sdbx-terraform-locks" --region "$REGION"
        echo "    ✓ Lock table deleted"
    else
        echo "    ⚠️  Lock table doesn't exist"
    fi

    echo "  ✓ Backend destroyed"
else
    echo "  ⏭️  Skipping backend destruction"
    echo "  Note: Terraform state is still preserved in S3"
fi

echo ""
echo "✅ Destruction complete!"
echo ""

# Summary
echo "📊 Summary:"
if [ "$destroy_backend" = "yes" ]; then
    echo "  ✓ All infrastructure destroyed"
    echo "  ✓ Terraform backend destroyed"
    echo "  ✓ All state files deleted"
    echo ""
    echo "To redeploy from scratch:"
    echo "  1. ./scripts/bootstrap-terraform-backend.sh"
    echo "  2. ./scripts/deploy-dev.sh"
else
    echo "  ✓ Dev and prod environments destroyed"
    echo "  ✓ Terraform backend preserved"
    echo ""
    echo "To redeploy:"
    echo "  ./scripts/deploy-dev.sh"
fi
echo ""
