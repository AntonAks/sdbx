#!/bin/bash
set -e

# sdbx - Destroy Prod Environment Only
# Safely destroys only the prod environment

echo "⚠️  WARNING: This will destroy the PRODUCTION environment!"
echo ""
read -p "Continue? Type 'prod' to confirm: " confirm

if [ "$confirm" != "prod" ]; then
    echo "❌ Aborted"
    exit 0
fi

echo ""
echo "🗑️  Destroying prod environment..."
echo ""

# Empty S3 buckets
echo "📦 Emptying S3 buckets..."
aws s3 rm s3://sdbx-prod-files --recursive 2>/dev/null || echo "  Files bucket already empty"
aws s3 rm s3://sdbx-prod-static --recursive 2>/dev/null || echo "  Static bucket already empty"
echo ""

# Destroy infrastructure
echo "💣 Running terraform destroy..."
cd terraform/environments/prod
terraform destroy

echo ""
echo "✅ Prod environment destroyed!"
echo ""
echo "To redeploy:"
echo "  cd terraform/environments/prod"
echo "  terraform apply"
echo ""
