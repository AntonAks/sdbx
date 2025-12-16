#!/bin/bash
set -e

# sdbx - Destroy Dev Environment Only
# Safely destroys only the dev environment

echo "⚠️  WARNING: This will destroy the DEV environment!"
echo ""
read -p "Continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "❌ Aborted"
    exit 0
fi

echo ""
echo "🗑️  Destroying dev environment..."
echo ""

# Empty S3 buckets
echo "📦 Emptying S3 buckets..."
aws s3 rm s3://sdbx-dev-files --recursive 2>/dev/null || echo "  Files bucket already empty"
aws s3 rm s3://sdbx-dev-static --recursive 2>/dev/null || echo "  Static bucket already empty"
echo ""

# Destroy infrastructure
echo "💣 Running terraform destroy..."
cd terraform/environments/dev
terraform destroy

echo ""
echo "✅ Dev environment destroyed!"
echo ""
echo "To redeploy:"
echo "  ./scripts/deploy-dev.sh"
echo ""
