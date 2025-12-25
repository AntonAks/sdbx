#!/bin/bash
set -e

# Build Lambda deployment packages
# This script packages all Lambda functions with their shared dependencies

echo "🔨 Building Lambda deployment packages..."

# Define paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_ROOT/backend"
BUILDS_DIR="$PROJECT_ROOT/terraform/modules/api/modules/lambda/builds"

# Lambda functions to build
# Format: "folder_name:function_name"
LAMBDAS=(
  "upload_init:upload-init"
  "get_metadata:get-metadata"
  "download:download"
  "cleanup:cleanup"
  "report_abuse:report-abuse"
)

# Environment (dev or prod)
ENVIRONMENT="${1:-dev}"

# Create builds directory
mkdir -p "$BUILDS_DIR"

# Build each Lambda function
for lambda_entry in "${LAMBDAS[@]}"; do
  # Split folder_name:function_name
  IFS=':' read -r folder_name function_name <<< "$lambda_entry"

  echo "  📦 Building $function_name..."

  LAMBDA_DIR="$BACKEND_DIR/lambdas/$folder_name"
  TEMP_DIR="$BUILDS_DIR/${ENVIRONMENT}_${function_name}_temp"
  ZIP_FILE="$BUILDS_DIR/sdbx-${ENVIRONMENT}-${function_name}.zip"

  # Clean up any existing temp directory
  rm -rf "$TEMP_DIR"
  mkdir -p "$TEMP_DIR"

  # Copy handler
  cp "$LAMBDA_DIR/handler.py" "$TEMP_DIR/"

  # Copy shared modules
  cp -r "$BACKEND_DIR/shared" "$TEMP_DIR/"

  # Install dependencies if requirements.txt exists
  if [ -f "$LAMBDA_DIR/requirements.txt" ]; then
    echo "    📥 Installing dependencies from requirements.txt..."
    pip install -q -r "$LAMBDA_DIR/requirements.txt" -t "$TEMP_DIR/"
  fi

  # Create zip file
  cd "$TEMP_DIR"
  zip -q -r "$ZIP_FILE" . -x "*.pyc" -x "__pycache__/*"
  cd - > /dev/null

  # Clean up temp directory
  rm -rf "$TEMP_DIR"

  # Get zip file size
  SIZE=$(du -h "$ZIP_FILE" | cut -f1)
  echo "    ✅ Built $ZIP_FILE ($SIZE)"
done

echo ""
echo "✅ All Lambda packages built successfully!"
echo ""