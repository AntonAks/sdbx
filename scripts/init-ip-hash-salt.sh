#!/bin/bash
set -e

# sdbx - Initialize IP Hash Salt in AWS Parameter Store
# Usage: ./scripts/init-ip-hash-salt.sh <project> <environment>
# Example: ./scripts/init-ip-hash-salt.sh sdbx dev

PROJECT="${1:-sdbx}"
ENV="${2:-dev}"
PARAM_NAME="/${PROJECT}/${ENV}/ip-hash-salt"

echo "Initializing IP hash salt for ${PROJECT}/${ENV}..."
echo "  Parameter: ${PARAM_NAME}"
echo ""

# Check if parameter already exists
if aws ssm get-parameter --name "${PARAM_NAME}" --query "Parameter.Name" --output text 2>/dev/null; then
    echo "Parameter ${PARAM_NAME} already exists."
    echo "To overwrite, delete it first:"
    echo "  aws ssm delete-parameter --name ${PARAM_NAME}"
    exit 1
fi

# Generate random salt (64 characters, base64 encoded)
SALT=$(openssl rand -base64 48)

# Store in Parameter Store as SecureString
aws ssm put-parameter \
    --name "${PARAM_NAME}" \
    --type "SecureString" \
    --value "${SALT}" \
    --description "HMAC salt for IP address hashing in sdbx ${ENV}" \
    --tags "Key=Project,Value=${PROJECT}" "Key=Environment,Value=${ENV}" "Key=ManagedBy,Value=Manual"

echo ""
echo "Salt initialized successfully."
echo "  Parameter: ${PARAM_NAME}"
echo "  Type: SecureString (KMS encrypted)"
echo ""
echo "Next steps:"
echo "  1. Deploy infrastructure: make deploy-${ENV}"
echo "  2. Verify: aws ssm get-parameter --name ${PARAM_NAME} --with-decryption --query Parameter.Value"
