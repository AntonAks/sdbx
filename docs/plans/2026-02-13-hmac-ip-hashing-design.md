# Design: HMAC + Salt for Secure IP Hashing

**Issue**: #6
**Date**: 2026-02-13
**Status**: Approved

## Problem

IP addresses are hashed with plain SHA-256. The IPv4 space (~4.3B addresses) is small enough to precompute all hashes (rainbow table attack). Salt planned for Terraform state would be exposed to anyone with state access.

## Solution

Replace plain SHA-256 with HMAC-SHA256 using a secret salt stored in AWS Systems Manager Parameter Store.

## Scope

Only 2 Lambdas currently hash IPs (`upload_init`, `pin_upload_init`). Changes are scoped to these. Follows least-privilege principle.

## Components

### 1. Security Module (`backend/shared/security.py`)

Three new functions:
- `_get_ssm_parameter(param_name)` - boto3 SSM call with `@lru_cache(maxsize=1)`
- `get_ip_hash_salt()` - reads `IP_HASH_SALT_PARAM` env var, fetches from SSM
- `hash_ip_secure(ip)` - HMAC-SHA256 with cached salt

### 2. Handler Updates

- `backend/lambdas/upload_init/handler.py` - use `hash_ip_secure()` instead of `hashlib.sha256()`
- `backend/lambdas/pin_upload_init/handler.py` - same

### 3. Terraform (`terraform/modules/api/main.tf`)

For `lambda_upload_init` and `lambda_pin_upload_init`:
- Add `IP_HASH_SALT_PARAM` env var
- Add `ssm:GetParameter` IAM permission (scoped to parameter ARN)
- Add `kms:Decrypt` IAM permission
- Add `data.aws_region.current` and `data.aws_caller_identity.current`

### 4. Salt Init Script (`scripts/init-ip-hash-salt.sh`)

- Check if parameter exists (prevent overwrite)
- Generate 64-char salt via `openssl rand -base64 48`
- Store as SecureString at `/${project}/${env}/ip-hash-salt`

### 5. Makefile Targets

`init-salt-dev`, `init-salt-prod`, `check-salt-dev`, `check-salt-prod`

### 6. Deploy Script (`scripts/deploy-dev.sh`)

Check salt exists in Parameter Store after Terraform init, prompt to initialize if missing.

### 7. Unit Tests (`backend/tests/test_security.py`)

6 tests with mocked boto3: SSM retrieval, caching, HMAC correctness, different IPs diverge, missing env var, missing parameter.

### 8. README Update

Security section + Salt Management section.

## Files

**New:**
- `scripts/init-ip-hash-salt.sh`

**Modified:**
- `backend/shared/security.py`
- `backend/lambdas/upload_init/handler.py`
- `backend/lambdas/pin_upload_init/handler.py`
- `backend/tests/test_security.py`
- `terraform/modules/api/main.tf`
- `terraform/modules/api/variables.tf`
- `Makefile`
- `scripts/deploy-dev.sh`
- `README.md`
