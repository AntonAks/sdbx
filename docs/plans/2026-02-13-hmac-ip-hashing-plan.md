# HMAC + Salt for Secure IP Hashing — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace plain SHA-256 IP hashing with HMAC-SHA256 using a secret salt from AWS Parameter Store, fixing rainbow table and correlation vulnerabilities.

**Architecture:** Add three functions to `backend/shared/security.py` (SSM fetch with LRU cache, salt getter, HMAC hasher). Update the two Lambda handlers that hash IPs. Add Terraform IAM permissions for SSM + KMS on those two Lambdas. Create a one-time salt init script.

**Tech Stack:** Python 3.12 (hmac, hashlib, functools.lru_cache), boto3 SSM client, Terraform, Bash

---

## Task 1: Add HMAC hashing functions to security module

**Files:**
- Modify: `backend/shared/security.py` (append after line 206)
- Test: `backend/tests/test_security.py` (append after line 231)

**Step 1: Write the failing tests**

Add to `backend/tests/test_security.py`:

```python
from unittest.mock import patch, MagicMock
from shared.security import hash_ip_secure, get_ip_hash_salt, _get_ssm_parameter


class TestIPHashWithParameterStore:
    """Test HMAC-SHA256 IP hashing with Parameter Store salt."""

    def setup_method(self):
        """Clear caches between tests."""
        _get_ssm_parameter.cache_clear()
        # Reset module-level cache
        import shared.security
        shared.security._ip_hash_salt_cache = None

    @patch('shared.security.boto3.client')
    def test_get_ssm_parameter_success(self, mock_boto_client, monkeypatch):
        """Should retrieve parameter from SSM."""
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.return_value = {
            'Parameter': {'Value': 'test-salt-value'}
        }
        mock_boto_client.return_value = mock_ssm

        result = _get_ssm_parameter('/sdbx/dev/ip-hash-salt')

        assert result == 'test-salt-value'
        mock_ssm.get_parameter.assert_called_once_with(
            Name='/sdbx/dev/ip-hash-salt',
            WithDecryption=True
        )

    @patch('shared.security.boto3.client')
    def test_get_ssm_parameter_caching(self, mock_boto_client):
        """Should only call SSM once due to LRU cache."""
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.return_value = {
            'Parameter': {'Value': 'cached-salt'}
        }
        mock_boto_client.return_value = mock_ssm

        result1 = _get_ssm_parameter('/sdbx/dev/ip-hash-salt')
        result2 = _get_ssm_parameter('/sdbx/dev/ip-hash-salt')

        assert result1 == result2 == 'cached-salt'
        assert mock_ssm.get_parameter.call_count == 1

    @patch('shared.security.boto3.client')
    def test_hash_ip_secure_with_parameter_store(self, mock_boto_client, monkeypatch):
        """Should produce valid HMAC-SHA256 hash."""
        monkeypatch.setenv('IP_HASH_SALT_PARAM', '/sdbx/dev/ip-hash-salt')
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.return_value = {
            'Parameter': {'Value': 'test-salt'}
        }
        mock_boto_client.return_value = mock_ssm

        result = hash_ip_secure('192.168.1.1')

        # Should be 64-char hex string (SHA-256 output)
        assert len(result) == 64
        assert all(c in '0123456789abcdef' for c in result)

    @patch('shared.security.boto3.client')
    def test_hash_ip_secure_different_ips_different_hashes(self, mock_boto_client, monkeypatch):
        """Different IPs should produce different hashes."""
        monkeypatch.setenv('IP_HASH_SALT_PARAM', '/sdbx/dev/ip-hash-salt')
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.return_value = {
            'Parameter': {'Value': 'test-salt'}
        }
        mock_boto_client.return_value = mock_ssm

        hash1 = hash_ip_secure('192.168.1.1')
        hash2 = hash_ip_secure('10.0.0.1')

        assert hash1 != hash2

    def test_get_ip_hash_salt_no_param_name(self, monkeypatch):
        """Should raise error if IP_HASH_SALT_PARAM env var not set."""
        monkeypatch.delenv('IP_HASH_SALT_PARAM', raising=False)

        with pytest.raises(ValueError, match="IP_HASH_SALT_PARAM"):
            get_ip_hash_salt()

    @patch('shared.security.boto3.client')
    def test_hash_ip_secure_parameter_not_found(self, mock_boto_client, monkeypatch):
        """Should raise error if parameter doesn't exist in SSM."""
        monkeypatch.setenv('IP_HASH_SALT_PARAM', '/sdbx/dev/ip-hash-salt')
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.side_effect = Exception("ParameterNotFound")
        mock_boto_client.return_value = mock_ssm

        with pytest.raises(Exception):
            hash_ip_secure('192.168.1.1')
```

**Step 2: Run tests to verify they fail**

Run: `cd backend && . venv/bin/activate && pytest tests/test_security.py::TestIPHashWithParameterStore -v`
Expected: FAIL — `ImportError: cannot import name 'hash_ip_secure'`

**Step 3: Write the implementation**

Append to `backend/shared/security.py`:

```python
import hashlib
import hmac
from functools import lru_cache

import boto3

# Module-level cache for IP hash salt
_ip_hash_salt_cache = None


@lru_cache(maxsize=1)
def _get_ssm_parameter(param_name: str) -> str:
    """
    Retrieve a parameter from AWS Systems Manager Parameter Store.

    Uses LRU cache so only one API call per Lambda lifetime.

    Args:
        param_name: Full parameter name (e.g., /sdbx/dev/ip-hash-salt)

    Returns:
        Parameter value string
    """
    ssm_client = boto3.client('ssm')
    response = ssm_client.get_parameter(
        Name=param_name,
        WithDecryption=True
    )
    return response['Parameter']['Value']


def get_ip_hash_salt() -> str:
    """
    Get the IP hash salt from Parameter Store.

    Caches the salt in a module-level variable for performance.

    Returns:
        Salt string for HMAC hashing

    Raises:
        ValueError: If IP_HASH_SALT_PARAM env var is not set
    """
    global _ip_hash_salt_cache
    if _ip_hash_salt_cache is not None:
        return _ip_hash_salt_cache

    param_name = os.environ.get('IP_HASH_SALT_PARAM')
    if not param_name:
        raise ValueError("IP_HASH_SALT_PARAM environment variable is not set")

    _ip_hash_salt_cache = _get_ssm_parameter(param_name)
    return _ip_hash_salt_cache


def hash_ip_secure(ip: str) -> str:
    """
    Hash an IP address using HMAC-SHA256 with a secret salt.

    Args:
        ip: IP address string to hash

    Returns:
        64-character hex string (HMAC-SHA256 digest)
    """
    salt = get_ip_hash_salt()
    return hmac.new(salt.encode(), ip.encode(), hashlib.sha256).hexdigest()
```

**Step 4: Run tests to verify they pass**

Run: `cd backend && . venv/bin/activate && pytest tests/test_security.py::TestIPHashWithParameterStore -v`
Expected: 6 passed

**Step 5: Run full test suite to check for regressions**

Run: `cd backend && . venv/bin/activate && pytest tests/ -v --tb=short`
Expected: All 226+ tests pass

**Step 6: Commit**

```bash
git add backend/shared/security.py backend/tests/test_security.py
git commit -m "feat: add HMAC-SHA256 IP hashing with Parameter Store salt

Adds hash_ip_secure(), get_ip_hash_salt(), and _get_ssm_parameter() to
security module. Salt is fetched from SSM Parameter Store and cached in
Lambda memory. Includes 6 unit tests with mocked boto3."
```

---

## Task 2: Update Lambda handlers to use HMAC hashing

**Files:**
- Modify: `backend/lambdas/upload_init/handler.py:2,136`
- Modify: `backend/lambdas/pin_upload_init/handler.py:2,106`

**Step 1: Update `upload_init/handler.py`**

Remove `import hashlib` (line 2).

Add to imports (after `from shared.security import require_cloudfront_and_recaptcha`):
```python
from shared.security import hash_ip_secure, require_cloudfront_and_recaptcha
```
(Merge into the existing import line.)

Replace line 136:
```python
ip_hash = hashlib.sha256(source_ip.encode()).hexdigest()
```
With:
```python
ip_hash = hash_ip_secure(source_ip)
```

**Step 2: Update `pin_upload_init/handler.py`**

Remove `import hashlib` (line 2).

Add to imports (after `from shared.security import require_cloudfront_and_recaptcha`):
```python
from shared.security import hash_ip_secure, require_cloudfront_and_recaptcha
```
(Merge into the existing import line.)

Replace line 106:
```python
ip_hash = hashlib.sha256(source_ip.encode()).hexdigest()
```
With:
```python
ip_hash = hash_ip_secure(source_ip)
```

**Step 3: Run full backend tests**

Run: `cd backend && . venv/bin/activate && pytest tests/ -v --tb=short`
Expected: All tests pass

**Step 4: Commit**

```bash
git add backend/lambdas/upload_init/handler.py backend/lambdas/pin_upload_init/handler.py
git commit -m "feat: switch upload handlers to HMAC-SHA256 IP hashing

Replace hashlib.sha256() with hash_ip_secure() in upload_init and
pin_upload_init handlers. Removes plain SHA-256 rainbow table vulnerability."
```

---

## Task 3: Update Terraform — add SSM/KMS permissions

**Files:**
- Modify: `terraform/modules/api/main.tf:280-319,522-556`

**Step 1: Add data sources**

Add after line 11 (after the `aws_api_gateway_rest_api` resource opening tag area — actually add at the very top of the file, before line 1):

```hcl
# Data sources for constructing ARNs
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
```

**Step 2: Update `lambda_upload_init` module (lines 280-319)**

Add to `environment_variables` block:
```hcl
IP_HASH_SALT_PARAM = "/${var.project_name}/${var.environment}/ip-hash-salt"
```

Add two new IAM policy statements:
```hcl
{
  effect = "Allow"
  actions = [
    "ssm:GetParameter"
  ]
  resources = ["arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${var.project_name}/${var.environment}/ip-hash-salt"]
},
{
  effect = "Allow"
  actions = [
    "kms:Decrypt"
  ]
  resources = ["*"]
}
```

**Step 3: Update `lambda_pin_upload_init` module (lines 522-556)**

Same changes as Step 2: add `IP_HASH_SALT_PARAM` env var and two IAM policy statements.

**Step 4: Validate Terraform**

Run: `cd terraform/environments/dev && terraform validate` (if initialized)
Or just visually verify HCL syntax is correct.

**Step 5: Commit**

```bash
git add terraform/modules/api/main.tf
git commit -m "feat: add SSM and KMS permissions for IP hash salt

Add IP_HASH_SALT_PARAM env var and ssm:GetParameter + kms:Decrypt IAM
permissions to upload_init and pin_upload_init Lambda modules."
```

---

## Task 4: Create salt initialization script

**Files:**
- Create: `scripts/init-ip-hash-salt.sh`

**Step 1: Write the script**

```bash
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
```

**Step 2: Make executable**

Run: `chmod +x scripts/init-ip-hash-salt.sh`

**Step 3: Commit**

```bash
git add scripts/init-ip-hash-salt.sh
git commit -m "feat: add salt initialization script for Parameter Store

One-time script to generate and store HMAC salt as SecureString in
AWS Systems Manager Parameter Store. Prevents accidental overwrites."
```

---

## Task 5: Add Makefile targets

**Files:**
- Modify: `Makefile` (append after line 225)

**Step 1: Add salt management targets**

```makefile
init-salt-dev: ## Initialize IP hash salt for dev environment
	@./scripts/init-ip-hash-salt.sh sdbx dev

init-salt-prod: ## Initialize IP hash salt for prod environment
	@./scripts/init-ip-hash-salt.sh sdbx prod

check-salt-dev: ## Check if IP hash salt exists in dev Parameter Store
	@aws ssm get-parameter --name "/sdbx/dev/ip-hash-salt" --query "Parameter.{Name:Name,Type:Type,LastModified:LastModifiedDate}" --output table 2>/dev/null || echo "Salt not found. Run: make init-salt-dev"

check-salt-prod: ## Check if IP hash salt exists in prod Parameter Store
	@aws ssm get-parameter --name "/sdbx/prod/ip-hash-salt" --query "Parameter.{Name:Name,Type:Type,LastModified:LastModifiedDate}" --output table 2>/dev/null || echo "Salt not found. Run: make init-salt-prod"
```

**Step 2: Commit**

```bash
git add Makefile
git commit -m "feat: add Makefile targets for salt management

Adds init-salt-dev, init-salt-prod, check-salt-dev, check-salt-prod
targets for managing IP hash salt in Parameter Store."
```

---

## Task 6: Update deploy script with salt check

**Files:**
- Modify: `scripts/deploy-dev.sh:28-29`

**Step 1: Add salt check**

Insert after line 29 (`terraform init` block) and before line 30 (the blank line before "Validate"):

```bash

# Check if IP hash salt exists in Parameter Store
echo "Checking IP hash salt in Parameter Store..."
PARAM_NAME="/sdbx/dev/ip-hash-salt"
if aws ssm get-parameter --name "${PARAM_NAME}" --query "Parameter.Name" --output text 2>/dev/null; then
    echo "  Salt found in Parameter Store"
else
    echo ""
    echo "IP hash salt not found in Parameter Store."
    echo "This is required for secure IP hashing."
    echo ""
    read -p "Initialize salt now? (yes/no): " init_salt
    if [ "$init_salt" = "yes" ]; then
        "$(dirname "$0")/init-ip-hash-salt.sh" sdbx dev
    else
        echo "Please run: make init-salt-dev"
        echo "Then re-run this deployment."
        exit 1
    fi
fi
echo ""
```

**Step 2: Commit**

```bash
git add scripts/deploy-dev.sh
git commit -m "feat: add salt check to dev deploy script

Checks if IP hash salt exists in Parameter Store before deploying.
Prompts to initialize if missing."
```

---

## Task 7: Update README

**Files:**
- Modify: `README.md:152-153,232`

**Step 1: Update security section**

In the "What We DO Store" section (line 152), change:
```
- ✅ IP address hash (SHA-256, for abuse prevention only)
```
To:
```
- ✅ IP address hash (HMAC-SHA256 with secret salt, for abuse prevention only)
```

In the "Privacy Policy" section (line 377), change:
```
- IP address hash (SHA-256, for abuse prevention only, not linked to files)
```
To:
```
- IP address hash (HMAC-SHA256 with secret salt, for abuse prevention only, not linked to files)
```

**Step 2: Add Salt Management section**

Insert after the Quick Start section (after line 232, before "### Local Frontend Development"):

```markdown
### Salt Management

IP addresses are hashed using HMAC-SHA256 with a secret salt stored in AWS Systems Manager Parameter Store. This prevents rainbow table attacks against the IP hash database.

```bash
# Initialize salt (once per environment)
make init-salt-dev
make init-salt-prod

# Check if salt exists
make check-salt-dev
make check-salt-prod
```

The salt is:
- KMS encrypted in Parameter Store (never in Terraform state or code)
- Cached in Lambda memory (one API call per cold start)
- Audited via CloudTrail
- Free (within AWS free tier)
```

**Step 3: Commit**

```bash
git add README.md
git commit -m "docs: update README with HMAC-SHA256 and salt management

Updates IP hash references from SHA-256 to HMAC-SHA256. Adds Salt
Management section with setup instructions."
```

---

## Task 8: Final verification

**Step 1: Run full backend test suite**

Run: `cd backend && . venv/bin/activate && pytest tests/ -v --tb=short`
Expected: All tests pass (226+ existing + 6 new = 232+)

**Step 2: Run frontend tests**

Run: `cd frontend && node --test tests/*.test.js`
Expected: All 84 tests pass (no changes to frontend)

**Step 3: Review all changes**

Run: `git log --oneline -7` to see all commits.
Run: `git diff main --stat` to see all changed files.

Verify file list matches plan:
- `backend/shared/security.py` (modified)
- `backend/tests/test_security.py` (modified)
- `backend/lambdas/upload_init/handler.py` (modified)
- `backend/lambdas/pin_upload_init/handler.py` (modified)
- `terraform/modules/api/main.tf` (modified)
- `scripts/init-ip-hash-salt.sh` (new)
- `Makefile` (modified)
- `scripts/deploy-dev.sh` (modified)
- `README.md` (modified)
