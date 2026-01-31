# CLAUDE.md - sdbx Project Context

> **Zero-Knowledge File Sharing Service**
> One-time download, end-to-end encrypted, privacy-first

## Project Overview

sdbx is a serverless file and text sharing service where:
- Files and text secrets are encrypted **client-side** before upload (AES-256-GCM)
- Encryption key stays in URL fragment — **never sent to server**
- **One-time mode**: Each file/text can be accessed **exactly once**, then deleted
- **Vault mode**: Password-protected content with **unlimited access** until expiry
- **PIN mode**: Share via 6-digit code + 4-character PIN (no long URLs needed)
- Text secrets (up to 1000 characters) stored in DynamoDB
- Files (up to 500MB) stored in S3
- No user accounts, no email, no tracking — true zero-knowledge

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ FRONTEND (S3 + CloudFront)                                  │
│ - Vanilla JS, no frameworks                                 │
│ - Web Crypto API for encryption                             │
│ - Tab UI: Files / Text / Vault (password-protected)        │
│ - Method selection: Share Link vs PIN Code                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ BACKEND (API Gateway + Lambda)                              │
│ - Python 3.12                                               │
│ - 9 Lambda functions                                        │
│ - DynamoDB for metadata + statistics + text secrets         │
│ - S3 for encrypted file blobs                               │
└─────────────────────────────────────────────────────────────┘
```

## Tech Stack

| Layer          | Technology              |
|----------------|-------------------------|
| Frontend       | Vanilla JS, HTML, CSS   |
| Encryption     | Web Crypto API          |
| CDN            | CloudFront              |
| Static Hosting | S3                      |
| API            | API Gateway (REST)      |
| Compute        | Lambda (Python 3.12)    |
| Database       | DynamoDB                |
| File Storage   | S3                      |
| IaC            | Terraform               |
| CI/CD          | GitHub Actions          |
| Region         | eu-central-1 (Frankfurt)|

## Project Structure

```
sdbx/
├── CLAUDE.md                 # This file
├── ROADMAP.md                # Development progress
├── README.md                 # Public documentation
│
├── terraform/
│   ├── environments/
│   │   ├── dev/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── terraform.tfvars
│   │   └── prod/
│   │       ├── main.tf
│   │       ├── variables.tf
│   │       └── terraform.tfvars
│   ├── modules/
│   │   ├── api/              # API Gateway + Lambda
│   │   ├── storage/          # S3 + DynamoDB
│   │   ├── cdn/              # CloudFront
│   │   └── monitoring/       # CloudWatch
│   └── shared/
│       └── backend.tf        # S3 state backend config
│
├── backend/
│   ├── lambdas/
│   │   ├── upload_init/
│   │   │   └── handler.py
│   │   ├── get_metadata/
│   │   │   └── handler.py
│   │   ├── get_stats/
│   │   │   └── handler.py
│   │   ├── download/
│   │   │   └── handler.py
│   │   ├── cleanup/
│   │   │   └── handler.py
│   │   ├── report_abuse/
│   │   │   └── handler.py
│   │   ├── pin_upload_init/
│   │   │   └── handler.py
│   │   ├── pin_initiate/
│   │   │   └── handler.py
│   │   ├── pin_verify/
│   │   │   └── handler.py
│   │   └── requirements.txt     # Shared dependencies
│   ├── shared/
│   │   ├── __init__.py
│   │   ├── dynamo.py         # DynamoDB helpers
│   │   ├── s3.py             # S3 helpers
│   │   ├── pin_utils.py      # PIN hashing/verification
│   │   └── validation.py     # Input validation
│   └── tests/
│       ├── test_upload.py
│       ├── test_download.py
│       └── conftest.py
│
├── frontend/
│   ├── index.html
│   ├── download.html
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   ├── crypto.js         # Encryption/decryption + PBKDF2
│   │   ├── upload.js         # File upload flow
│   │   ├── text-upload.js    # Text secret upload flow
│   │   ├── vault-upload.js   # Vault (password-protected) upload
│   │   ├── pin-upload.js     # PIN code upload flow
│   │   ├── download.js       # Download flow (files + text + vault)
│   │   ├── pin-download.js   # PIN code download flow
│   │   ├── utils.js          # Helpers
│   │   └── init.js           # Page initialization
│   └── assets/
│       └── favicon.ico
│
└── .github/
    └── workflows/
        ├── deploy-dev.yml
        └── deploy-prod.yml
```

## Key Flows

### File Upload Flow
1. User selects file + TTL (1h/12h/24h or custom 5min-7days)
2. **Frontend generates reCAPTCHA v3 token** (invisible, score-based)
3. Frontend generates random 256-bit key
4. Frontend encrypts file with AES-256-GCM
5. Frontend calls `POST /api/upload/init` with reCAPTCHA token → gets presigned S3 URL (no filename sent)
6. **Backend verifies reCAPTCHA token** (score must be >= 0.5)
7. Frontend uploads encrypted blob to S3
8. Frontend shows URL: `https://domain/download.html#{file_id}#{key}#{filename}`
9. User copies link manually

**Note**: The filename is stored client-side in the URL fragment only. The server never receives or stores filenames.

### Text Secret Upload Flow
1. User types text (max 1000 chars) + TTL (1h/12h/24h or custom 5min-7days)
2. **Frontend generates reCAPTCHA v3 token** (invisible, score-based)
3. Frontend generates random 256-bit key
4. Frontend encrypts text with AES-256-GCM
5. Frontend converts encrypted data to base64
6. Frontend calls `POST /api/upload/init` with `content_type: "text"` and base64 encrypted text
7. **Backend verifies reCAPTCHA token** (score must be >= 0.5)
8. Backend stores encrypted text directly in DynamoDB (no S3)
9. Frontend shows URL: `https://domain/download.html#{secret_id}#{key}`
10. User copies link manually

### Download Flow (CRITICAL: Atomic Marking)
1. User opens link
2. Frontend extracts `file_id`, `key`, and optional `filename` from URL fragment
3. Frontend calls `GET /api/files/{id}/metadata` → check availability (no reCAPTCHA needed for read-only)
4. User confirms download (one-time warning)
5. **Frontend generates reCAPTCHA v3 token**
6. Frontend calls `POST /api/files/{id}/download` with reCAPTCHA token
7. **Backend verifies reCAPTCHA token** (prevents bot-triggered deletions)
8. **Backend atomically marks as downloaded** (DynamoDB conditional update)
9. Backend returns response based on `content_type`:
   - **Files**: Presigned S3 download URL
   - **Text**: Base64 encrypted text directly
10. Frontend handles based on content type:
   - **Files**: Downloads from S3, decrypts, saves with filename
   - **Text**: Decrypts base64 text, displays in readonly textarea with copy button

### Atomic Download (Prevents Race Conditions)
```python
# DynamoDB conditional update - MUST use this pattern
response = table.update_item(
    Key={'file_id': file_id},
    UpdateExpression='SET downloaded = :true, downloaded_at = :now',
    ConditionExpression='downloaded = :false AND expires_at > :current',
    ExpressionAttributeValues={
        ':true': True,
        ':false': False,
        ':now': datetime.utcnow().isoformat(),
        ':current': int(time.time())
    }
)
# If ConditionalCheckFailedException → file already downloaded
```

### Statistics Tracking
The application tracks global aggregate statistics in a privacy-preserving manner:

1. **On Download**: After marking file/text as downloaded, backend increments global counters
2. **Atomic Updates**: Uses DynamoDB ADD operation to prevent race conditions
3. **Metrics Tracked**: Download count + total bytes transferred (both files and text)
4. **Privacy**: Only aggregate data, no user-specific information
5. **Display**: Frontend shows "X shares • Y MB transferred" in header

**STATS Record** (`file_id="STATS"`):
```python
{
    "file_id": "STATS",
    "downloads": 1234,
    "total_bytes": 2684354560,  # ~2.5 GB
    "updated_at": "2025-12-26T12:00:00Z"
}
```

**Protection**: Cleanup Lambda skips STATS record to preserve statistics forever.

### Vault Upload Flow (Password-Protected Multi-Access)
1. User selects Vault tab, chooses File or Text, enters password (min 4 chars)
2. **Frontend generates reCAPTCHA v3 token**
3. Frontend generates random 256-bit **data key**
4. Frontend generates random 16-byte **salt**
5. Frontend derives **password key** from password using PBKDF2:
   - 100,000 iterations
   - SHA-256 hash
   - 256-bit output
6. Frontend **encrypts data key** with password key (AES-256-GCM)
7. Frontend **encrypts content** with data key (AES-256-GCM)
8. Frontend calls `POST /api/upload/init` with:
   - `access_mode: "multi"`
   - `salt: <base64>`
   - `encrypted_key: <base64>`
   - Content (file to S3 or encrypted text in request)
9. Backend stores metadata with vault fields
10. Frontend shows URL: `https://domain/download.html#{file_id}#{salt}#{filename}#vault`
11. **Password is NOT in URL** — user must share separately

### Vault Download Flow
1. User opens vault link
2. Frontend detects `#vault` suffix, shows password prompt
3. User enters password
4. Frontend derives password key using stored salt + PBKDF2
5. Frontend decrypts the encrypted data key
6. Frontend downloads encrypted content (from S3 or DynamoDB)
7. Frontend decrypts content with data key
8. **Content remains available** — no one-time deletion for vault mode
9. Backend increments `download_count` for statistics

**Vault URL Format**: `#file_id#salt#filename#vault`
**One-time URL Format**: `#file_id#key#filename`
**PIN Mode**: No URL — uses 6-digit code + 4-character PIN

### PIN Upload Flow
1. User selects "PIN Code" method on upload page
2. User selects file + enters 4-character alphanumeric PIN + TTL
3. **Frontend generates reCAPTCHA v3 token**
4. Frontend calls `POST /pin/upload` with PIN (plaintext over HTTPS), file_size, TTL
5. **Backend verifies reCAPTCHA token** (score >= 0.5)
6. Backend generates salt, hashes PIN with SHA-256(PIN + salt), generates 6-digit file ID
7. Backend stores pin_hash + salt in DynamoDB (never stores raw PIN)
8. Backend returns file_id (6 digits), upload_url (presigned S3), and salt (hex)
9. Frontend derives encryption key from PIN + salt via PBKDF2 (100k iterations, SHA-256)
10. Frontend encrypts file with derived key (AES-256-GCM)
11. Frontend uploads encrypted data to S3
12. Frontend shows 6-digit code + PIN to user (user must remember both)

### PIN Download Flow
1. Recipient opens download page (no URL hash needed)
2. Enters 6-digit code in digit-by-digit input boxes
3. Frontend calls `POST /pin/initiate` → starts 60-second session
4. Timer starts counting down (green > 20s, yellow 10-20s, red < 10s)
5. Recipient enters 4-character PIN
6. Frontend calls `POST /pin/verify` with PIN
7. **Backend verifies PIN hash** using constant-time comparison (`hmac.compare_digest`)
8. On success: returns salt + presigned download URL (or encrypted text)
9. Frontend derives same key from PIN + salt via PBKDF2
10. Frontend downloads encrypted data from S3, decrypts, saves file
11. **File atomically marked as downloaded** (one-time use)

**PIN Security:**
- 3 wrong attempts → 12-hour lockout
- 60-second session timeout for PIN entry
- Constant-time PIN comparison prevents timing attacks
- PIN never stored — only SHA-256 hash

## API Endpoints

| Method | Endpoint                      | Purpose                              |
|--------|-------------------------------|--------------------------------------|
| POST   | /api/upload/init              | Initialize file/text upload          |
| GET    | /api/files/{id}/metadata      | Check availability                   |
| POST   | /api/files/{id}/download      | Mark downloaded + get content        |
| POST   | /api/files/{id}/report        | Report abuse                         |
| GET    | /api/stats                    | Get global statistics                |
| POST   | /api/pin/upload               | Initialize PIN-based upload          |
| POST   | /api/pin/initiate             | Start PIN entry session (60s)        |
| POST   | /api/pin/verify               | Verify PIN + get download content    |

## DynamoDB Schema

**Table: `sdbx-{env}-files`**

### File and Text Secret Records

| Attribute       | Type   | Description                            |
|-----------------|--------|----------------------------------------|
| file_id (PK)    | String | UUID v4                                |
| content_type    | String | "file" or "text"                       |
| file_size       | Number | Size in bytes (or encrypted text size) |
| created_at      | String | ISO 8601                               |
| expires_at      | Number | Unix timestamp (TTL)                   |
| downloaded      | Bool   | One-time download flag                 |
| downloaded_at   | String | ISO 8601 (optional)                    |
| ip_hash         | String | SHA256 of uploader IP                  |
| report_count    | Number | Abuse reports                          |
| s3_key          | String | S3 object key (files only)             |
| encrypted_text  | String | Base64 encrypted text (text only)      |
| access_mode     | String | "one_time" or "multi" (vault)          |
| salt            | String | Base64 PBKDF2 salt (vault only)        |
| encrypted_key   | String | Base64 encrypted data key (vault only) |
| download_count  | Number | Total downloads (vault only)           |
| pin_hash        | String | SHA-256 hash of PIN (PIN mode only)    |
| attempts_left   | Number | Remaining PIN attempts (PIN mode only) |
| locked_until    | Number | Unix timestamp of lockout end (PIN)    |
| session_started | Number | Unix timestamp of session start (PIN)  |
| session_expires | Number | Unix timestamp of session end (PIN)    |

### Statistics Record

Special record with `file_id="STATS"` for tracking global aggregate metrics:

| Attribute     | Type   | Description                    |
|---------------|--------|--------------------------------|
| file_id (PK)  | String | "STATS" (reserved)             |
| downloads     | Number | Total downloads count          |
| total_bytes   | Number | Total bytes transferred        |
| updated_at    | String | ISO 8601 (last update)         |

**Note**: The cleanup Lambda skips the STATS record to preserve statistics forever.

## Encryption Spec

### One-Time Mode (File/Text)
| Parameter     | Value                          |
|---------------|--------------------------------|
| Algorithm     | AES-256-GCM                    |
| Key size      | 256 bits (32 bytes)            |
| IV size       | 96 bits (12 bytes), random     |
| Key derivation| crypto.getRandomValues()       |
| Auth tag      | 128 bits                       |

### Vault Mode (Password-Protected)
| Parameter     | Value                          |
|---------------|--------------------------------|
| Algorithm     | AES-256-GCM (double layer)     |
| Data key      | 256 bits, random               |
| Password KDF  | PBKDF2                         |
| PBKDF2 iterations | 100,000                    |
| PBKDF2 hash   | SHA-256                        |
| Salt size     | 128 bits (16 bytes), random    |
| IV size       | 96 bits (12 bytes), random     |

**Vault encryption layers:**
1. Content encrypted with random data key (AES-256-GCM)
2. Data key encrypted with password-derived key (AES-256-GCM)
3. Salt stored server-side, password never transmitted

### PIN Mode
| Parameter     | Value                          |
|---------------|--------------------------------|
| Algorithm     | AES-256-GCM (single layer)     |
| Key derivation| PBKDF2 from PIN                |
| PBKDF2 iterations | 100,000                    |
| PBKDF2 hash   | SHA-256                        |
| Salt size     | 256 bits (32 bytes), random    |
| IV size       | 96 bits (12 bytes), random     |
| PIN hash (server) | SHA-256(PIN + salt)        |
| PIN comparison | hmac.compare_digest (constant-time) |

**PIN encryption flow:**
1. Server generates salt, returns to client
2. Client derives key from PIN + salt via PBKDF2 (extractable=true for Web Worker)
3. Content encrypted directly with PIN-derived key (AES-256-GCM)
4. Server stores SHA-256(PIN + salt) for verification only

```javascript
// Frontend encryption pattern (one-time mode)
const key = crypto.getRandomValues(new Uint8Array(32));
const iv = crypto.getRandomValues(new Uint8Array(12));

const cryptoKey = await crypto.subtle.importKey(
    'raw', key, { name: 'AES-GCM' }, false, ['encrypt']
);

const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    cryptoKey,
    fileBuffer
);

// Prepend IV to ciphertext
const result = new Uint8Array(iv.length + encrypted.byteLength);
result.set(iv);
result.set(new Uint8Array(encrypted), iv.length);
```

```javascript
// Vault mode - PBKDF2 key derivation
const salt = crypto.getRandomValues(new Uint8Array(16));
const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
);
const passwordKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false, ['encrypt', 'decrypt']
);
// Then encrypt the data key with passwordKey
```

## Environment Variables

### Lambda Functions
```
BUCKET_NAME=sdbx-{env}-files
TABLE_NAME=sdbx-{env}-files
ENVIRONMENT={dev|prod}
MAX_FILE_SIZE=104857600  # 100MB
CLOUDFRONT_SECRET=<random-32-char-string>  # For origin verification
RECAPTCHA_SECRET_KEY=<google-recaptcha-secret>  # For bot protection
```

### Lambda Layer
All Lambda functions use a shared Lambda Layer (`sdbx-{env}-dependencies`) containing:
- `requests>=2.31.0` (for reCAPTCHA verification)
- All transitive dependencies (urllib3, certifi, idna, charset-normalizer)

**Benefits:**
- Smaller deployment packages (~5KB handler code vs ~16MB with bundled deps)
- Faster deployments (layer cached, only code changes deployed)
- Consistent dependency versions across all functions
- Single storage location for shared dependencies

### Frontend (build-time)
```
API_BASE_URL=https://api.{domain}/v1
```

## Coding Guidelines

### General Principles

**1. Clean Code Fundamentals**
- **KISS** — Keep It Simple, Stupid. Prefer straightforward solutions.
- **DRY** — Don't Repeat Yourself. Extract common logic into functions.
- **YAGNI** — You Aren't Gonna Need It. Don't build features "just in case".
- **Single Responsibility** — Each function/module does ONE thing well.
- **Fail Fast** — Validate inputs early, return/throw immediately on error.

**2. Naming Conventions**
```
# Good: Clear, descriptive, pronounceable
get_file_metadata()
is_file_expired()
download_url
max_file_size

# Bad: Abbreviated, unclear, generic
get_fm()
chk_exp()
url1
size
```

**3. Functions**
- Max 20-30 lines per function (soft limit)
- Max 3-4 parameters; use objects/dicts for more
- Single return type (don't return `string | None | dict`)
- Pure functions when possible (no side effects)

**4. Comments**
```python
# Bad: Describes WHAT (obvious from code)
# Increment counter by 1
counter += 1

# Good: Describes WHY (not obvious)
# DynamoDB TTL can take up to 48h, so we check manually
if is_expired(record):
    return None
```

**5. Error Messages**
```python
# Bad: Generic
raise ValueError("Invalid input")

# Good: Specific, actionable
raise ValueError(f"TTL must be one of {ALLOWED_TTL_VALUES}, got: {ttl}")
```

---

### Python (Backend)

**Setup**
- Python 3.12
- Formatter: `black` (line length 100)
- Import sorter: `isort`
- Linter: `ruff` or `flake8`
- Type checker: `mypy` (strict mode)
- Tests: `pytest`

**Import Order**
```python
# 1. Standard library
import json
import logging
from datetime import datetime, timedelta
from typing import Any

# 2. Third-party
import boto3
from botocore.exceptions import ClientError

# 3. Local
from shared.dynamo import get_file_record
from shared.exceptions import FileNotFoundError
```

**Type Hints (Required)**
```python
# Always type function signatures
def create_file_record(
    file_id: str,
    file_size: int,
    ttl_hours: int,
    ip_address: str,
) -> dict[str, Any]:
    """Create a new file record in DynamoDB."""
    ...

# Use Optional for nullable values
def get_file(file_id: str) -> Optional[FileRecord]:
    ...

# Use TypedDict for complex structures
class FileRecord(TypedDict):
    file_id: str
    file_size: int
    downloaded: bool
    expires_at: int
```

**Lambda Handler Pattern**
```python
import json
import logging
from typing import Any

from shared.exceptions import ValidationError, FileNotFoundError
from shared.validation import validate_file_id

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Get file metadata.
    
    Returns file info if available, 404 if not found.
    """
    # 1. Extract and validate input
    file_id = event.get("pathParameters", {}).get("file_id")
    
    try:
        validate_file_id(file_id)
    except ValidationError as e:
        return _error_response(400, str(e))
    
    # 2. Business logic
    try:
        record = get_file_record(file_id)
        if not record:
            return _error_response(404, "File not found")
        
        return _success_response({
            "file_id": record["file_id"],
            "file_size": record["file_size"],
            "available": not record["downloaded"],
            "expires_at": record["expires_at"],
        })
        
    except Exception as e:
        logger.exception(f"Unexpected error for file_id={file_id}")
        return _error_response(500, "Internal server error")


def _success_response(data: dict) -> dict[str, Any]:
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(data),
    }


def _error_response(status: int, message: str) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps({"error": message}),
    }
```

**Logging**
```python
# Never use print() — always logging
logger.info(f"Processing file_id={file_id}")
logger.warning(f"File expired: {file_id}")
logger.error(f"DynamoDB error: {e}")
logger.exception("Unexpected error")  # Includes stack trace

# Structure logs for CloudWatch Insights
logger.info(json.dumps({
    "action": "file_downloaded",
    "file_id": file_id,
    "file_size": file_size,
    "duration_ms": duration,
}))
```

**Error Handling**
```python
# Define custom exceptions
class SecureDropError(Exception):
    """Base exception for SecureDrop."""
    pass

class ValidationError(SecureDropError):
    """Invalid input data."""
    pass

class FileNotFoundError(SecureDropError):
    """File does not exist."""
    pass

class FileAlreadyDownloadedError(SecureDropError):
    """File was already downloaded."""
    pass

# Catch specific exceptions, not bare except
try:
    result = table.update_item(...)
except ClientError as e:
    if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
        raise FileAlreadyDownloadedError(file_id)
    raise  # Re-raise unexpected errors
```

**Constants**
```python
# Use constants, not magic values
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
ALLOWED_TTL_VALUES = ("1h", "12h", "24h")  # Presets, also accepts numeric minutes (5-10080)
PRESIGNED_URL_EXPIRY = 300  # 5 minutes

TTL_TO_SECONDS = {
    "1h": 3600,
    "12h": 43200,
    "24h": 86400,
}
```

---

### JavaScript (Frontend)

**Setup**
- Vanilla JS (ES6+), no frameworks
- No build step for MVP
- No external dependencies
- Strict mode always

**File Structure**
```javascript
// js/crypto.js - Encryption module
// js/upload.js - Upload flow
// js/download.js - Download flow
// js/api.js - API calls
// js/utils.js - Helpers
// js/constants.js - Configuration
```

**Module Pattern**
```javascript
// Use IIFE to avoid global pollution
const CryptoModule = (function() {
    'use strict';
    
    // Private constants
    const ALGORITHM = 'AES-GCM';
    const KEY_LENGTH = 256;
    const IV_LENGTH = 12;
    
    // Private functions
    function generateIV() {
        return crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    }
    
    // Public API
    return {
        /**
         * Generate a random encryption key
         * @returns {Promise<CryptoKey>}
         */
        async generateKey() {
            return crypto.subtle.generateKey(
                { name: ALGORITHM, length: KEY_LENGTH },
                true,  // extractable
                ['encrypt', 'decrypt']
            );
        },
        
        /**
         * Encrypt data with AES-256-GCM
         * @param {ArrayBuffer} data - Data to encrypt
         * @param {CryptoKey} key - Encryption key
         * @returns {Promise<Uint8Array>} IV + ciphertext
         */
        async encrypt(data, key) {
            const iv = generateIV();
            const ciphertext = await crypto.subtle.encrypt(
                { name: ALGORITHM, iv },
                key,
                data
            );
            
            // Prepend IV to ciphertext
            const result = new Uint8Array(iv.length + ciphertext.byteLength);
            result.set(iv);
            result.set(new Uint8Array(ciphertext), iv.length);
            return result;
        },
        
        /**
         * Decrypt data with AES-256-GCM
         * @param {Uint8Array} data - IV + ciphertext
         * @param {CryptoKey} key - Decryption key
         * @returns {Promise<ArrayBuffer>} Decrypted data
         */
        async decrypt(data, key) {
            const iv = data.slice(0, IV_LENGTH);
            const ciphertext = data.slice(IV_LENGTH);
            
            return crypto.subtle.decrypt(
                { name: ALGORITHM, iv },
                key,
                ciphertext
            );
        }
    };
})();
```

**JSDoc (Required for Public Functions)**
```javascript
/**
 * Upload an encrypted file to the server
 * @param {File} file - File to upload
 * @param {string|number} ttl - Time to live: "1h" | "12h" | "24h" | minutes (5-10080)
 * @param {function(number): void} onProgress - Progress callback (0-100)
 * @returns {Promise<{fileId: string, shareUrl: string}>}
 * @throws {Error} If upload fails
 */
async function uploadFile(file, ttl, onProgress) {
    // ...
}
```

**Error Handling**
```javascript
// Define error types
class SecureDropError extends Error {
    constructor(message, code) {
        super(message);
        this.name = 'SecureDropError';
        this.code = code;
    }
}

class NetworkError extends SecureDropError {
    constructor(message) {
        super(message, 'NETWORK_ERROR');
    }
}

class DecryptionError extends SecureDropError {
    constructor() {
        super('Failed to decrypt file. Invalid key or corrupted data.', 'DECRYPTION_ERROR');
    }
}

// Always use try/catch with async/await
async function downloadFile(fileId, key) {
    try {
        const metadata = await api.getMetadata(fileId);
        if (!metadata.available) {
            throw new SdbxError('File already downloaded', 'ALREADY_DOWNLOADED');
        }

        const encryptedData = await api.download(fileId);
        const decryptedData = await CryptoModule.decrypt(encryptedData, key);

        return decryptedData;
    } catch (error) {
        if (error instanceof SdbxError) {
            throw error;  // Re-throw known errors
        }
        console.error('Download failed:', error);
        throw new NetworkError('Failed to download file');
    }
}
```

**DOM Manipulation**
```javascript
// Cache DOM elements
const elements = {
    dropZone: document.getElementById('drop-zone'),
    fileInput: document.getElementById('file-input'),
    uploadBtn: document.getElementById('upload-btn'),
    progressBar: document.getElementById('progress-bar'),
    resultUrl: document.getElementById('result-url'),
};

// Use event delegation for dynamic elements
document.addEventListener('click', (e) => {
    if (e.target.matches('.copy-btn')) {
        handleCopyClick(e.target);
    }
});

// Clean up event listeners
function cleanup() {
    elements.dropZone.removeEventListener('drop', handleDrop);
    elements.dropZone.removeEventListener('dragover', handleDragOver);
}
```

**Constants**
```javascript
// js/constants.js
const CONFIG = Object.freeze({
    API_BASE_URL: 'https://api.example.com/v1',
    MAX_FILE_SIZE: 100 * 1024 * 1024,  // 100 MB
    ALLOWED_TTL: ['1h', '12h', '24h'],  // Presets, custom also supported (5-10080 minutes)
    PRESIGNED_URL_EXPIRY: 300,  // 5 minutes
});

const MESSAGES = Object.freeze({
    FILE_TOO_LARGE: 'File size exceeds 100 MB limit',
    UPLOAD_SUCCESS: 'File uploaded successfully',
    COPY_SUCCESS: 'Link copied to clipboard',
    DOWNLOAD_WARNING: 'This file can only be downloaded ONCE. Continue?',
});
```

---

### Terraform

**File Structure**
```
terraform/
├── modules/
│   └── storage/
│       ├── main.tf        # Resources
│       ├── variables.tf   # Input variables
│       ├── outputs.tf     # Output values
│       └── README.md      # Module documentation
└── environments/
    └── dev/
        ├── main.tf        # Module calls
        ├── variables.tf   # Variable declarations
        ├── outputs.tf     # Root outputs
        ├── providers.tf   # Provider config
        ├── backend.tf     # State backend
        └── terraform.tfvars  # Variable values (git-ignored)
```

**Naming Conventions**
```hcl
# Resources: {project}-{env}-{resource}
resource "aws_s3_bucket" "files" {
  bucket = "sdbx-${var.environment}-files"
}

# Variables: snake_case, descriptive
variable "environment" {
  description = "Deployment environment (dev, prod)"
  type        = string
}

variable "max_file_size_mb" {
  description = "Maximum file size in megabytes"
  type        = number
  default     = 100
}
```

**Required Tags**
```hcl
locals {
  common_tags = {
    Project     = "sdbx"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Repository  = "github.com/user/sdbx"
  }
}

resource "aws_s3_bucket" "files" {
  bucket = "securedrop-${var.environment}-files"
  tags   = local.common_tags
}
```

**Variable Validation**
```hcl
variable "environment" {
  description = "Deployment environment"
  type        = string
  
  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "Environment must be 'dev' or 'prod'."
  }
}

variable "ttl_options" {
  description = "Allowed TTL values in hours"
  type        = list(number)
  default     = [1, 12, 24]
  
  validation {
    condition     = alltrue([for t in var.ttl_options : t > 0 && t <= 168])
    error_message = "TTL values must be between 1 and 168 hours."
  }
}
```

**Module Pattern**
```hcl
# modules/storage/main.tf
resource "aws_s3_bucket" "files" {
  bucket = "${var.project_name}-${var.environment}-files"
  tags   = var.tags
}

resource "aws_s3_bucket_public_access_block" "files" {
  bucket = aws_s3_bucket.files.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# modules/storage/outputs.tf
output "bucket_name" {
  description = "Name of the files S3 bucket"
  value       = aws_s3_bucket.files.id
}

output "bucket_arn" {
  description = "ARN of the files S3 bucket"
  value       = aws_s3_bucket.files.arn
}
```

---

### Git Conventions

**Branch Naming**
```
main        # Production-ready code
develop     # Integration branch
feature/*   # New features: feature/add-upload-progress
bugfix/*    # Bug fixes: bugfix/fix-race-condition
hotfix/*    # Production hotfixes: hotfix/fix-critical-bug
```

**Commit Messages**
```
# Format: <type>(<scope>): <description>

feat(upload): add progress indicator
fix(download): handle race condition with atomic update
docs(readme): add deployment instructions
refactor(crypto): extract key generation to separate function
test(api): add tests for metadata endpoint
chore(deps): update boto3 to 1.28.0

# Types: feat, fix, docs, style, refactor, test, chore
# Keep under 72 characters
```

**Pull Request Checklist**
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No console.log / print statements
- [ ] No hardcoded secrets or URLs
- [ ] Error handling in place

---

### Testing Guidelines

**Python Tests**
```python
# tests/test_upload.py
import pytest
from moto import mock_dynamodb, mock_s3

from lambdas.upload_init.handler import handler


@pytest.fixture
def dynamodb_table():
    """Create mock DynamoDB table."""
    with mock_dynamodb():
        # Setup table...
        yield table


class TestUploadInit:
    """Tests for upload_init Lambda."""
    
    def test_valid_upload_returns_presigned_url(self, dynamodb_table):
        """Should return presigned URL for valid request."""
        event = {
            "body": '{"file_size": 1024, "ttl": "1h"}'
        }
        
        response = handler(event, None)
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert "upload_url" in body
        assert "file_id" in body
    
    def test_invalid_ttl_returns_400(self, dynamodb_table):
        """Should return 400 for invalid TTL value."""
        event = {
            "body": '{"file_size": 1024, "ttl": "invalid"}'
        }
        
        response = handler(event, None)
        
        assert response["statusCode"] == 400
    
    def test_file_too_large_returns_413(self, dynamodb_table):
        """Should return 413 when file exceeds limit."""
        event = {
            "body": '{"file_size": 200000000, "ttl": "1h"}'  # 200MB
        }
        
        response = handler(event, None)
        
        assert response["statusCode"] == 413
```

**Test Naming**
```python
# Pattern: test_<condition>_<expected_result>
def test_valid_file_id_returns_metadata():
def test_expired_file_returns_404():
def test_concurrent_downloads_only_one_succeeds():
```

---

### Code Review Checklist

**Functionality**
- [ ] Does the code do what it's supposed to?
- [ ] Are edge cases handled?
- [ ] Is error handling appropriate?

**Security**
- [ ] No secrets in code?
- [ ] Input validated?
- [ ] SQL/NoSQL injection prevented?
- [ ] XSS prevented (if frontend)?

**Clean Code**
- [ ] Functions are small and focused?
- [ ] Names are clear and descriptive?
- [ ] No code duplication?
- [ ] No dead code or commented-out code?

**Performance**
- [ ] No N+1 queries?
- [ ] Appropriate data structures?
- [ ] No memory leaks (event listeners)?

**Testing**
- [ ] Tests cover happy path?
- [ ] Tests cover error cases?
- [ ] Tests are readable?

## Commands Reference

### Terraform
```bash
# Initialize
cd terraform/environments/dev
terraform init

# Plan changes
terraform plan -var-file=terraform.tfvars

# Apply
terraform apply -var-file=terraform.tfvars

# Destroy (careful!)
terraform destroy -var-file=terraform.tfvars
```

### Backend Development
```bash
# Install dependencies
cd backend
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Format code
black lambdas/ shared/
isort lambdas/ shared/

# Package Lambda
cd lambdas/upload_init
zip -r function.zip handler.py
```

### Frontend Development
```bash
# Serve locally (simple)
cd frontend
python -m http.server 8000

# Deploy to S3
aws s3 sync frontend/ s3://securedrop-dev-static/ --delete
aws cloudfront create-invalidation --distribution-id XXX --paths "/*"
```

## Security Checklist

- [x] S3 bucket: Block all public access
- [x] S3 bucket: Enable SSE-S3 encryption
- [ ] API Gateway: Enable throttling
- [x] API Gateway: CORS only for frontend domain
- [x] Lambda: Minimum IAM permissions
- [x] DynamoDB: Enable TTL
- [x] CloudFront: HTTPS only, TLS 1.2+
- [x] CloudFront: Origin verification with custom header (blocks direct API access)
- [x] Lambda: Verify CloudFront origin header on all endpoints
- [x] No secrets in code — use environment variables
- [x] Input validation on all endpoints
- [x] **reCAPTCHA v3 bot protection** (deployed to prod)
- [x] **Lambda Layer for dependency management** (deployed to prod)
- [x] **Content Security Policy** (deployed to prod) - Blocks inline scripts, restricts resource loading
- [x] **Comprehensive test suite** (159+ tests, zero mocks, ~80% coverage)
- [ ] Rate limiting per IP (Phase 3: WAF if needed)

### Security Implementation

**Phase 1: CloudFront Origin Verification** ✅ Deployed
- All API requests must come through CloudFront
- CloudFront adds `X-Origin-Verify` header with secret value
- Lambda functions verify header presence and value
- Direct API calls return 403 Forbidden
- Implementation: `backend/shared/security.py`

**Phase 2: reCAPTCHA v3** ✅ Deployed (December 2024)
- Google reCAPTCHA v3 integrated on all POST endpoints
- Invisible to users (score-based verification, threshold: 0.5)
- Protected endpoints: upload init, download, abuse report
- Prevents automated bot/script abuse
- Implementation: `backend/shared/security.py` (`verify_recaptcha()`)
- Site key in frontend, secret key in Lambda environment variables
- Lambda Layer contains `requests` library for API verification
- Combined protection: ~95-98% bot blocking effectiveness

**Phase 3: Content Security Policy** ✅ Deployed (December 2024)
- Strict CSP headers via CloudFront response headers policy
- Blocks inline scripts (all scripts moved to external files)
- Restricts connections to: self, reCAPTCHA, API Gateway, S3
- Prevents XSS attacks and unauthorized resource loading
- Implementation: `terraform/modules/cdn/main.tf` + `frontend/js/init.js`
- No `unsafe-inline` - maintains security without compromises

**Phase 4: Comprehensive Testing** ✅ Completed (December 2024)
- 159+ tests with ZERO mocks
- Backend: 135+ tests (validation, response, JSON, security)
- Frontend: 24 tests (AES-256-GCM encryption, key management)
- ~80% code coverage of shared modules
- Tests real logic and real encryption
- Implementation: `backend/tests/`, `frontend/tests/`, `TESTING.md`

## Common Pitfalls

1. **URL Fragment**: The `#key` part is NEVER sent to server — this is by design
2. **Atomic Download**: Always use DynamoDB conditional update, never read-then-write
3. **Presigned URLs**: Set short expiry (5 min for download, 15 min for upload)
4. **File Size**: Validate both client-side and server-side (max 100MB)
5. **CORS**: Must be configured on both API Gateway AND S3 bucket
6. **TTL**: DynamoDB TTL is eventually consistent — may take up to 48h
7. **API Path**: Frontend calls `/dev/*` which CloudFront routes to API Gateway (no `/api` prefix needed)

## Current Features

- Max file size: 500MB
- Text secrets: up to 1000 characters
- Tab UI for file/text/vault selection
- Multi-file ZIP bundles (up to 10 files)
- Custom expiration times (5 min - 7 days) with real-time preview
- **Vault mode**: Password-protected multi-access sharing
- **PIN mode**: 6-digit code + 4-char PIN sharing (no long URLs)
- QR code generation for sharing
- Languages: English only (i18n in future)
- Desktop-first (mobile support available)

## Useful Links

- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [DynamoDB Conditional Updates](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html)
- [S3 Presigned URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)

---

**Last Updated**: January 31, 2026
**Version**: v1.4 - PIN-Based File Sharing

## Recent Changes (v1.4)

- PIN mode: 6-digit code + 4-character alphanumeric PIN sharing
- PBKDF2 key derivation from PIN (100k iterations, SHA-256)
- SHA-256(PIN + salt) for server-side PIN verification
- Constant-time PIN comparison (hmac.compare_digest)
- 60-second session timeout for PIN entry
- 3-attempt lockout with 12-hour cooldown
- Method selection UI (Link vs PIN) on upload page
- 6 individual digit input boxes for code entry on download page
- 3 new Lambda functions: pin_upload_init, pin_initiate, pin_verify
- 3 new API endpoints: /pin/upload, /pin/initiate, /pin/verify

## Previous Changes (v1.3)

- ✅ **Vault mode**: Password-protected multi-access sharing
- ✅ PBKDF2 key derivation (100k iterations, SHA-256)
- ✅ Double encryption layer (data key + password key)
- ✅ Multi-access mode (unlimited downloads until expiry)
- ✅ Vault tab in UI for file and text
- ✅ Password prompt on download page for vault content
- ✅ QR code generation for all share links

## Previous Changes (v1.2)

- ✅ Multi-file ZIP bundles (up to 10 files, client-side compression)
- ✅ Custom expiration times (5 min - 7 days) with dropdown selects
- ✅ Real-time expiration preview in user's local timezone
- ✅ Text secrets support (up to 1000 characters)
- ✅ Tab UI for file/text selection
- ✅ Dynamic download page labels (detects file vs text)
- ✅ Statistics display: "X shares • Y MB transferred"
- ✅ Context-aware UI messaging

