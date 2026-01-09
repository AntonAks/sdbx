# sdbx

> Zero-knowledge file and text sharing service with end-to-end encryption and one-time access

## Features

- **Client-side encryption** - Files and text are encrypted in your browser before upload (AES-256-GCM)
- **Text secrets** - Share encrypted text snippets (up to 1000 characters) without files
- **File sharing** - Upload files up to 500MB with secure encryption
- **One-time access** - Each file/text can only be viewed once, then it's automatically deleted (with network failure protection)
- **Zero-knowledge** - The server never sees your encryption keys or unencrypted content
- **No registration** - No accounts, no email, no tracking
- **Self-destructing** - Content expires after 1, 12, or 24 hours
- **Privacy-first** - Built with privacy as the core principle

## How It Works

### Uploading Files

1. Select a file and choose expiration time (1h, 12h, or 24h)
2. Your browser generates a random encryption key
3. File is encrypted locally using AES-256-GCM
4. Encrypted file is uploaded to secure storage (no filename sent to server)
5. You receive a shareable link with the decryption key and filename in the URL fragment (`#key#filename`)
6. The key and filename never leave your browser or reach the server

### Sharing Text Secrets

1. Type or paste your secret text (max 1000 characters)
2. Choose expiration time (1h, 12h, or 24h)
3. Your browser generates a random encryption key
4. Text is encrypted locally using AES-256-GCM
5. Encrypted text is sent directly to the database (no files created)
6. You receive a shareable link with the decryption key in the URL fragment
7. The key never leaves your browser or reaches the server

### Downloading/Viewing

1. Open the shared link
2. Your browser extracts the decryption key from the URL fragment
3. Click to view/download (warning: this works only once!)
4. **Download reserved** - Server reserves the content for your download (10-minute window)
5. Content is downloaded and decrypted in your browser:
   - **Files**: Downloaded and saved with original filename
   - **Text**: Displayed in a copyable text area
6. **Download confirmed** - Your browser confirms successful download to the server
7. Content is automatically deleted from the server
8. The link becomes invalid forever

**Network Failure Protection**: If your download is interrupted (network error, browser crash), you have 10 minutes to retry using the same link. This ensures you don't lose access due to temporary technical issues while maintaining one-time download security.

## Security

- **Encryption**: AES-256-GCM with 256-bit keys
- **Zero-knowledge**: Decryption keys and filenames stay in URL fragments, never sent to server
- **Two-phase download**: Reservation system prevents data loss from network failures while maintaining one-time access
- **Bot protection**: Google reCAPTCHA v3 with invisible verification (deployed)
- **Origin verification**: CloudFront custom header blocks direct API access (deployed)
- **Atomic operations**: Race condition prevention using conditional database updates
- **HTTPS only**: All communication encrypted in transit (TLS 1.2+)
- **No tracking**: No user accounts, no IP logging, no analytics

### Security Layers

**Layer 1 - CloudFront Origin Verification** ✅ Deployed
- Custom secret header blocks direct API calls
- Only requests through CloudFront are accepted
- Prevents automated script abuse
- Zero cost protection

**Layer 2 - reCAPTCHA v3** ✅ Deployed
- Bot detection and prevention on all POST endpoints
- Invisible to legitimate users (score-based verification)
- Protects upload, download, and abuse report endpoints
- Minimum score threshold: 0.5 (adjustable)
- Lambda Layer for efficient dependency management

See [SECURITY_PLAN.md](./SECURITY_PLAN.md) for complete security implementation details.

## Limitations

- Maximum file size: 500 MB
- Files expire after max 24 hours
- Each file can only be downloaded once (with 10-minute retry window for network failures)
- Desktop browsers recommended (mobile support coming soon)

## Technology

- **Frontend**: Vanilla JavaScript, Web Crypto API
- **Backend**: AWS Lambda (7 functions, Python 3.12), API Gateway
- **Storage**: S3 (encrypted files), DynamoDB (metadata + statistics)
- **CDN**: CloudFront
- **Infrastructure**: Terraform (Infrastructure as Code)

## Development

See [ROADMAP.md](./ROADMAP.md) for development progress and plans.
See [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed deployment instructions.

### Prerequisites

- AWS Account
- Terraform >= 1.5
- Python 3.12
- AWS CLI configured (`aws configure`)

### Quick Start - Deploy to AWS

```bash
# 1. Bootstrap Terraform backend (once per AWS account)
./scripts/bootstrap-terraform-backend.sh

# 2. Deploy infrastructure
make init-dev
make deploy-dev

# 3. Update API URLs in frontend/js/upload.js and frontend/js/download.js
# Get your API endpoint: cd terraform/environments/dev && terraform output api_endpoint

# 4. Deploy frontend
make deploy-frontend-dev

# 5. Get your CloudFront URL
cd terraform/environments/dev && terraform output cloudfront_domain
```

### Local Frontend Development

```bash
# Serve frontend locally
cd frontend
python -m http.server 8000
# Visit http://localhost:8000

# Note: You'll need to update API URLs to point to your deployed backend
```

### Deployment Status

- ✅ Development environment deployed and operational
- ✅ Production environment deployed and operational
- ✅ Comprehensive test suite (159+ tests, zero mocks)

See [DEPLOYMENT.md](./DEPLOYMENT.md) for troubleshooting and detailed instructions.

## Testing

sdbx has a comprehensive test suite with **159+ tests** and **ZERO mocks**:

```bash
# Run all tests (backend + frontend)
make test

# Run backend tests only (Python)
make test-backend

# Run frontend tests only (JavaScript)
make test-frontend

# Run backend tests with coverage report
make test-backend-cov
```

**Test Coverage:**
- **Backend**: 135+ tests covering validation, response formatting, JSON encoding, security
- **Frontend**: 24 tests covering AES-256-GCM encryption, key management, URL encoding
- **Coverage**: ~80% of shared modules
- **Philosophy**: No mocks - testing real logic and real crypto

See [TESTING.md](./TESTING.md) for detailed testing guide.

## Privacy Policy

- We don't store unencrypted files
- We don't store or have access to filenames
- We don't have access to your encryption keys
- We don't log IP addresses for file access
- Files are automatically deleted after first download or expiration
- No cookies, no tracking, no analytics

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please read our contribution guidelines first.

## Disclaimer

This service is provided as-is. While we implement strong encryption and security practices, users are responsible for their own data. Do not use for illegal content.

---

**Built with privacy in mind** 🔒
