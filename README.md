# sdbx

> Zero-knowledge file sharing service with end-to-end encryption and one-time downloads

## Features

- **Client-side encryption** - Files are encrypted in your browser before upload (AES-256-GCM)
- **One-time download** - Each file can only be downloaded once, then it's automatically deleted
- **Zero-knowledge** - The server never sees your encryption key, filenames, or unencrypted files
- **No registration** - No accounts, no email, no tracking
- **Self-destructing** - Files expire after 1, 12, or 24 hours
- **Privacy-first** - Built with privacy as the core principle

## How It Works

### Uploading

1. Select a file and choose expiration time (1h, 12h, or 24h)
2. Your browser generates a random encryption key
3. File is encrypted locally using AES-256-GCM
4. Encrypted file is uploaded to secure storage (no filename sent to server)
5. You receive a shareable link with the decryption key and filename in the URL fragment (`#key#filename`)
6. The key and filename never leave your browser or reach the server

### Downloading

1. Open the shared link
2. Your browser extracts the decryption key and filename from the URL fragment
3. Click download (warning: this works only once!)
4. Encrypted file is downloaded and decrypted in your browser
5. File is saved with its original filename
6. File is automatically deleted from the server
7. The link becomes invalid forever

## Security

- **Encryption**: AES-256-GCM with 256-bit keys
- **Zero-knowledge**: Decryption keys and filenames stay in URL fragments, never sent to server
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

- Maximum file size: 100 MB
- Files expire after max 24 hours
- Each file can only be downloaded once
- Desktop browsers recommended (mobile support coming soon)

## Technology

- **Frontend**: Vanilla JavaScript, Web Crypto API
- **Backend**: AWS Lambda (Python 3.12), API Gateway
- **Storage**: S3 (encrypted files), DynamoDB (metadata)
- **CDN**: CloudFront
- **Infrastructure**: Terraform

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
- ✅ Live at: https://d21g35hqtnbz7i.cloudfront.net/
- 🟡 Production deployment pending

See [DEPLOYMENT.md](./DEPLOYMENT.md) for troubleshooting and detailed instructions.

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
