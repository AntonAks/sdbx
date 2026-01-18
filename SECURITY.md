# Security Policy

## 🔒 Reporting Security Vulnerabilities

**Please DO NOT open public issues for security vulnerabilities.**

⚠️ **Why not public issues?** Public disclosure of vulnerabilities before patches are available puts all users at risk. We need time to fix the issue first.

### How to Report

**Use GitHub Security Advisories (Private Reporting):**

1. Go to [github.com/antonaks/sdbx/security/advisories](https://github.com/antonaks/sdbx/security/advisories)
2. Click "Report a vulnerability"
3. Fill in the details privately

**Or contact via:**
- Create a private security advisory on GitHub
- Email: [your-github-email] (if you prefer email)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Response time:** We aim to respond within **48-72 hours**.

---

## ⏱️ Response Timeline

- **Critical:** Patch within 7 days
- **High:** Patch within 14 days  
- **Medium:** Patch within 30 days
- **Low:** Next release

---

## 🎁 Rewards

We offer:

- Public acknowledgment (if desired)
- Credit in release notes
- Our sincere gratitude 🙏

---

## 🏗️ Security Architecture

### Zero-Knowledge Design
- Encryption keys **never** leave your browser
- Keys stored in URL fragment (`#key`) - never sent to server
- We **cannot** decrypt your files, even if we wanted to

### Encryption
- **AES-256-GCM** encryption
- **256-bit** keys generated client-side
- **Random IV** for each encryption

### Security Layers
1. **Client-side:** All encryption in browser
2. **Transport:** HTTPS/TLS 1.2+ only
3. **CloudFront:** Origin verification, DDoS protection
4. **API Gateway:** Rate limiting, CORS
5. **Lambda:** reCAPTCHA v3, input validation
6. **Storage:** S3/DynamoDB encryption at rest

### Atomic Operations
- DynamoDB conditional updates prevent race conditions
- One-time download enforced at database level

---

## 🔍 Security Scope

### ✅ In Scope
- Encryption implementation
- Authentication/authorization bypass
- Data leakage
- Race conditions
- XSS, CSRF, injection attacks
- Rate limit bypass

### ❌ Out of Scope
- AWS infrastructure security (handled by AWS)
- Social engineering
- Physical security
- Theoretical attacks (unless practical)
- DDoS (handled by CloudFront)

---

## ⚠️ Known Limitations

We're transparent about current limitations:
- No password protection (yet)
- No file integrity verification
- No sender authentication
- Requires modern browser with Web Crypto API
- Single download only (by design)

See [ROADMAP.md](./ROADMAP.md) for planned improvements.

---

## 🛡️ Secure Coding Practices

For contributors:
- Always validate input
- Use parameterized queries
- Never log sensitive data
- Use cryptographically secure random (CSPRNG)
- Keep dependencies updated
- Follow principle of least privilege

---

## 📚 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/)

---

## 🙏 Thank You

We take security seriously and appreciate responsible disclosure. Your efforts help keep sdbx safe for everyone.

**Questions?** Open a [security advisory](https://github.com/antonaks/sdbx/security/advisories) or regular [issue](https://github.com/antonaks/sdbx/issues) for non-security questions.
