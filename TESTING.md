# Testing Guide for sdbx

Complete testing suite with **NO MOCKS** - all tests use real logic and real crypto.

## Quick Start

```bash
# Run all tests (backend + frontend)
make test

# Run backend tests only
make test-backend

# Run frontend tests only
make test-frontend

# Run backend tests with coverage report
make test-backend-cov
```

---

## Test Suite Overview

### Backend Tests (Python)
- **Location**: `backend/tests/`
- **Tests**: 135+ tests
- **Coverage**: ~80% of shared modules
- **No mocks**: Tests real validation, response formatting, JSON encoding

**Test files:**
- `test_validation.py` - 45 tests (UUID, file size, TTL)
- `test_response.py` - 40+ tests (HTTP responses, CORS)
- `test_json_helper.py` - 30+ tests (DynamoDB Decimal encoding)
- `test_security.py` - 20+ tests (CloudFront origin verification)

### Frontend Tests (JavaScript)
- **Location**: `frontend/tests/`
- **Tests**: 24 tests
- **Coverage**: ~90% of crypto module
- **No mocks**: Tests real AES-256-GCM encryption

**Test files:**
- `crypto.test.js` - 24 tests (encryption, key management, URL encoding)

---

## Backend Testing

### First Time Setup (One-Time)

```bash
cd backend

# Install python3-venv if needed
sudo apt install python3.12-venv

# Virtual environment is created automatically by make command
```

### Running Backend Tests

```bash
# From project root
make test-backend

# Or directly from backend/
cd backend
source venv/bin/activate  # Activate venv if exists
pip install -r requirements-test.txt
pytest tests/ -v
```

### Backend Test Commands

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_validation.py

# Run specific test function
pytest tests/test_validation.py::TestValidateFileId::test_valid_uuid_v4

# Run tests matching pattern
pytest -k "decimal"

# Run with coverage
pytest --cov=shared --cov-report=term-missing

# Generate HTML coverage report
pytest --cov=shared --cov-report=html
# Open: backend/htmlcov/index.html
```

### What Backend Tests Cover

✅ **Validation Logic**
- UUID v4 format checking
- File size limits (0 to 100MB)
- TTL validation (1h, 12h, 24h)
- Edge cases and boundary values
- No sensitive data in error messages

✅ **Response Formatting**
- Success responses (200, 201)
- Error responses (400, 403, 404, 410, 500)
- CORS headers always present
- Decimal handling from DynamoDB
- Unicode and special characters

✅ **JSON Encoding**
- DynamoDB Decimal → int/float conversion
- Nested structures
- Edge cases (0, negative, scientific notation)

✅ **Security**
- CloudFront origin header verification
- Case-insensitive header matching
- Secret validation
- Dev mode handling

---

## Frontend Testing

### Requirements

- Node.js 15+ (has built-in Web Crypto API)
- No npm packages needed (uses Node.js built-in test runner)

### Running Frontend Tests

```bash
# From project root
make test-frontend

# Or directly from frontend/
cd frontend
npm test

# Or with Node.js directly
node --test tests/crypto.test.js

# Watch mode (re-run on changes)
npm run test:watch
```

### What Frontend Tests Cover

✅ **AES-256-GCM Encryption**
- Key generation (256-bit)
- Encryption/decryption round-trip
- Wrong key rejection
- Empty data handling
- Large files (10 MB)
- Unicode text preservation

✅ **IV (Initialization Vector)**
- IV prepended to ciphertext
- IV uniqueness per encryption
- Correct IV length (12 bytes)

✅ **Key Management**
- Key export to raw bytes
- Key import from raw bytes
- Base64 encoding for URLs
- Base64 decoding from URLs
- Key roundtrip (export → import)

✅ **Real-World Scenarios**
- Complete upload/download flow
- Key-in-URL-fragment pattern
- Verification key never sent to server

✅ **Edge Cases**
- Corrupted ciphertext → fails
- Truncated data → fails
- Very short ciphertext → fails

---

## Coverage Reports

### Backend Coverage

```bash
# Generate HTML coverage report
make test-backend-cov

# View in browser
xdg-open backend/htmlcov/index.html
```

**Expected Coverage:**
- `validation.py`: 95%+
- `response.py`: 100%
- `json_helper.py`: 100%
- `security.py`: 60% (CloudFront check only, not reCAPTCHA)

### Frontend Coverage

Frontend tests use Node.js built-in test runner which doesn't have built-in coverage.
For coverage, you can use:

```bash
cd frontend
npm install --save-dev c8
npx c8 node --test tests/*.test.js
```

---

## Test Output Examples

### Backend Success
```
======================== test session starts =========================
collected 135 items

tests/test_validation.py::TestValidateFileId::test_valid_uuid_v4 PASSED
tests/test_validation.py::TestValidateFileId::test_reject_invalid PASSED
tests/test_response.py::TestSuccessResponse::test_basic_success PASSED
tests/test_json_helper.py::TestDecimalEncoder::test_encode_decimal PASSED
...

======================== 135 passed in 0.85s =========================
```

### Frontend Success
```
# tests 24
# suites 7
# pass 24
# fail 0
# cancelled 0
# skipped 0
# todo 0
# duration_ms 165ms
```

---

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  backend-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: |
          cd backend
          python -m venv venv
          source venv/bin/activate
          pip install -r requirements-test.txt

      - name: Run tests
        run: |
          cd backend
          source venv/bin/activate
          pytest --cov=shared --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./backend/coverage.xml

  frontend-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Run tests
        run: |
          cd frontend
          node --test tests/*.test.js
```

---

## What's NOT Tested (Yet)

### Requires DynamoDB (Postponed)
- ❌ File record creation
- ❌ Atomic download (race conditions)
- ❌ Cleanup pagination logic
- ❌ Report abuse counting

### Requires Mocking (Postponed)
- ❌ S3 presigned URL generation
- ❌ reCAPTCHA HTTP verification

These will be added when you decide on DynamoDB testing strategy (LocalStack vs DynamoDB Local).

---

## Troubleshooting

### Backend: "python3-venv not available"
```bash
sudo apt install python3.12-venv
```

### Backend: "Module not found"
```bash
cd backend
source venv/bin/activate
pip install -r requirements-test.txt
```

### Frontend: "Node.js version too old"
```bash
# Need Node.js 15+ for Web Crypto API
node --version

# Update if needed
# Ubuntu: snap install node --classic
```

### Tests pass but coverage fails
```bash
# Make sure pytest-cov is installed
cd backend
source venv/bin/activate
pip install pytest-cov
```

---

## Best Practices

1. **Run tests before committing**
   ```bash
   make test
   ```

2. **Check coverage regularly**
   ```bash
   make test-backend-cov
   ```

3. **Add tests for new features**
   - New validation? → Add to `test_validation.py`
   - New response helper? → Add to `test_response.py`
   - New crypto function? → Add to `crypto.test.js`

4. **Keep tests fast**
   - No external API calls
   - No real AWS services (for now)
   - Total runtime: <3 seconds

5. **No mocks unless necessary**
   - Test real logic
   - Only mock external HTTP calls if needed
   - Never mock internal modules

---

## Test Philosophy

> **"If you're mocking everything, you're testing nothing."**

Our tests focus on:
- ✅ Real business logic
- ✅ Real encryption/decryption
- ✅ Real validation
- ✅ Real JSON encoding
- ✅ Fast execution (<3s total)
- ✅ No external dependencies

This gives us:
- Confidence that code actually works
- Fast feedback loop
- Easy to understand and maintain
- Catches real bugs, not mock bugs

---

## Summary

```bash
# Quick commands
make test              # Run all tests
make test-backend      # Backend only
make test-frontend     # Frontend only
make test-backend-cov  # Backend with coverage

# Test counts
Backend:  135+ tests ✅
Frontend:  24 tests ✅
Total:    159+ tests ✅
Mocks:     0 🎉
```

**All tests passing, zero mocks, real encryption verified!**
