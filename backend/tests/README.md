# sdbx Backend Tests

Pure unit tests with **NO MOCKS** - testing real business logic.

## Setup

### Option 1: Virtual Environment (Recommended)
```bash
cd backend

# Install python3-venv if needed
sudo apt install python3.12-venv

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements-test.txt
```

### Option 2: System-wide (Not Recommended)
```bash
cd backend
pip install --break-system-packages pytest pytest-cov boto3
```

## Running Tests

### Run all tests
```bash
cd backend
pytest
```

### Run with coverage report
```bash
pytest --cov=shared --cov-report=term-missing
```

### Run only specific test file
```bash
pytest tests/test_validation.py
pytest tests/test_response.py
pytest tests/test_json_helper.py
pytest tests/test_security.py
```

### Run tests matching a pattern
```bash
pytest -k "test_valid"  # Only tests with "test_valid" in name
pytest -k "Decimal"     # Only tests related to Decimal
```

### Run with verbose output
```bash
pytest -v
```

### Run only unit tests (default - all current tests)
```bash
pytest -m unit
```

## Test Coverage

Current test files:
- ✅ `test_validation.py` - File ID, file size, TTL validation (45 tests)
- ✅ `test_response.py` - Response formatting, CORS headers (40+ tests)
- ✅ `test_json_helper.py` - Decimal encoding for DynamoDB (30+ tests)
- ✅ `test_security.py` - CloudFront origin verification (20+ tests)

**Total: 135+ tests, 0 mocks**

## What's Tested

### ✅ Fully Tested (No Mocks)
- Input validation (file_id, file_size, ttl)
- Response formatting (success, error, status codes)
- JSON serialization (Decimal handling)
- CORS headers
- CloudFront origin verification
- Error message sanitization
- Edge cases and boundary conditions

### 🚧 Not Yet Tested (Requires DynamoDB)
- File record creation
- Atomic download (race conditions)
- Cleanup pagination
- Report abuse counting

### 🚧 Not Yet Tested (Requires HTTP Mocking)
- reCAPTCHA verification (calls Google API)

## Test Philosophy

**We avoid heavy mocking:**
- ❌ Don't mock internal modules
- ❌ Don't mock business logic
- ✅ Test real validation logic
- ✅ Test real response formatting
- ✅ Test real JSON encoding
- ✅ Only mock external HTTP calls (when necessary)

## Coverage Goals

- Current: **~80% of shared/ modules** (validation, response, json_helper, security)
- Target: **90%+ coverage** after adding DynamoDB integration tests

## HTML Coverage Report

After running tests with coverage:
```bash
pytest --cov=shared --cov-report=html
```

Open the report:
```bash
xdg-open htmlcov/index.html
```

## CI/CD Integration

Add to GitHub Actions:
```yaml
- name: Run tests
  run: |
    cd backend
    pip install -r requirements-test.txt
    pytest --cov=shared --cov-report=xml

- name: Upload coverage
  uses: codecov/codecov-action@v3
  with:
    files: ./backend/coverage.xml
```
