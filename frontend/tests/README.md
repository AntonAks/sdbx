# sdbx Frontend Crypto Tests

**Pure encryption tests with REAL Web Crypto API - NO MOCKS**

## What's Tested

### ✅ AES-256-GCM Encryption (50+ tests)
- Key generation (256-bit)
- Encryption/decryption round-trip
- IV (Initialization Vector) randomness
- Wrong key rejection
- Key export/import
- Base64 URL encoding
- Large files (10 MB)
- Unicode handling
- Edge cases & corrupted data

### ✅ Zero-Knowledge Architecture
- Complete upload → download flow simulation
- Key-in-URL-fragment pattern
- Verification that key never sent to server

## Running Tests

### Requirements
- Node.js 15+ (has built-in Web Crypto API)

### Run Tests
```bash
cd frontend

# Run all tests
npm test

# Run only crypto tests
npm run test:crypto

# Watch mode (re-run on changes)
npm run test:watch

# Or directly with Node.js
node --test tests/crypto.test.js
```

## Test Output Example
```
✔ CryptoModule - Key Generation > should generate a valid AES-256 key (5.2ms)
✔ CryptoModule - Key Generation > should generate different keys each time (2.1ms)
✔ CryptoModule - Encryption/Decryption > should encrypt and decrypt data correctly (3.5ms)
✔ CryptoModule - Encryption/Decryption > should fail decryption with wrong key (2.8ms)
✔ CryptoModule - Encryption/Decryption > should handle large data (10 MB) (125ms)
✔ CryptoModule - IV > should use different IV each time (4.2ms)
✔ CryptoModule - Base64 Conversion > should encrypt/decrypt with base64-converted key (3.1ms)
✔ CryptoModule - Real-World Scenarios > should simulate complete upload/download flow (5.7ms)
...
✔ all tests passed (47 tests, 250ms)
```

## Test Coverage

**Cryptographic Operations:**
- ✅ Key generation (AES-256)
- ✅ Random IV generation (96-bit)
- ✅ AES-GCM encryption
- ✅ AES-GCM decryption
- ✅ Key export (raw bytes)
- ✅ Key import (raw bytes)
- ✅ Base64 encoding for URLs
- ✅ Base64 decoding from URLs

**Data Sizes:**
- ✅ Empty data (0 bytes)
- ✅ Small data (1 byte)
- ✅ Normal data (KB range)
- ✅ Large data (10 MB)

**Security:**
- ✅ Wrong key → decryption fails
- ✅ Corrupted ciphertext → fails
- ✅ Truncated data → fails
- ✅ IV uniqueness per encryption
- ✅ Key never in server requests

**Real-World Flows:**
- ✅ Upload: encrypt → convert key → URL
- ✅ Download: URL → restore key → decrypt
- ✅ Unicode text preservation
- ✅ Binary data integrity

## Why No Mocks?

We use **real Web Crypto API** because:
- ✅ Tests actual encryption strength
- ✅ Catches real crypto bugs
- ✅ Verifies browser compatibility
- ✅ Tests are still fast (<1s total)

## Key Test Scenarios

### 1. Encryption Round-Trip
```javascript
const data = new TextEncoder().encode('Secret');
const key = await CryptoModule.generateKey();

const encrypted = await CryptoModule.encrypt(data.buffer, key);
const decrypted = await CryptoModule.decrypt(encrypted, key);

// ✅ Data perfectly restored
```

### 2. Wrong Key Fails
```javascript
const key1 = await CryptoModule.generateKey();
const key2 = await CryptoModule.generateKey();

const encrypted = await CryptoModule.encrypt(data, key1);

// ❌ Decryption with key2 throws error
await CryptoModule.decrypt(encrypted, key2); // Rejects!
```

### 3. URL Key Flow
```javascript
// Upload
const key = await CryptoModule.generateKey();
const base64 = await CryptoModule.keyToBase64(key);
const url = `https://sdbx.cc/download#file-123#${base64}`;

// Download
const keyFromUrl = url.split('#')[2];
const restoredKey = await CryptoModule.base64ToKey(keyFromUrl);

// ✅ Works perfectly
```

### 4. Large File
```javascript
const tenMB = new Uint8Array(10 * 1024 * 1024);
crypto.getRandomValues(tenMB);

const encrypted = await CryptoModule.encrypt(tenMB.buffer, key);
const decrypted = await CryptoModule.decrypt(encrypted, key);

// ✅ All 10 MB perfectly restored
```

## CI/CD Integration

Add to GitHub Actions:
```yaml
- name: Test Frontend Crypto
  run: |
    cd frontend
    node --test tests/crypto.test.js
```

## Browser Compatibility

Web Crypto API is supported in:
- ✅ Chrome 37+
- ✅ Firefox 34+
- ✅ Safari 11+
- ✅ Edge 79+
- ✅ Node.js 15+

All modern browsers support AES-GCM!
