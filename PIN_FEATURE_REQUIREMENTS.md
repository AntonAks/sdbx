# PIN-Based File Sharing - Functional Requirements

**Version:** 1.0  
**Date:** January 31, 2026  
**Status:** Draft

---

## 1. Overview

### 1.1 Purpose
Add PIN-based file sharing to sdbx as an alternative to URL-based sharing. This feature allows users to share files using a simple 6-digit ID + 4-character PIN combination instead of long URLs with encryption keys.

### 1.2 Use Case
**Scenario:** User wants to send a file from phone to computer
1. User uploads file on phone
2. User sets 4-character PIN
3. System generates 6-digit ID
4. User goes to computer, enters ID
5. System gives 60 seconds to enter PIN
6. User enters PIN and downloads file

### 1.3 Key Benefits
- ✅ **Simpler sharing:** 6 digits easier to type than long URL
- ✅ **Zero-knowledge maintained:** PIN not stored on server
- ✅ **Brute-force protection:** 3 attempts + 12-hour lockout
- ✅ **Time-limited:** 60-second window for PIN entry
- ✅ **Same security:** AES-256-GCM encryption

---

## 2. Functional Requirements

### 2.1 File Upload with PIN

#### FR-2.1.1 PIN Input
- **REQ-001:** User MUST be able to set a custom 4-character PIN during upload
- **REQ-002:** PIN MUST accept alphanumeric characters (a-z, A-Z, 0-9)
- **REQ-003:** PIN MUST be exactly 4 characters long
- **REQ-004:** PIN validation MUST occur before file encryption starts
- **REQ-005:** System MUST show clear error messages for invalid PINs

**Example Valid PINs:**
- `7a2B` ✅
- `1234` ✅
- `AbCd` ✅

**Example Invalid PINs:**
- `12` ❌ (too short)
- `12345` ❌ (too long)
- `12@#` ❌ (special characters)
- `ab cd` ❌ (contains space)

#### FR-2.1.2 File ID Generation
- **REQ-006:** System MUST generate a unique 6-digit numeric ID for each upload
- **REQ-007:** File ID MUST be randomly generated (not sequential)
- **REQ-008:** File ID collision MUST be prevented (retry generation if exists)
- **REQ-009:** File ID MUST be displayed prominently to user after upload
- **REQ-010:** File ID MUST be valid for 24 hours maximum (based on selected TTL)

**Example File IDs:**
- `482973` ✅
- `000001` ✅
- `999999` ✅

#### FR-2.1.3 Encryption Key Derivation
- **REQ-011:** Encryption key MUST be derived from PIN using PBKDF2-SHA256
- **REQ-012:** System MUST generate unique random salt (32 bytes) for each upload
- **REQ-013:** Salt MUST be stored in database for later key derivation
- **REQ-014:** Key derivation MUST use minimum 100,000 iterations
- **REQ-015:** Final encryption key MUST be 256-bit AES-GCM compatible

#### FR-2.1.4 PIN Storage (Security)
- **REQ-016:** Original PIN MUST NOT be stored in database
- **REQ-017:** PIN hash MUST be stored for verification (SHA-256(PIN + salt))
- **REQ-018:** PIN MUST NOT be transmitted in upload response
- **REQ-019:** PIN MUST NOT appear in server logs

#### FR-2.1.5 Upload Response
- **REQ-020:** Upload response MUST include:
  - 6-digit file ID
  - Upload URL (S3 presigned)
  - Expiration timestamp
- **REQ-021:** Upload response MUST NOT include:
  - PIN (user already knows it)
  - Salt (only needed for download)
  - PIN hash

---

### 2.2 Download Initiation (File ID Entry)

#### FR-2.2.1 File ID Input
- **REQ-022:** User MUST be able to enter 6-digit file ID on download page
- **REQ-023:** Input MUST validate format (exactly 6 numeric digits)
- **REQ-024:** System MUST provide clear error for invalid format
- **REQ-025:** System MUST check if file ID exists in database

#### FR-2.2.2 File Availability Checks
Before starting session, system MUST verify:
- **REQ-026:** File exists (ID found in database)
- **REQ-027:** File has not expired (TTL check)
- **REQ-028:** File has not been downloaded yet
- **REQ-029:** File is not currently locked (brute-force protection)

#### FR-2.2.3 Lock Status Check
- **REQ-030:** If file is locked, system MUST return error with remaining time
- **REQ-031:** Error message MUST show hours remaining until unlock
- **REQ-032:** User MUST NOT be able to bypass lock by any means

**Example:** 
```
"File is locked. Try again in 8 hours"
```

#### FR-2.2.4 Session Creation
- **REQ-033:** System MUST create a 60-second session after valid ID entry
- **REQ-034:** Session start timestamp MUST be recorded in database
- **REQ-035:** Session expiration timestamp MUST be calculated (start + 60 seconds)
- **REQ-036:** Session MUST be single-use (new ID entry creates new session)

#### FR-2.2.5 Session Response
- **REQ-037:** Response MUST include:
  - Success message
  - Session expiration timestamp
  - Remaining attempts count (3, 2, 1, or 0)
- **REQ-038:** Response MUST NOT include:
  - Salt (only after correct PIN)
  - Download URL
  - Any file metadata

---

### 2.3 PIN Entry and Verification

#### FR-2.3.1 60-Second Timer
- **REQ-039:** User MUST enter PIN within 60 seconds of ID entry
- **REQ-040:** Frontend MUST display countdown timer (seconds remaining)
- **REQ-041:** Timer MUST turn red in last 10 seconds
- **REQ-042:** After 60 seconds, session MUST expire automatically
- **REQ-043:** Backend MUST reject PIN submissions after session expiration
- **REQ-044:** User MUST be able to start new session by re-entering ID

#### FR-2.3.2 PIN Validation
- **REQ-045:** System MUST verify PIN format (4 alphanumeric characters)
- **REQ-046:** PIN verification MUST be case-sensitive
- **REQ-047:** System MUST hash submitted PIN with stored salt
- **REQ-048:** System MUST compare hashed PIN with stored PIN hash
- **REQ-049:** Verification MUST be constant-time to prevent timing attacks

#### FR-2.3.3 Attempt Tracking
- **REQ-050:** Each file MUST have 3 PIN entry attempts
- **REQ-051:** Counter MUST decrement after each incorrect PIN
- **REQ-052:** Counter MUST NOT reset until successful download or expiration
- **REQ-053:** Correct PIN MUST NOT decrement attempt counter

#### FR-2.3.4 Incorrect PIN Response
- **REQ-054:** System MUST return clear error message for incorrect PIN
- **REQ-055:** Error MUST include remaining attempts count
- **REQ-056:** After each failed attempt, updated count MUST be persisted to database

**Example Responses:**
```
Attempt 1 failed: "Incorrect PIN. 2 attempts left"
Attempt 2 failed: "Incorrect PIN. 1 attempt left"
Attempt 3 failed: "Incorrect PIN. File locked for 12 hours"
```

#### FR-2.3.5 Lockout After 3 Failed Attempts
- **REQ-057:** After 3 incorrect PIN entries, file MUST be locked
- **REQ-058:** Lock duration MUST be exactly 12 hours
- **REQ-059:** Lock timestamp MUST be calculated from last failed attempt
- **REQ-060:** Lock MUST persist in database (locked_until field)
- **REQ-061:** During lock period, ID entry MUST fail immediately
- **REQ-062:** After lock expiration, attempts counter MUST reset to 3

#### FR-2.3.6 Correct PIN Response
- **REQ-063:** On correct PIN, system MUST return:
  - Salt (for client-side key derivation)
  - S3 presigned download URL
  - File size
  - Success message
- **REQ-064:** Session timer MUST stop after correct PIN
- **REQ-065:** File MUST be reserved for download (existing atomic operation)

---

### 2.4 File Download and Decryption

#### FR-2.4.1 Client-Side Key Derivation
- **REQ-066:** Frontend MUST derive encryption key from PIN + salt
- **REQ-067:** Key derivation MUST use same PBKDF2 parameters as upload:
  - Algorithm: PBKDF2-SHA256
  - Iterations: 100,000
  - Key length: 256 bits
- **REQ-068:** Derived key MUST match original upload key

#### FR-2.4.2 File Download
- **REQ-069:** Frontend MUST download encrypted file from S3 presigned URL
- **REQ-070:** Download progress MUST be displayed to user
- **REQ-071:** Network errors MUST be handled gracefully

#### FR-2.4.3 File Decryption
- **REQ-072:** Frontend MUST decrypt file using derived AES-GCM key
- **REQ-073:** Decryption MUST use existing CryptoModule
- **REQ-074:** Decryption progress MUST be displayed to user
- **REQ-075:** Decryption errors MUST show clear error message

#### FR-2.4.4 Download Confirmation
- **REQ-076:** After successful decryption, frontend MUST call confirm endpoint
- **REQ-077:** Confirmation MUST mark file as downloaded in database
- **REQ-078:** File MUST be deleted from S3 after confirmation
- **REQ-079:** Link MUST become invalid after confirmation

---

### 2.5 Security Requirements

#### FR-2.5.1 Zero-Knowledge Architecture
- **REQ-080:** Server MUST NOT have access to original PIN at any time
- **REQ-081:** Server MUST NOT be able to derive encryption key without PIN
- **REQ-082:** Server MUST NOT be able to decrypt uploaded files
- **REQ-083:** Encryption key MUST only exist on client side
- **REQ-084:** Salt alone MUST NOT allow key derivation without PIN

#### FR-2.5.2 Brute-Force Protection
- **REQ-085:** File ID space MUST be large enough (1,000,000 combinations)
- **REQ-086:** PIN space MUST be large enough (1,679,616 combinations with 4 alphanumeric)
- **REQ-087:** Combined entropy MUST prevent practical brute-force attacks
- **REQ-088:** 3-attempt limit MUST make PIN guessing infeasible
- **REQ-089:** 12-hour lockout MUST prevent automated retry attacks

#### FR-2.5.3 Rate Limiting
- **REQ-090:** Session initiation endpoint MUST have rate limiting
- **REQ-091:** PIN verification endpoint MUST have rate limiting
- **REQ-092:** Rate limits MUST prevent automated attacks
- **REQ-093:** Rate limiting MUST use CloudFront + reCAPTCHA

#### FR-2.5.4 Data Privacy
- **REQ-094:** PIN MUST NOT appear in CloudWatch logs
- **REQ-095:** PIN MUST NOT appear in access logs
- **REQ-096:** IP addresses MUST be hashed (existing requirement)
- **REQ-097:** File metadata MUST NOT include PIN hash in responses

---

### 2.6 Data Model Requirements

#### FR-2.6.1 DynamoDB Schema Extensions
Existing fields remain unchanged. New fields:

```python
{
    # Existing fields (unchanged)
    "file_id": "482973",           # NOW: 6-digit numeric ID
    "s3_key": "files/482973",
    "file_size": 2500000,
    "created_at": "2026-01-31T...",
    "expires_at": 1738368000,
    "downloaded": False,
    "ip_hash": "sha256...",
    
    # NEW: PIN-based authentication
    "pin_hash": "sha256(PIN+salt)",  # REQ-017
    "salt": "64char_hex_string",     # REQ-013
    
    # NEW: Session management
    "session_started": 1738360000,   # REQ-034 (timestamp or null)
    "session_expires": 1738360060,   # REQ-035 (timestamp or null)
    
    # NEW: Attempt tracking
    "attempts_left": 3,              # REQ-050 (3, 2, 1, or 0)
    
    # NEW: Lockout
    "locked_until": 1738403600,      # REQ-060 (timestamp or null)
}
```

#### FR-2.6.2 Field Constraints
- **REQ-098:** file_id MUST be 6-digit string (stored as string, not number)
- **REQ-099:** pin_hash MUST be 64-character hex string (SHA-256)
- **REQ-100:** salt MUST be 64-character hex string (32 bytes)
- **REQ-101:** session_expires MUST be Unix timestamp (integer)
- **REQ-102:** attempts_left MUST be integer (0-3)
- **REQ-103:** locked_until MUST be Unix timestamp or null

---

### 2.7 API Endpoints

#### FR-2.7.1 Upload Initialization (Modified)
```
POST /upload/init

Request:
{
    "file_size": 2500000,
    "pin": "7a2B",           // NEW: User's 4-char PIN
    "ttl": "24h",
    "recaptcha_token": "..."
}

Response (Success):
{
    "file_id": "482973",     // NEW: 6-digit ID instead of UUID
    "upload_url": "https://s3...",
    "expires_at": 1738368000
}

Response (Error):
{
    "error": "PIN must be exactly 4 characters"
}
```

**Requirements:**
- **REQ-104:** Endpoint MUST validate PIN format
- **REQ-105:** Endpoint MUST generate unique 6-digit ID
- **REQ-106:** Endpoint MUST create salt and hash PIN
- **REQ-107:** Endpoint MUST initialize attempts_left to 3

---

#### FR-2.7.2 Download Session Initiation (NEW)
```
POST /download/initiate

Request:
{
    "file_id": "482973"
}

Response (Success):
{
    "message": "Session started. Enter PIN within 60 seconds",
    "session_expires": 1738360060,
    "attempts_left": 3
}

Response (Locked):
{
    "error": "File is locked. Try again in 8 hours"
}

Response (Expired):
{
    "error": "File has expired"
}

Response (Not Found):
{
    "error": "File not found"
}
```

**Requirements:**
- **REQ-108:** Endpoint MUST validate 6-digit format
- **REQ-109:** Endpoint MUST check file status (exists, not expired, not downloaded, not locked)
- **REQ-110:** Endpoint MUST create 60-second session
- **REQ-111:** Endpoint MUST update session timestamps in database

---

#### FR-2.7.3 PIN Verification & Download (Modified)
```
POST /download

Request:
{
    "file_id": "482973",
    "pin": "7a2B"
}

Response (Success - Correct PIN):
{
    "download_url": "https://s3...",
    "salt": "abc123...",     // For client key derivation
    "file_size": 2500000
}

Response (Incorrect PIN - Attempts Left):
{
    "error": "Incorrect PIN. 2 attempts left"
}

Response (Incorrect PIN - Locked):
{
    "error": "Incorrect PIN. File locked for 12 hours"
}

Response (Session Expired):
{
    "error": "Session expired. Please enter file ID again"
}
```

**Requirements:**
- **REQ-112:** Endpoint MUST verify active session (not expired)
- **REQ-113:** Endpoint MUST verify attempts_left > 0
- **REQ-114:** Endpoint MUST hash PIN with salt and compare
- **REQ-115:** Endpoint MUST decrement attempts on failure
- **REQ-116:** Endpoint MUST lock file after 3 failures
- **REQ-117:** Endpoint MUST return salt only on success

---

### 2.8 UI/UX Requirements

#### FR-2.8.1 Upload Page
- **REQ-118:** PIN input field MUST be clearly labeled
- **REQ-119:** PIN input MUST show character count (X/4)
- **REQ-120:** PIN input MUST provide real-time validation feedback
- **REQ-121:** After upload, file ID MUST be displayed in large, readable font
- **REQ-122:** After upload, page MUST show reminder to save both ID and PIN
- **REQ-123:** After upload, page MUST NOT show copy button (user already has PIN)

**Mockup:**
```
┌──────────────────────────────────────┐
│  Set Your PIN                        │
│  ┌─────────┐                         │
│  │ ____    │  (4 characters)         │
│  └─────────┘                         │
│                                      │
│  [Encrypt & Upload]                  │
└──────────────────────────────────────┘

After upload:
┌──────────────────────────────────────┐
│  ✅ File Uploaded!                   │
│                                      │
│        Your File ID:                 │
│       ┏━━━━━━━━━━┓                   │
│       ┃  482973  ┃                   │
│       ┗━━━━━━━━━━┛                   │
│                                      │
│  🔐 Remember your PIN: ****          │
│  📅 Expires in: 24 hours             │
└──────────────────────────────────────┘
```

#### FR-2.8.2 Download Page - Step 1 (ID Entry)
- **REQ-124:** Input field MUST be clearly labeled "Enter File ID"
- **REQ-125:** Input MUST only accept 6 numeric digits
- **REQ-126:** Input MUST auto-focus on page load
- **REQ-127:** Continue button MUST be disabled until 6 digits entered

**Mockup:**
```
┌──────────────────────────────────────┐
│  Download Your File                  │
│                                      │
│  Step 1: Enter File ID               │
│  ┌────────┐                          │
│  │ ______ │  [Continue]              │
│  └────────┘                          │
│  (6 digits)                          │
└──────────────────────────────────────┘
```

#### FR-2.8.3 Download Page - Step 2 (PIN Entry)
- **REQ-128:** Timer MUST be prominently displayed
- **REQ-129:** Timer MUST update every second
- **REQ-130:** Timer MUST turn red at 10 seconds remaining
- **REQ-131:** Attempts remaining MUST be clearly shown
- **REQ-132:** PIN input MUST be 4-character alphanumeric
- **REQ-133:** Error messages MUST be clear and actionable

**Mockup:**
```
┌──────────────────────────────────────┐
│  ⏱️  Time Remaining: 47 seconds      │
│  🎯 Attempts Left: 3                 │
│                                      │
│  Enter PIN:                          │
│  ┌──────┐                            │
│  │ ____ │  [Download]                │
│  └──────┘                            │
│  (4 characters)                      │
└──────────────────────────────────────┘

After incorrect PIN:
┌──────────────────────────────────────┐
│  ❌ Incorrect PIN                    │
│  🎯 2 attempts left                  │
│                                      │
│  Enter PIN:                          │
│  ┌──────┐                            │
│  │ ____ │  [Download]                │
│  └──────┘                            │
└──────────────────────────────────────┘

After 3 failures:
┌──────────────────────────────────────┐
│  🔒 File Locked                      │
│                                      │
│  Too many incorrect attempts.        │
│  Try again in 12 hours.              │
│                                      │
│  [Return to Home]                    │
└──────────────────────────────────────┘
```

---

### 2.9 Error Handling

#### FR-2.9.1 Upload Errors
- **REQ-134:** Invalid PIN format → "PIN must be exactly 4 alphanumeric characters"
- **REQ-135:** ID collision (rare) → Retry generation automatically
- **REQ-136:** Network error → "Upload failed. Please try again"

#### FR-2.9.2 Download Errors
- **REQ-137:** Invalid ID format → "File ID must be 6 digits"
- **REQ-138:** File not found → "File not found or has expired"
- **REQ-139:** File already downloaded → "File has already been downloaded"
- **REQ-140:** File locked → "File is locked. Try again in X hours"
- **REQ-141:** Session expired → "Session expired. Please enter file ID again"
- **REQ-142:** Incorrect PIN → "Incorrect PIN. X attempts left"

---

### 2.10 Performance Requirements

#### FR-2.10.1 Response Times
- **REQ-143:** Upload initialization MUST respond within 2 seconds
- **REQ-144:** Session creation MUST respond within 1 second
- **REQ-145:** PIN verification MUST respond within 1 second
- **REQ-146:** Key derivation (client) MUST complete within 3 seconds

#### FR-2.10.2 Scalability
- **REQ-147:** System MUST support 1000 concurrent sessions
- **REQ-148:** Database queries MUST use indexed fields (file_id)
- **REQ-149:** Session cleanup MUST run automatically (expired sessions)

---

### 2.11 Backward Compatibility

#### FR-2.11.1 Existing URL-Based Sharing
- **REQ-150:** Existing URL-based file sharing MUST continue to work
- **REQ-151:** Users MUST be able to choose between PIN and URL methods
- **REQ-152:** Both methods MUST use same encryption (AES-256-GCM)
- **REQ-153:** Database MUST support both URL-based and PIN-based records

#### FR-2.11.2 Database Migration
- **REQ-154:** New fields MUST be optional (nullable) for existing records
- **REQ-155:** Existing records MUST continue to work without new fields
- **REQ-156:** Migration MUST be zero-downtime

---

### 2.12 Testing Requirements

#### FR-2.12.1 Unit Tests
- **REQ-157:** Test PIN validation logic
- **REQ-158:** Test 6-digit ID generation (uniqueness)
- **REQ-159:** Test key derivation (PBKDF2)
- **REQ-160:** Test PIN hash comparison
- **REQ-161:** Test attempt decrement logic
- **REQ-162:** Test lockout logic (12 hours)
- **REQ-163:** Test session expiration (60 seconds)

#### FR-2.12.2 Integration Tests
- **REQ-164:** Test complete upload flow with PIN
- **REQ-165:** Test complete download flow (ID → PIN → file)
- **REQ-166:** Test failed PIN attempts → lockout
- **REQ-167:** Test session timeout → retry flow
- **REQ-168:** Test concurrent downloads (same file ID)

#### FR-2.12.3 Security Tests
- **REQ-169:** Verify PIN not in logs
- **REQ-170:** Verify PIN not in responses
- **REQ-171:** Verify key not derivable without PIN
- **REQ-172:** Verify timing attack resistance
- **REQ-173:** Verify brute-force protection

---

## 3. Non-Functional Requirements

### 3.1 Security
- All cryptographic operations MUST follow industry standards
- Zero-knowledge architecture MUST be maintained
- No degradation of existing security posture

### 3.2 Usability
- PIN-based flow MUST be simpler than URL-based for mobile→desktop use case
- Error messages MUST be clear and actionable
- UI MUST be responsive on all devices

### 3.3 Performance
- Response times MUST not degrade existing performance
- Database queries MUST be optimized (indexes)
- Client-side operations MUST not block UI

### 3.4 Reliability
- 99.9% uptime for download endpoints
- Graceful degradation on errors
- Automatic cleanup of expired sessions

### 3.5 Maintainability
- Code MUST follow existing project patterns
- New code MUST have test coverage >80%
- Documentation MUST be updated

---

## 4. Out of Scope (Future Considerations)

The following are **NOT** part of this initial implementation:

- ❌ Custom expiration times for PIN-based uploads
- ❌ PIN reset/recovery mechanism
- ❌ Multiple download attempts with same PIN
- ❌ Admin dashboard for locked files
- ❌ Email/SMS notifications
- ❌ QR code generation for ID+PIN
- ❌ PIN strength meter
- ❌ Biometric authentication
- ❌ Two-factor authentication

---

## 5. Acceptance Criteria

### 5.1 Upload Flow
- ✅ User can set 4-character PIN
- ✅ System generates unique 6-digit ID
- ✅ File is encrypted with PIN-derived key
- ✅ ID is displayed to user after upload

### 5.2 Download Flow
- ✅ User can enter 6-digit ID
- ✅ System creates 60-second session
- ✅ Timer counts down visibly
- ✅ User can enter PIN within time limit
- ✅ File downloads and decrypts on correct PIN

### 5.3 Security
- ✅ 3 incorrect PINs → 12-hour lockout
- ✅ PIN never stored or logged
- ✅ Server cannot decrypt without PIN
- ✅ Encryption key only exists client-side

### 5.4 Error Handling
- ✅ Clear messages for all error states
- ✅ Graceful handling of session timeout
- ✅ Lock countdown displayed correctly

---

## 6. Implementation Phases

### Phase 1: Backend (Week 1)
- Database schema updates
- New Lambda functions (initiate, verify)
- Modified upload_init Lambda
- Unit tests

### Phase 2: Frontend (Week 2)
- Upload page PIN input
- Download page step 1 (ID entry)
- Download page step 2 (PIN + timer)
- Integration tests

### Phase 3: Testing & Deployment (Week 3)
- End-to-end testing
- Security audit
- Performance testing
- Documentation
- Staged rollout (dev → prod)

---

## 7. Success Metrics

### 7.1 Usage Metrics
- % of uploads using PIN vs URL
- Average time to download (ID→PIN→file)
- Failed PIN attempts rate

### 7.2 Security Metrics
- Number of files locked (brute-force attempts)
- Average session duration
- PIN retry patterns

### 7.3 Performance Metrics
- Upload response time (p95)
- Download response time (p95)
- Key derivation time (client)

---

## 8. Risks and Mitigations

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| ID collisions | Low | High | Retry generation, monitor collisions |
| Brute-force attacks | Medium | High | 3-attempt limit, 12h lockout, rate limiting |
| Session timeout too short | Medium | Medium | User testing, adjustable timeout |
| Key derivation slow on old devices | Low | Medium | Performance testing, show progress |
| Users forget PIN | High | Low | Education, "no recovery" warning |

---

## 9. Dependencies

### 9.1 Technical Dependencies
- PBKDF2 support in Web Crypto API (✅ Available)
- SHA-256 hashing (✅ Available)
- DynamoDB conditional updates (✅ Available)
- CloudFront rate limiting (✅ Available)

### 9.2 External Dependencies
- None (fully self-contained feature)

---

## 10. Documentation Updates Required

- ✅ README.md - Add PIN-based flow description
- ✅ API documentation - New endpoints
- ✅ User guide - How to use PIN feature
- ✅ Security documentation - PIN derivation explanation
- ✅ Architecture diagram - Update with new flows

---

## 11. Appendix

### A. Cryptographic Specifications

**Key Derivation:**
```
salt = random(32 bytes)
pin_hash = SHA256(PIN + salt)
encryption_key = PBKDF2-SHA256(
    password = PIN,
    salt = salt,
    iterations = 100000,
    keylen = 32 bytes
)
```

**Encryption:**
```
algorithm = AES-256-GCM
iv = random(12 bytes)
ciphertext = AES-GCM-ENCRYPT(
    plaintext = file_data,
    key = encryption_key,
    iv = iv
)
output = iv || ciphertext
```

### B. Database Indexes

Required indexes for performance:
```
Primary Key: file_id (existing)
GSI 1: expires_at (for cleanup - existing)
GSI 2: locked_until (for lock expiration queries - NEW)
```

### C. Example User Journey

**Mobile Upload:**
1. Open sdbx.cc on phone
2. Select file "vacation.jpg" (2.5 MB)
3. Enter PIN: `7a2B`
4. Tap "Upload"
5. See ID: `482973`
6. Remember: "482973" and "7a2B"

**Desktop Download:**
1. Open sdbx.cc on computer
2. Enter ID: `482973`
3. Click "Continue"
4. See timer: "60 seconds"
5. Enter PIN: `7a2B`
6. Click "Download"
7. File saves as "vacation.jpg"

---

**End of Requirements Document**
