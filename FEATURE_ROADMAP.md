# sdbx Feature Roadmap

> Planned features for the zero-knowledge file and text sharing service

---

## 📋 Feature List

| # | Feature | Category | Complexity | Status |
|---|---------|----------|------------|--------|
| 1 | Multiple Files / Zip Bundle | Core | Medium | ✅ Done |
| 2 | Custom Expiration Times | UX | Low | ✅ Done |
| 3 | Vault (Password Protection) | Security | Medium | ✅ Done |
| 4 | IP/Geo Restriction | Security | Medium | 📋 Planned |
| 5 | Self-destructing Voice Message | New Content Type | Medium-High | 📋 Planned |
| 6 | Dead Man's Switch | Unique | High | 📋 Planned |
| 7 | Short URLs | UX | Low-Medium | 📋 Planned |

---

## 🏷️ Features by Category

### Core Enhancements
- ✅ **Multiple Files / Zip Bundle** - Upload multiple files as encrypted bundle

### Security
- ✅ **Vault (Password Protection)** - Password-protected multi-access sharing with PBKDF2
- 📋 **IP/Geo Restriction** - Restrict downloads by country or IP range

### UX Improvements
- ✅ **Custom Expiration Times** - Precise expiration (5 min - 7 days) with real-time preview
- 📋 **Short URLs** - Shorter file IDs for cleaner, easier-to-share links

### New Content Types
- 📋 **Self-destructing Voice Message** - Record and share encrypted audio messages

### Unique/Advanced
- 📋 **Dead Man's Switch** - Auto-share files if user doesn't check in within set interval

---

## 📝 Feature Details

### 1. Multiple Files / Zip Bundle ✅
- Client-side zip creation using JSZip
- Encrypt the bundle as single file
- Show file list on download page before commit

### 2. Vault (Password Protection) ✅
- PBKDF2 to derive key from password (100k iterations, SHA-256)
- Double encryption: content with data key, data key with password key
- Password never sent to server (only salt stored)
- Recipient needs link AND password (shared via different channel)
- Multi-access mode: unlimited downloads until expiry
- Supports both files and text secrets

### 3. Custom Expiration Times ✅
- Dropdown selects for minutes/hours/days with predefined values
- Range: 5 minutes to 7 days (manages storage costs)
- Quick presets (1h, 12h, 24h) + custom option
- Real-time expiration preview in user's local timezone
- Backend validates and accepts both preset strings and numeric minutes

### 4. IP/Geo Restriction
- Use MaxMind GeoIP or CloudFront geo headers
- Allowlist/blocklist countries
- Optional IP range restriction for corporate use
- Privacy-preserving: no IP logging, just validation

### 5. Self-destructing Voice Message
- MediaRecorder API in browser
- Encrypt audio blob same as files
- Playback-only on download page (no save button)
- Auto-delete after single play

### 6. Dead Man's Switch
- User sets check-in interval (daily/weekly/monthly)
- System sends reminder to check in
- If missed → auto-share to predefined recipient
- Requires minimal identity (email) while preserving privacy
- Use case: emergency access, digital inheritance

### 7. Short URLs
- Generate 6-8 character unique codes instead of full UUIDs
- Add `short_code` field to DynamoDB record
- Reduces URL length by ~30 characters
- Benefits: easier verbal sharing, cleaner look, better QR codes

---

## 🚀 Implementation Priority

### ✅ Completed
1. Multiple Files / Zip Bundle
2. Custom Expiration Times
3. Vault (Password Protection)

### Quick Wins (Low Complexity)
4. Short URLs

### Medium Effort
5. IP/Geo Restriction

### Larger Features
6. Self-destructing Voice Message
7. Dead Man's Switch

---

## 📊 Legend

| Status | Meaning |
|--------|---------|
| ✅ Done | Implemented and deployed |
| 🚧 In Progress | Currently being developed |
| 📋 Planned | On the roadmap |
| 💡 Idea | Under consideration |

---

*Last updated: January 2026*
