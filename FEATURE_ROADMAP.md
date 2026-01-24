# sdbx Feature Roadmap

> Planned features for the zero-knowledge file and text sharing service

---

## 📋 Feature List

| # | Feature | Category | Complexity | Status |
|---|---------|----------|------------|--------|
| 1 | Multiple Files / Zip Bundle | Core | Medium | ✅ Done |
| 2 | Password Protection (Double Encryption) | Security | Medium | 📋 Planned |
| 3 | Custom Expiration Times | UX | Low | 📋 Planned |
| 4 | IP/Geo Restriction | Security | Medium | 📋 Planned |
| 5 | Self-destructing Voice Message | New Content Type | Medium-High | 📋 Planned |
| 6 | Dead Man's Switch | Unique | High | 📋 Planned |
| 7 | Short URLs | UX | Low-Medium | 📋 Planned |

---

## 🏷️ Features by Category

### Core Enhancements
- ✅ **Multiple Files / Zip Bundle** - Upload multiple files as encrypted bundle

### Security
- 📋 **Password Protection (Double Encryption)** - Optional password layer on top of encryption key
- 📋 **IP/Geo Restriction** - Restrict downloads by country or IP range

### UX Improvements
- 📋 **Custom Expiration Times** - Precise expiration (minutes/hours/days) beyond presets
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

### 2. Password Protection (Double Encryption)
- PBKDF2/Argon2 to derive key from password
- Combine with random key for double encryption
- Password never sent to server
- Recipient needs link AND password (shared via different channel)

### 3. Custom Expiration Times
- Time picker UI (minutes/hours/days + specific datetime)
- Max cap (7 days?) to manage storage costs
- Keep quick presets (1h, 12h, 24h) + add custom option

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

### Quick Wins (Low Complexity)
1. Custom Expiration Times
2. Short URLs

### Medium Effort
3. Password Protection
4. IP/Geo Restriction

### Larger Features
5. Self-destructing Voice Message
6. Dead Man's Switch

---

## 📊 Legend

| Status | Meaning |
|--------|---------|
| ✅ Done | Implemented and deployed |
| 🚧 In Progress | Currently being developed |
| 📋 Planned | On the roadmap |
| 💡 Idea | Under consideration |

---

*Last updated: January 2025*
