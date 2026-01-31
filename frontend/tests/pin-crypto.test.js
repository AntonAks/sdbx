/**
 * PBKDF2 Key Derivation Tests for PIN Mode
 * Tests deriveKeyFromPassword with extractable parameter
 * NO MOCKS - Uses actual Web Crypto API
 *
 * Run with: node --test tests/pin-crypto.test.js
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { webcrypto } from 'node:crypto';
import { createHash, pbkdf2Sync } from 'node:crypto';

// Polyfill for browser crypto API
global.crypto = webcrypto;
global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
global.atob = (b64) => Buffer.from(b64, 'base64').toString('binary');

// Inline CryptoModule with PBKDF2 support (mirrors frontend/js/crypto.js)
const CryptoModule = (function() {
    const ALGORITHM = 'AES-GCM';
    const KEY_LENGTH = 256;
    const IV_LENGTH = 12;
    const SALT_LENGTH = 16;
    const PBKDF2_ITERATIONS = 100000;

    function generateSalt() {
        return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    }

    async function deriveKeyFromPassword(password, salt, extractable) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: PBKDF2_ITERATIONS,
                hash: 'SHA-256',
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            extractable === true,
            ['encrypt', 'decrypt']
        );
    }

    async function exportKey(key) {
        return crypto.subtle.exportKey('raw', key);
    }

    async function encrypt(data, key) {
        const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
        const ciphertext = await crypto.subtle.encrypt(
            { name: ALGORITHM, iv: iv },
            key,
            data
        );

        const result = new Uint8Array(iv.length + ciphertext.byteLength);
        result.set(iv, 0);
        result.set(new Uint8Array(ciphertext), iv.length);
        return result;
    }

    async function decrypt(data, key) {
        const iv = data.slice(0, IV_LENGTH);
        const ciphertext = data.slice(IV_LENGTH);
        return crypto.subtle.decrypt(
            { name: ALGORITHM, iv: iv },
            key,
            ciphertext
        );
    }

    return {
        generateSalt,
        deriveKeyFromPassword,
        exportKey,
        encrypt,
        decrypt,
        PBKDF2_ITERATIONS,
        SALT_LENGTH,
    };
})();

// Utility: hexToUint8Array (mirrors frontend/js/pin-upload.js)
function hexToUint8Array(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

// Utility: uint8ArrayToHex
function uint8ArrayToHex(arr) {
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}


describe('PBKDF2 Key Derivation - Determinism', () => {
    it('should derive the same key from the same PIN and salt', async () => {
        const pin = '1234';
        const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        const key1 = await CryptoModule.deriveKeyFromPassword(pin, salt, true);
        const key2 = await CryptoModule.deriveKeyFromPassword(pin, salt, true);

        const raw1 = new Uint8Array(await CryptoModule.exportKey(key1));
        const raw2 = new Uint8Array(await CryptoModule.exportKey(key2));

        assert.deepStrictEqual(raw1, raw2, 'Same PIN + same salt should produce identical keys');
    });

    it('should derive different keys from different PINs with the same salt', async () => {
        const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        const key1 = await CryptoModule.deriveKeyFromPassword('1234', salt, true);
        const key2 = await CryptoModule.deriveKeyFromPassword('5678', salt, true);

        const raw1 = new Uint8Array(await CryptoModule.exportKey(key1));
        const raw2 = new Uint8Array(await CryptoModule.exportKey(key2));

        assert.notDeepStrictEqual(raw1, raw2, 'Different PINs should produce different keys');
    });

    it('should derive different keys from the same PIN with different salts', async () => {
        const pin = '9999';
        const salt1 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        const salt2 = new Uint8Array([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);

        const key1 = await CryptoModule.deriveKeyFromPassword(pin, salt1, true);
        const key2 = await CryptoModule.deriveKeyFromPassword(pin, salt2, true);

        const raw1 = new Uint8Array(await CryptoModule.exportKey(key1));
        const raw2 = new Uint8Array(await CryptoModule.exportKey(key2));

        assert.notDeepStrictEqual(raw1, raw2, 'Different salts should produce different keys');
    });
});


describe('PBKDF2 Key Derivation - Key Properties', () => {
    it('should produce a 256-bit (32 byte) key', async () => {
        const pin = '4567';
        const salt = CryptoModule.generateSalt();

        const key = await CryptoModule.deriveKeyFromPassword(pin, salt, true);
        const rawKey = await CryptoModule.exportKey(key);

        assert.strictEqual(rawKey.byteLength, 32, 'Derived key should be 32 bytes (256 bits)');
    });

    it('should produce an AES-GCM key', async () => {
        const pin = '0000';
        const salt = CryptoModule.generateSalt();

        const key = await CryptoModule.deriveKeyFromPassword(pin, salt, true);

        assert.strictEqual(key.type, 'secret', 'Key type should be secret');
        assert.strictEqual(key.algorithm.name, 'AES-GCM', 'Algorithm should be AES-GCM');
        assert.strictEqual(key.algorithm.length, 256, 'Key length should be 256 bits');
    });

    it('should produce a key usable for encrypt and decrypt', async () => {
        const pin = '1111';
        const salt = CryptoModule.generateSalt();

        const key = await CryptoModule.deriveKeyFromPassword(pin, salt, false);

        assert.ok(key.usages.includes('encrypt'), 'Key should support encryption');
        assert.ok(key.usages.includes('decrypt'), 'Key should support decryption');
    });
});


describe('PBKDF2 Key Derivation - Cross-Verification with Node.js', () => {
    it('should match Node.js pbkdf2Sync output with correct parameters', async () => {
        const pin = 'testpin';
        const salt = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160]);

        // Derive key using Web Crypto API (frontend implementation)
        const webCryptoKey = await CryptoModule.deriveKeyFromPassword(pin, salt, true);
        const webCryptoRaw = new Uint8Array(await CryptoModule.exportKey(webCryptoKey));

        // Derive key using Node.js crypto (reference implementation)
        const nodeKey = pbkdf2Sync(pin, Buffer.from(salt), 100000, 32, 'sha256');

        assert.deepStrictEqual(
            webCryptoRaw,
            new Uint8Array(nodeKey),
            'Web Crypto PBKDF2 output should match Node.js pbkdf2Sync'
        );
    });

    it('should match Node.js output for numeric PIN', async () => {
        const pin = '8472';
        const salt = new Uint8Array(16);
        salt.fill(0xAB);

        const webCryptoKey = await CryptoModule.deriveKeyFromPassword(pin, salt, true);
        const webCryptoRaw = new Uint8Array(await CryptoModule.exportKey(webCryptoKey));

        const nodeKey = pbkdf2Sync(pin, Buffer.from(salt), 100000, 32, 'sha256');

        assert.deepStrictEqual(
            webCryptoRaw,
            new Uint8Array(nodeKey),
            'Numeric PIN derivation should match Node.js reference'
        );
    });

    it('should match Node.js output for longer password', async () => {
        const password = 'MySecureVaultPassword123!';
        const salt = crypto.getRandomValues(new Uint8Array(16));

        const webCryptoKey = await CryptoModule.deriveKeyFromPassword(password, salt, true);
        const webCryptoRaw = new Uint8Array(await CryptoModule.exportKey(webCryptoKey));

        const nodeKey = pbkdf2Sync(password, Buffer.from(salt), 100000, 32, 'sha256');

        assert.deepStrictEqual(
            webCryptoRaw,
            new Uint8Array(nodeKey),
            'Long password derivation should match Node.js reference'
        );
    });

    it('should use exactly 100,000 iterations', () => {
        // Verify the constant matches the CLAUDE.md spec
        assert.strictEqual(
            CryptoModule.PBKDF2_ITERATIONS,
            100000,
            'PBKDF2 iterations should be 100,000'
        );
    });
});


describe('PBKDF2 Key Derivation - Extractability', () => {
    it('should produce an extractable key when extractable=true', async () => {
        const pin = '1234';
        const salt = CryptoModule.generateSalt();

        const key = await CryptoModule.deriveKeyFromPassword(pin, salt, true);

        assert.strictEqual(key.extractable, true, 'Key should be extractable');

        // Should be able to export
        const rawKey = await CryptoModule.exportKey(key);
        assert.strictEqual(rawKey.byteLength, 32, 'Exported key should be 32 bytes');
    });

    it('should produce a non-extractable key when extractable=false', async () => {
        const pin = '1234';
        const salt = CryptoModule.generateSalt();

        const key = await CryptoModule.deriveKeyFromPassword(pin, salt, false);

        assert.strictEqual(key.extractable, false, 'Key should not be extractable');

        // Export should throw
        await assert.rejects(
            async () => await CryptoModule.exportKey(key),
            'Should not be able to export non-extractable key'
        );
    });

    it('should produce a non-extractable key by default (no extractable param)', async () => {
        const pin = '1234';
        const salt = CryptoModule.generateSalt();

        // Call without extractable parameter
        const key = await CryptoModule.deriveKeyFromPassword(pin, salt);

        assert.strictEqual(key.extractable, false, 'Default should be non-extractable');
    });

    it('should produce a non-extractable key when extractable=undefined', async () => {
        const pin = '1234';
        const salt = CryptoModule.generateSalt();

        const key = await CryptoModule.deriveKeyFromPassword(pin, salt, undefined);

        assert.strictEqual(key.extractable, false, 'undefined should be treated as non-extractable');
    });

    it('should produce a non-extractable key when extractable=null', async () => {
        const pin = '1234';
        const salt = CryptoModule.generateSalt();

        const key = await CryptoModule.deriveKeyFromPassword(pin, salt, null);

        assert.strictEqual(key.extractable, false, 'null should be treated as non-extractable');
    });

    it('extractable and non-extractable keys should encrypt the same way', async () => {
        const pin = '5555';
        const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        const plaintext = new TextEncoder().encode('Test data for both keys');

        const extractableKey = await CryptoModule.deriveKeyFromPassword(pin, salt, true);
        const nonExtractableKey = await CryptoModule.deriveKeyFromPassword(pin, salt, false);

        // Encrypt with extractable, decrypt with non-extractable (same derived key)
        const encrypted = await CryptoModule.encrypt(plaintext.buffer, extractableKey);
        const decrypted = await CryptoModule.decrypt(encrypted, nonExtractableKey);

        const result = new TextDecoder().decode(decrypted);
        assert.strictEqual(result, 'Test data for both keys', 'Both keys should be functionally identical');
    });
});


describe('hexToUint8Array - Hex Salt Conversion', () => {
    it('should convert a hex string to correct bytes', () => {
        const hex = '0a141e28323c46505a646e78828c96a0';
        const result = hexToUint8Array(hex);

        const expected = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160]);
        assert.deepStrictEqual(result, expected, 'Hex conversion should produce correct bytes');
    });

    it('should handle all-zeros hex string', () => {
        const hex = '00000000000000000000000000000000';
        const result = hexToUint8Array(hex);

        assert.strictEqual(result.length, 16, 'Should produce 16 bytes');
        assert.ok(result.every(b => b === 0), 'All bytes should be zero');
    });

    it('should handle all-FF hex string', () => {
        const hex = 'ffffffffffffffffffffffffffffffff';
        const result = hexToUint8Array(hex);

        assert.strictEqual(result.length, 16, 'Should produce 16 bytes');
        assert.ok(result.every(b => b === 255), 'All bytes should be 255');
    });

    it('should handle uppercase hex', () => {
        const hex = 'AABBCCDD';
        const result = hexToUint8Array(hex);

        const expected = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);
        assert.deepStrictEqual(result, expected, 'Uppercase hex should work');
    });

    it('should round-trip with uint8ArrayToHex', () => {
        const original = new Uint8Array([0, 127, 255, 1, 128, 64, 32, 16, 8, 4, 2, 1, 99, 200, 50, 150]);
        const hex = uint8ArrayToHex(original);
        const restored = hexToUint8Array(hex);

        assert.deepStrictEqual(restored, original, 'Round-trip should preserve bytes');
    });

    it('should produce salt bytes usable for PBKDF2', async () => {
        // Simulate: server stores salt as hex, frontend converts back to bytes
        const originalSalt = CryptoModule.generateSalt();
        const saltHex = uint8ArrayToHex(originalSalt);
        const restoredSalt = hexToUint8Array(saltHex);

        // Both salts should derive the same key
        const pin = '7777';
        const key1 = await CryptoModule.deriveKeyFromPassword(pin, originalSalt, true);
        const key2 = await CryptoModule.deriveKeyFromPassword(pin, restoredSalt, true);

        const raw1 = new Uint8Array(await CryptoModule.exportKey(key1));
        const raw2 = new Uint8Array(await CryptoModule.exportKey(key2));

        assert.deepStrictEqual(raw1, raw2, 'Hex-converted salt should derive the same key');
    });
});


describe('Salt Generation', () => {
    it('should generate a 16-byte salt', () => {
        const salt = CryptoModule.generateSalt();

        assert.ok(salt instanceof Uint8Array, 'Salt should be Uint8Array');
        assert.strictEqual(salt.length, 16, 'Salt should be 16 bytes (128 bits)');
    });

    it('should generate different salts each time', () => {
        const salt1 = CryptoModule.generateSalt();
        const salt2 = CryptoModule.generateSalt();

        assert.notDeepStrictEqual(salt1, salt2, 'Salts should be different');
    });

    it('should match expected salt length constant', () => {
        assert.strictEqual(
            CryptoModule.SALT_LENGTH,
            16,
            'Salt length should be 16 bytes'
        );
    });
});


describe('PBKDF2 - PIN Mode End-to-End Flow', () => {
    it('should simulate complete PIN upload and download flow', async () => {
        // === UPLOAD SIDE ===
        const pin = '4829';
        const originalText = 'This is my secret PIN-protected content!';
        const plaintext = new TextEncoder().encode(originalText);

        // 1. Generate salt
        const salt = CryptoModule.generateSalt();

        // 2. Derive key from PIN
        const encryptionKey = await CryptoModule.deriveKeyFromPassword(pin, salt, false);

        // 3. Encrypt content
        const encrypted = await CryptoModule.encrypt(plaintext.buffer, encryptionKey);

        // 4. Store salt as hex in URL, encrypted content on server
        const saltHex = uint8ArrayToHex(salt);
        const shareUrl = `https://sdbx.cc/download#file-456#${saltHex}#secret.txt#vault`;

        // === DOWNLOAD SIDE ===
        // 5. Parse URL
        const parts = shareUrl.split('#');
        const fileId = parts[1];
        const receivedSaltHex = parts[2];
        const filename = parts[3];
        const mode = parts[4];

        assert.strictEqual(mode, 'vault', 'Should detect vault mode');

        // 6. Convert salt back to bytes
        const receivedSalt = hexToUint8Array(receivedSaltHex);

        // 7. User enters PIN on download page
        const enteredPin = '4829';

        // 8. Derive same key from PIN
        const decryptionKey = await CryptoModule.deriveKeyFromPassword(enteredPin, receivedSalt, false);

        // 9. Decrypt content
        const decrypted = await CryptoModule.decrypt(encrypted, decryptionKey);
        const result = new TextDecoder().decode(decrypted);

        assert.strictEqual(result, originalText, 'PIN-protected content should decrypt correctly');
    });

    it('should fail decryption with wrong PIN', async () => {
        const correctPin = '1234';
        const wrongPin = '9999';
        const salt = CryptoModule.generateSalt();
        const plaintext = new TextEncoder().encode('Secret data');

        // Encrypt with correct PIN
        const encKey = await CryptoModule.deriveKeyFromPassword(correctPin, salt, false);
        const encrypted = await CryptoModule.encrypt(plaintext.buffer, encKey);

        // Try to decrypt with wrong PIN
        const wrongKey = await CryptoModule.deriveKeyFromPassword(wrongPin, salt, false);

        await assert.rejects(
            async () => await CryptoModule.decrypt(encrypted, wrongKey),
            'Decryption with wrong PIN should fail'
        );
    });

    it('should allow multiple downloads with same PIN (vault mode)', async () => {
        const pin = '5555';
        const salt = CryptoModule.generateSalt();
        const plaintext = new TextEncoder().encode('Multi-access content');

        const key = await CryptoModule.deriveKeyFromPassword(pin, salt, false);
        const encrypted = await CryptoModule.encrypt(plaintext.buffer, key);

        // Simulate multiple downloads - each time re-derive the key
        for (let i = 0; i < 3; i++) {
            const downloadKey = await CryptoModule.deriveKeyFromPassword(pin, salt, false);
            const decrypted = await CryptoModule.decrypt(encrypted, downloadKey);
            const result = new TextDecoder().decode(decrypted);
            assert.strictEqual(result, 'Multi-access content', `Download ${i + 1} should succeed`);
        }
    });
});
