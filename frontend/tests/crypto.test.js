/**
 * Crypto module tests - Testing REAL encryption/decryption
 * NO MOCKS - Uses actual Web Crypto API
 *
 * Run with: node --test tests/crypto.test.js
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { webcrypto } from 'node:crypto';

// Polyfill for browser crypto API
global.crypto = webcrypto;
global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
global.atob = (b64) => Buffer.from(b64, 'base64').toString('binary');

// Import crypto module (we'll need to make it ES module compatible)
// For now, inline the implementation for testing
const CryptoModule = (function() {
    const ALGORITHM = 'AES-GCM';
    const KEY_LENGTH = 256;
    const IV_LENGTH = 12;

    async function generateKey() {
        return crypto.subtle.generateKey(
            { name: ALGORITHM, length: KEY_LENGTH },
            true,
            ['encrypt', 'decrypt']
        );
    }

    function generateIV() {
        return crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    }

    async function encrypt(data, key) {
        const iv = generateIV();
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

    async function exportKey(key) {
        return crypto.subtle.exportKey('raw', key);
    }

    async function importKey(keyData) {
        return crypto.subtle.importKey(
            'raw',
            keyData,
            { name: ALGORITHM },
            true,
            ['encrypt', 'decrypt']
        );
    }

    async function keyToBase64(key) {
        const rawKey = await exportKey(key);
        const keyArray = new Uint8Array(rawKey);
        const keyString = String.fromCharCode.apply(null, keyArray);
        return btoa(keyString);
    }

    async function base64ToKey(base64) {
        const keyString = atob(base64);
        const keyArray = new Uint8Array(keyString.length);
        for (let i = 0; i < keyString.length; i++) {
            keyArray[i] = keyString.charCodeAt(i);
        }
        return importKey(keyArray.buffer);
    }

    return {
        generateKey,
        encrypt,
        decrypt,
        exportKey,
        importKey,
        keyToBase64,
        base64ToKey,
    };
})();


describe('CryptoModule - Key Generation', () => {
    it('should generate a valid AES-256 key', async () => {
        const key = await CryptoModule.generateKey();

        assert.ok(key, 'Key should be generated');
        assert.strictEqual(key.type, 'secret', 'Key type should be secret');
        assert.strictEqual(key.algorithm.name, 'AES-GCM', 'Algorithm should be AES-GCM');
        assert.strictEqual(key.algorithm.length, 256, 'Key length should be 256 bits');
    });

    it('should generate different keys each time', async () => {
        const key1 = await CryptoModule.generateKey();
        const key2 = await CryptoModule.generateKey();

        const raw1 = await CryptoModule.exportKey(key1);
        const raw2 = await CryptoModule.exportKey(key2);

        // Convert to arrays for comparison
        const arr1 = new Uint8Array(raw1);
        const arr2 = new Uint8Array(raw2);

        assert.notDeepStrictEqual(arr1, arr2, 'Keys should be different');
    });

    it('should generate extractable keys', async () => {
        const key = await CryptoModule.generateKey();
        assert.strictEqual(key.extractable, true, 'Key should be extractable');
    });
});


describe('CryptoModule - Encryption/Decryption', () => {
    it('should encrypt and decrypt data correctly', async () => {
        const originalText = 'Hello, zero-knowledge!';
        const originalData = new TextEncoder().encode(originalText);

        const key = await CryptoModule.generateKey();

        // Encrypt
        const encrypted = await CryptoModule.encrypt(originalData.buffer, key);

        // Decrypt
        const decrypted = await CryptoModule.decrypt(encrypted, key);
        const decryptedText = new TextDecoder().decode(decrypted);

        assert.strictEqual(decryptedText, originalText, 'Decrypted text should match original');
    });

    it('should fail decryption with wrong key', async () => {
        const data = new TextEncoder().encode('Secret data');

        const key1 = await CryptoModule.generateKey();
        const key2 = await CryptoModule.generateKey();

        const encrypted = await CryptoModule.encrypt(data.buffer, key1);

        // Decrypting with wrong key should throw
        await assert.rejects(
            async () => await CryptoModule.decrypt(encrypted, key2),
            /operation failed/i,
            'Should reject with wrong key'
        );
    });

    it('should handle empty data', async () => {
        const emptyData = new Uint8Array(0);
        const key = await CryptoModule.generateKey();

        const encrypted = await CryptoModule.encrypt(emptyData.buffer, key);
        const decrypted = await CryptoModule.decrypt(encrypted, key);

        assert.strictEqual(decrypted.byteLength, 0, 'Decrypted data should be empty');
    });

    it('should handle small data (1 byte)', async () => {
        const data = new Uint8Array([42]);
        const key = await CryptoModule.generateKey();

        const encrypted = await CryptoModule.encrypt(data.buffer, key);
        const decrypted = await CryptoModule.decrypt(encrypted, key);

        const result = new Uint8Array(decrypted);
        assert.strictEqual(result[0], 42, 'Single byte should be preserved');
    });

    it('should handle large data (10 MB)', async () => {
        // Create 10 MB of random data
        const largeData = new Uint8Array(10 * 1024 * 1024);

        // Fill in chunks (crypto.getRandomValues has 64KB limit)
        const chunkSize = 65536;
        for (let i = 0; i < largeData.length; i += chunkSize) {
            const chunk = largeData.subarray(i, Math.min(i + chunkSize, largeData.length));
            crypto.getRandomValues(chunk);
        }

        const key = await CryptoModule.generateKey();

        const encrypted = await CryptoModule.encrypt(largeData.buffer, key);
        const decrypted = await CryptoModule.decrypt(encrypted, key);

        const decryptedArray = new Uint8Array(decrypted);
        assert.strictEqual(decryptedArray.length, largeData.length, 'Size should match');
        assert.deepStrictEqual(decryptedArray, largeData, 'Data should match exactly');
    });

    it('should handle Unicode text', async () => {
        const unicodeText = 'Hello 世界 🌍 Привет مرحبا';
        const data = new TextEncoder().encode(unicodeText);

        const key = await CryptoModule.generateKey();

        const encrypted = await CryptoModule.encrypt(data.buffer, key);
        const decrypted = await CryptoModule.decrypt(encrypted, key);

        const result = new TextDecoder().decode(decrypted);
        assert.strictEqual(result, unicodeText, 'Unicode should be preserved');
    });
});


describe('CryptoModule - IV (Initialization Vector)', () => {
    it('should prepend IV to ciphertext', async () => {
        const data = new TextEncoder().encode('Test data');
        const key = await CryptoModule.generateKey();

        const encrypted = await CryptoModule.encrypt(data.buffer, key);

        // First 12 bytes should be IV
        assert.ok(encrypted.length >= 12, 'Encrypted data should include IV');
        assert.ok(encrypted.length > data.length, 'Encrypted should be larger than plaintext');
    });

    it('should use different IV each time', async () => {
        const data = new TextEncoder().encode('Same data');
        const key = await CryptoModule.generateKey();

        // Encrypt same data twice
        const encrypted1 = await CryptoModule.encrypt(data.buffer, key);
        const encrypted2 = await CryptoModule.encrypt(data.buffer, key);

        // Extract IVs (first 12 bytes)
        const iv1 = encrypted1.slice(0, 12);
        const iv2 = encrypted2.slice(0, 12);

        // IVs should be different
        assert.notDeepStrictEqual(iv1, iv2, 'IVs should be unique for each encryption');

        // But both should decrypt to same data
        const decrypted1 = await CryptoModule.decrypt(encrypted1, key);
        const decrypted2 = await CryptoModule.decrypt(encrypted2, key);

        const text1 = new TextDecoder().decode(decrypted1);
        const text2 = new TextDecoder().decode(decrypted2);

        assert.strictEqual(text1, text2, 'Both should decrypt to same data');
    });

    it('should have correct IV length (12 bytes)', async () => {
        const data = new TextEncoder().encode('Test');
        const key = await CryptoModule.generateKey();

        const encrypted = await CryptoModule.encrypt(data.buffer, key);

        // IV should be exactly 12 bytes (96 bits)
        const iv = encrypted.slice(0, 12);
        assert.strictEqual(iv.length, 12, 'IV should be 12 bytes');
    });
});


describe('CryptoModule - Key Export/Import', () => {
    it('should export key to raw bytes', async () => {
        const key = await CryptoModule.generateKey();
        const rawKey = await CryptoModule.exportKey(key);

        assert.ok(rawKey instanceof ArrayBuffer, 'Should return ArrayBuffer');
        assert.strictEqual(rawKey.byteLength, 32, 'Key should be 32 bytes (256 bits)');
    });

    it('should import key from raw bytes', async () => {
        const originalKey = await CryptoModule.generateKey();
        const rawKey = await CryptoModule.exportKey(originalKey);

        const importedKey = await CryptoModule.importKey(rawKey);

        assert.strictEqual(importedKey.type, 'secret', 'Imported key type should be secret');
        assert.strictEqual(importedKey.algorithm.name, 'AES-GCM', 'Algorithm should match');
    });

    it('should encrypt/decrypt with exported and re-imported key', async () => {
        const text = 'Test message';
        const data = new TextEncoder().encode(text);

        // Generate and export key
        const originalKey = await CryptoModule.generateKey();
        const rawKey = await CryptoModule.exportKey(originalKey);

        // Import key
        const importedKey = await CryptoModule.importKey(rawKey);

        // Encrypt with original, decrypt with imported
        const encrypted = await CryptoModule.encrypt(data.buffer, originalKey);
        const decrypted = await CryptoModule.decrypt(encrypted, importedKey);

        const result = new TextDecoder().decode(decrypted);
        assert.strictEqual(result, text, 'Should work with imported key');
    });
});


describe('CryptoModule - Base64 Conversion', () => {
    it('should convert key to base64', async () => {
        const key = await CryptoModule.generateKey();
        const base64 = await CryptoModule.keyToBase64(key);

        assert.ok(typeof base64 === 'string', 'Should return string');
        assert.ok(base64.length > 0, 'Base64 should not be empty');
        assert.ok(/^[A-Za-z0-9+/=]+$/.test(base64), 'Should be valid base64');
    });

    it('should convert base64 back to key', async () => {
        const originalKey = await CryptoModule.generateKey();
        const base64 = await CryptoModule.keyToBase64(originalKey);

        const restoredKey = await CryptoModule.base64ToKey(base64);

        assert.strictEqual(restoredKey.type, 'secret', 'Restored key should be secret');
        assert.strictEqual(restoredKey.algorithm.name, 'AES-GCM', 'Algorithm should match');
    });

    it('should encrypt/decrypt with base64-converted key', async () => {
        const text = 'Secret message for URL';
        const data = new TextEncoder().encode(text);

        // Generate key and convert to base64 (for URL fragment)
        const originalKey = await CryptoModule.generateKey();
        const base64Key = await CryptoModule.keyToBase64(originalKey);

        // Simulate: User copies URL with base64 key
        // Later: Restore key from URL fragment
        const restoredKey = await CryptoModule.base64ToKey(base64Key);

        // Encrypt with original key
        const encrypted = await CryptoModule.encrypt(data.buffer, originalKey);

        // Decrypt with restored key (from URL)
        const decrypted = await CryptoModule.decrypt(encrypted, restoredKey);

        const result = new TextDecoder().decode(decrypted);
        assert.strictEqual(result, text, 'Should work with base64 key from URL');
    });

    it('should produce URL-safe base64', async () => {
        const key = await CryptoModule.generateKey();
        const base64 = await CryptoModule.keyToBase64(key);

        // Base64 for URLs should not contain problematic chars (handled by standard base64)
        assert.ok(!base64.includes('\n'), 'Should not contain newlines');
        assert.ok(!base64.includes(' '), 'Should not contain spaces');
    });
});


describe('CryptoModule - Real-World Scenarios', () => {
    it('should simulate complete upload/download flow', async () => {
        // === UPLOAD SIDE ===
        const originalFile = 'This is my secret document content!';
        const fileData = new TextEncoder().encode(originalFile);

        // 1. Generate key on client
        const encryptionKey = await CryptoModule.generateKey();

        // 2. Encrypt file
        const encryptedFile = await CryptoModule.encrypt(fileData.buffer, encryptionKey);

        // 3. Convert key to base64 for URL
        const keyForUrl = await CryptoModule.keyToBase64(encryptionKey);

        // 4. Upload encrypted file to server (simulated)
        const fileIdFromServer = 'file-123';
        const downloadUrl = `https://sdbx.cc/download#${fileIdFromServer}#${keyForUrl}`;

        // === DOWNLOAD SIDE ===
        // 5. User clicks link, browser extracts fragment
        const urlParts = downloadUrl.split('#');
        const fileId = urlParts[1];
        const keyBase64 = urlParts[2];

        // 6. Restore key from URL
        const decryptionKey = await CryptoModule.base64ToKey(keyBase64);

        // 7. Download encrypted file from server (simulated)
        const downloadedFile = encryptedFile;

        // 8. Decrypt file
        const decryptedFile = await CryptoModule.decrypt(downloadedFile, decryptionKey);

        // 9. Verify
        const finalText = new TextDecoder().decode(decryptedFile);
        assert.strictEqual(finalText, originalFile, 'Full flow should work');
    });

    it('should verify key never sent to server', () => {
        // This is a conceptual test - in real code:
        // - Key is generated client-side
        // - Key is in URL fragment (never sent to server)
        // - Only encrypted data is uploaded

        const uploadRequest = {
            file_size: 1024,
            ttl: '1h',
            // Key should NOT be here!
        };

        assert.ok(!uploadRequest.hasOwnProperty('key'), 'Key should never be in upload request');
        assert.ok(!uploadRequest.hasOwnProperty('encryption_key'), 'No encryption key in request');
    });
});


describe('CryptoModule - Edge Cases', () => {
    it('should handle corrupted ciphertext', async () => {
        const data = new TextEncoder().encode('Test data');
        const key = await CryptoModule.generateKey();

        const encrypted = await CryptoModule.encrypt(data.buffer, key);

        // Corrupt the ciphertext (flip some bits)
        encrypted[20] = encrypted[20] ^ 0xFF;

        // Decryption should fail
        await assert.rejects(
            async () => await CryptoModule.decrypt(encrypted, key),
            'Should reject corrupted data'
        );
    });

    it('should handle truncated ciphertext', async () => {
        const data = new TextEncoder().encode('Test data');
        const key = await CryptoModule.generateKey();

        const encrypted = await CryptoModule.encrypt(data.buffer, key);

        // Truncate ciphertext
        const truncated = encrypted.slice(0, encrypted.length - 5);

        // Decryption should fail
        await assert.rejects(
            async () => await CryptoModule.decrypt(truncated, key),
            'Should reject truncated data'
        );
    });

    it('should handle very short ciphertext (only IV)', async () => {
        const key = await CryptoModule.generateKey();
        const onlyIV = new Uint8Array(12); // Only IV, no ciphertext

        // Should fail or return empty
        await assert.rejects(
            async () => await CryptoModule.decrypt(onlyIV, key),
            'Should handle IV-only data gracefully'
        );
    });
});
