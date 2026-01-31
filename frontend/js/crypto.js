/**
 * Cryptography module for sdbx
 * Handles AES-256-GCM encryption and decryption
 */

'use strict';

const CryptoModule = (function() {
    const ALGORITHM = 'AES-GCM';
    const KEY_LENGTH = 256;
    const IV_LENGTH = 12; // 96 bits
    const SALT_LENGTH = 16; // 128 bits for PBKDF2
    const PBKDF2_ITERATIONS = 100000; // Standard recommendation

    /**
     * Generate a random encryption key
     * @returns {Promise<CryptoKey>} Generated key
     */
    async function generateKey() {
        return crypto.subtle.generateKey(
            {
                name: ALGORITHM,
                length: KEY_LENGTH,
            },
            true, // extractable
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Generate random IV (Initialization Vector)
     * @returns {Uint8Array} Random IV
     */
    function generateIV() {
        return crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    }

    /**
     * Encrypt data with AES-256-GCM
     * @param {ArrayBuffer} data - Data to encrypt
     * @param {CryptoKey} key - Encryption key
     * @returns {Promise<Uint8Array>} IV + ciphertext
     */
    async function encrypt(data, key) {
        const iv = generateIV();

        const ciphertext = await crypto.subtle.encrypt(
            {
                name: ALGORITHM,
                iv: iv,
            },
            key,
            data
        );

        // Prepend IV to ciphertext
        const result = new Uint8Array(iv.length + ciphertext.byteLength);
        result.set(iv, 0);
        result.set(new Uint8Array(ciphertext), iv.length);

        return result;
    }

    /**
     * Decrypt data with AES-256-GCM
     * @param {Uint8Array} data - IV + ciphertext
     * @param {CryptoKey} key - Decryption key
     * @returns {Promise<ArrayBuffer>} Decrypted data
     */
    async function decrypt(data, key) {
        // Extract IV and ciphertext
        const iv = data.slice(0, IV_LENGTH);
        const ciphertext = data.slice(IV_LENGTH);

        return crypto.subtle.decrypt(
            {
                name: ALGORITHM,
                iv: iv,
            },
            key,
            ciphertext
        );
    }

    /**
     * Export key to raw format
     * @param {CryptoKey} key - Key to export
     * @returns {Promise<ArrayBuffer>} Raw key bytes
     */
    async function exportKey(key) {
        return crypto.subtle.exportKey('raw', key);
    }

    /**
     * Import key from raw format
     * @param {ArrayBuffer} keyData - Raw key bytes
     * @returns {Promise<CryptoKey>} Imported key
     */
    async function importKey(keyData) {
        return crypto.subtle.importKey(
            'raw',
            keyData,
            {
                name: ALGORITHM,
            },
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Convert key to base64 for URL
     * @param {CryptoKey} key - Key to convert
     * @returns {Promise<string>} Base64-encoded key
     */
    async function keyToBase64(key) {
        const rawKey = await exportKey(key);
        const keyArray = new Uint8Array(rawKey);
        const keyString = String.fromCharCode.apply(null, keyArray);
        return btoa(keyString);
    }

    /**
     * Convert base64 string to key
     * @param {string} base64 - Base64-encoded key
     * @returns {Promise<CryptoKey>} Imported key
     */
    async function base64ToKey(base64) {
        const keyString = atob(base64);
        const keyArray = new Uint8Array(keyString.length);
        for (let i = 0; i < keyString.length; i++) {
            keyArray[i] = keyString.charCodeAt(i);
        }
        return importKey(keyArray.buffer);
    }

    /**
     * Encrypt file using Web Worker (non-blocking)
     * @param {File} file - File to encrypt
     * @param {CryptoKey} key - Encryption key
     * @param {function(number): void} onProgress - Progress callback (0-100)
     * @returns {Promise<Uint8Array>} Encrypted data
     */
    async function encryptFile(file, key, onProgress) {
        if (onProgress) onProgress(0);
        const arrayBuffer = await file.arrayBuffer();
        if (onProgress) onProgress(10);

        // Try Web Worker path (requires extractable key)
        let keyData;
        try {
            keyData = await exportKey(key);
        } catch (e) {
            // Key not extractable (some mobile browsers) — fall back to main thread
            return encryptMainThread(arrayBuffer, key, onProgress);
        }

        return new Promise((resolve, reject) => {
            try {
                const worker = new Worker('/js/crypto-worker.js');

                worker.onmessage = function(e) {
                    const { type, percent, result, error } = e.data;
                    if (type === 'progress') {
                        if (onProgress) onProgress(10 + (percent * 0.9));
                    } else if (type === 'complete') {
                        worker.terminate();
                        resolve(new Uint8Array(result));
                    } else if (type === 'error') {
                        worker.terminate();
                        reject(new Error(error));
                    }
                };

                worker.onerror = function(error) {
                    worker.terminate();
                    reject(error);
                };

                worker.postMessage({
                    action: 'encrypt',
                    data: arrayBuffer,
                    keyData: keyData
                }, [arrayBuffer]);

            } catch (error) {
                reject(error);
            }
        });
    }

    /**
     * Main-thread encryption fallback for non-extractable keys
     */
    async function encryptMainThread(data, key, onProgress) {
        if (onProgress) onProgress(20);
        const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
        if (onProgress) onProgress(30);

        const ciphertext = await crypto.subtle.encrypt(
            { name: ALGORITHM, iv: iv },
            key,
            data
        );
        if (onProgress) onProgress(90);

        const result = new Uint8Array(iv.length + ciphertext.byteLength);
        result.set(iv, 0);
        result.set(new Uint8Array(ciphertext), iv.length);
        if (onProgress) onProgress(100);
        return result;
    }

    /**
     * Decrypt file using Web Worker (non-blocking)
     * @param {Uint8Array} encryptedData - Encrypted data
     * @param {CryptoKey} key - Decryption key
     * @param {function(number): void} onProgress - Progress callback (0-100)
     * @returns {Promise<ArrayBuffer>} Decrypted data
     */
    async function decryptFile(encryptedData, key, onProgress) {
        if (onProgress) onProgress(0);

        // Try Web Worker path (requires extractable key)
        let keyData;
        try {
            keyData = await exportKey(key);
        } catch (e) {
            // Key not extractable (some mobile browsers) — fall back to main thread
            return decryptMainThread(encryptedData, key, onProgress);
        }

        return new Promise((resolve, reject) => {
            try {
                const worker = new Worker('/js/crypto-worker.js');

                worker.onmessage = function(e) {
                    const { type, percent, result, error } = e.data;
                    if (type === 'progress') {
                        if (onProgress) onProgress(percent);
                    } else if (type === 'complete') {
                        worker.terminate();
                        resolve(result);
                    } else if (type === 'error') {
                        worker.terminate();
                        reject(new Error(error));
                    }
                };

                worker.onerror = function(error) {
                    worker.terminate();
                    reject(error);
                };

                worker.postMessage({
                    action: 'decrypt',
                    data: encryptedData.buffer,
                    keyData: keyData
                }, [encryptedData.buffer]);

            } catch (error) {
                reject(error);
            }
        });
    }

    /**
     * Main-thread decryption fallback for non-extractable keys
     */
    async function decryptMainThread(encryptedData, key, onProgress) {
        if (onProgress) onProgress(10);
        const dataArray = new Uint8Array(encryptedData);
        const iv = dataArray.slice(0, IV_LENGTH);
        const ciphertext = dataArray.slice(IV_LENGTH);
        if (onProgress) onProgress(20);

        const decrypted = await crypto.subtle.decrypt(
            { name: ALGORITHM, iv: iv },
            key,
            ciphertext
        );
        if (onProgress) onProgress(100);
        return decrypted;
    }

    // ==========================================
    // Password-Based Key Derivation (for Vault)
    // ==========================================

    /**
     * Generate random salt for PBKDF2
     * @returns {Uint8Array} 16-byte salt
     */
    function generateSalt() {
        return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    }

    /**
     * Derive a key from password using PBKDF2
     * @param {string} password - User password
     * @param {Uint8Array} salt - Random salt (16 bytes)
     * @returns {Promise<CryptoKey>} Derived key for AES-GCM
     */
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

    /**
     * Encrypt an AES key with another key (for password protection)
     * @param {CryptoKey} dataKey - The key to encrypt
     * @param {CryptoKey} wrapperKey - Key to encrypt with
     * @returns {Promise<Uint8Array>} IV + encrypted key
     */
    async function encryptKey(dataKey, wrapperKey) {
        const iv = generateIV();
        const exportedKey = await crypto.subtle.exportKey('raw', dataKey);

        const encrypted = await crypto.subtle.encrypt(
            { name: ALGORITHM, iv: iv },
            wrapperKey,
            exportedKey
        );

        const result = new Uint8Array(iv.length + encrypted.byteLength);
        result.set(iv);
        result.set(new Uint8Array(encrypted), iv.length);
        return result;
    }

    /**
     * Decrypt an AES key with another key
     * @param {Uint8Array} encryptedKeyData - IV + encrypted key
     * @param {CryptoKey} wrapperKey - Key to decrypt with
     * @returns {Promise<CryptoKey>} Decrypted AES key
     */
    async function decryptKey(encryptedKeyData, wrapperKey) {
        const iv = encryptedKeyData.slice(0, IV_LENGTH);
        const ciphertext = encryptedKeyData.slice(IV_LENGTH);

        const decrypted = await crypto.subtle.decrypt(
            { name: ALGORITHM, iv: iv },
            wrapperKey,
            ciphertext
        );

        return crypto.subtle.importKey(
            'raw',
            decrypted,
            { name: ALGORITHM, length: KEY_LENGTH },
            true,
            ['decrypt']
        );
    }

    /**
     * Convert Uint8Array to base64
     * @param {Uint8Array} array - Byte array
     * @returns {string} Base64 string
     */
    function arrayToBase64(array) {
        return btoa(String.fromCharCode(...array));
    }

    /**
     * Convert base64 to Uint8Array
     * @param {string} base64 - Base64 string
     * @returns {Uint8Array} Byte array
     */
    function base64ToArray(base64) {
        return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    }

    return {
        generateKey,
        encrypt,
        decrypt,
        encryptFile,
        decryptFile,
        keyToBase64,
        base64ToKey,
        // Vault (password-based) functions
        generateSalt,
        deriveKeyFromPassword,
        encryptKey,
        decryptKey,
        arrayToBase64,
        base64ToArray,
    };
})();
