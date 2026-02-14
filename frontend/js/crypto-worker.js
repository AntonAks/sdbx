/**
 * Web Worker for encryption/decryption operations
 * Runs crypto operations in background thread to avoid blocking UI
 */

'use strict';

const ALGORITHM = 'AES-GCM';
const IV_LENGTH = 12; // 96 bits
const CHUNK_SIZE = 64 * 1024 * 1024; // 64MB chunks for progress reporting

/**
 * Generate random IV (Initialization Vector)
 */
function generateIV() {
    return crypto.getRandomValues(new Uint8Array(IV_LENGTH));
}

/**
 * Import raw key bytes as CryptoKey
 */
async function importKey(keyData) {
    return crypto.subtle.importKey(
        'raw',
        keyData,
        { name: ALGORITHM },
        true,
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypt data with progress reporting
 */
async function encryptWithProgress(data, keyData) {
    try {
        // Import key
        postMessage({ type: 'progress', percent: 5 });
        const key = await importKey(keyData);

        // Generate IV
        postMessage({ type: 'progress', percent: 10 });
        const iv = generateIV();

        // Encrypt data
        postMessage({ type: 'progress', percent: 20 });
        const ciphertext = await crypto.subtle.encrypt(
            { name: ALGORITHM, iv: iv },
            key,
            data
        );

        postMessage({ type: 'progress', percent: 80 });

        // Prepend IV to ciphertext
        const result = new Uint8Array(iv.length + ciphertext.byteLength);
        result.set(iv, 0);
        result.set(new Uint8Array(ciphertext), iv.length);

        postMessage({ type: 'progress', percent: 95 });

        // Send result
        postMessage({
            type: 'complete',
            result: result.buffer
        }, [result.buffer]); // Transfer ownership for efficiency

    } catch (error) {
        postMessage({
            type: 'error',
            error: error.message
        });
    }
}

/**
 * Decrypt data with progress reporting
 */
async function decryptWithProgress(data, keyData) {
    try {
        // Import key
        postMessage({ type: 'progress', percent: 5 });
        const key = await importKey(keyData);

        // Extract IV and ciphertext
        postMessage({ type: 'progress', percent: 10 });
        const dataArray = new Uint8Array(data);
        const iv = dataArray.slice(0, IV_LENGTH);
        const ciphertext = dataArray.slice(IV_LENGTH);

        // Decrypt
        postMessage({ type: 'progress', percent: 20 });
        const decrypted = await crypto.subtle.decrypt(
            { name: ALGORITHM, iv: iv },
            key,
            ciphertext
        );

        postMessage({ type: 'progress', percent: 90 });

        // Send result
        postMessage({
            type: 'complete',
            result: decrypted
        }, [decrypted]); // Transfer ownership for efficiency

    } catch (error) {
        postMessage({
            type: 'error',
            error: error.message
        });
    }
}

/**
 * Handle messages from main thread
 */
self.onmessage = async function(e) {
    const { action, data, keyData } = e.data;

    switch (action) {
        case 'encrypt':
            await encryptWithProgress(data, keyData);
            break;

        case 'decrypt':
            await decryptWithProgress(data, keyData);
            break;

        default:
            postMessage({
                type: 'error',
                error: `Unknown action: ${action}`
            });
    }
};
