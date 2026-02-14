/**
 * Utility functions for sdbx
 */

'use strict';

const Utils = (function() {
    /**
     * Format bytes to human-readable size
     * @param {number} bytes - File size in bytes
     * @returns {string} Formatted size (e.g., "1.5 MB")
     */
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';

        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));

        return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
    }

    /**
     * Format seconds to human-readable time
     * @param {number} seconds - Time in seconds
     * @returns {string} Formatted time (e.g., "2 hours 30 minutes")
     */
    function formatTimeRemaining(seconds) {
        if (seconds <= 0) return 'Expired';

        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);

        if (hours > 0) {
            return `${hours} hour${hours > 1 ? 's' : ''} ${minutes} minute${minutes !== 1 ? 's' : ''}`;
        }

        return `${minutes} minute${minutes !== 1 ? 's' : ''}`;
    }

    /**
     * Copy text to clipboard
     * @param {string} text - Text to copy
     * @returns {Promise<boolean>} Success status
     */
    async function copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (err) {
            console.error('Failed to copy:', err);
            return false;
        }
    }

    /**
     * Show error message
     * @param {string} message - Error message to display
     */
    function showError(message) {
        // TODO: Implement toast/notification system
        alert(`Error: ${message}`);
    }

    /**
     * Show success message
     * @param {string} message - Success message to display
     */
    function showSuccess(message) {
        // TODO: Implement toast/notification system
        alert(message);
    }

    /**
     * Get current timestamp in seconds
     * @returns {number} Unix timestamp
     */
    function getCurrentTimestamp() {
        return Math.floor(Date.now() / 1000);
    }

    /**
     * Validate file size
     * @param {number} size - File size in bytes
     * @param {number} maxSize - Maximum allowed size in bytes
     * @returns {boolean} Whether file size is valid
     */
    function validateFileSize(size, maxSize = 104857600) {
        return size > 0 && size <= maxSize;
    }

    /**
     * Get file ID from URL fragment
     * @returns {string|null} File ID or null
     */
    function getFileIdFromUrl() {
        const fragment = window.location.hash;
        if (!fragment.startsWith('#')) return null;

        // Format: #<file_id>#<key>
        // Decode URI component in case # is encoded as %23
        const decoded = decodeURIComponent(fragment.substring(1));
        const parts = decoded.split('#');
        return parts[0] || null;
    }

    /**
     * Get encryption key from URL fragment
     * @returns {string|null} Base64-encoded key or null
     */
    function getKeyFromFragment() {
        const fragment = window.location.hash;
        if (!fragment.startsWith('#')) return null;

        // Format: #<file_id>#<key>#<filename>
        // Decode URI component in case # is encoded as %23
        const decoded = decodeURIComponent(fragment.substring(1));
        const parts = decoded.split('#');
        return parts[1] || null;
    }

    /**
     * Get filename from URL fragment
     * @returns {string|null} Original filename or null
     */
    function getFileNameFromFragment() {
        const fragment = window.location.hash;
        if (!fragment.startsWith('#')) return null;

        // Format: #<file_id>#<key>#<filename>
        // Decode URI component in case # is encoded as %23
        const decoded = decodeURIComponent(fragment.substring(1));
        const parts = decoded.split('#');
        return parts[2] || null;
    }

    /**
     * Get reCAPTCHA v3 token for action
     * @param {string} siteKey - reCAPTCHA site key
     * @param {string} action - Action name (upload, download, report)
     * @returns {Promise<string>} reCAPTCHA token
     * @throws {Error} If reCAPTCHA fails
     */
    async function getRecaptchaToken(siteKey, action) {
        if (!window.grecaptcha) {
            throw new Error('reCAPTCHA not loaded');
        }

        if (!siteKey) {
            throw new Error('reCAPTCHA not configured');
        }

        return new Promise((resolve, reject) => {
            grecaptcha.ready(async () => {
                try {
                    const token = await grecaptcha.execute(siteKey, { action: action });
                    resolve(token);
                } catch (error) {
                    console.error('reCAPTCHA error:', error);
                    reject(new Error('Failed to verify reCAPTCHA. Please refresh and try again.'));
                }
            });
        });
    }

    return {
        formatFileSize,
        formatTimeRemaining,
        copyToClipboard,
        showError,
        showSuccess,
        getCurrentTimestamp,
        validateFileSize,
        getFileIdFromUrl,
        getKeyFromFragment,
        getFileNameFromFragment,
        getRecaptchaToken,
    };
})();
