/**
 * Share Page Module
 * Displays QR code and share link after successful upload
 */

(function() {
    'use strict';

    // Configuration
    const CONFIG = {
        API_BASE_URL: '/prod',
        QR_SIZE: 256, // 256x256px - optimal for mobile scanning
        MAX_QR_URL_LENGTH: 2000, // QR codes become unreliable above this length
    };

    // DOM Elements
    const elements = {
        loadingSection: document.getElementById('loading-section'),
        shareSection: document.getElementById('share-section'),
        errorSection: document.getElementById('error-section'),
        contentTypeLabel: document.getElementById('content-type-label'),
        qrContainer: document.getElementById('qr-container'),
        shareUrl: document.getElementById('share-url'),
        copyLinkBtn: document.getElementById('copy-link-btn'),
        copyQrBtn: document.getElementById('copy-qr-btn'),
        downloadQrBtn: document.getElementById('download-qr-btn'),
        countdown: document.getElementById('countdown'),
        countdownSection: document.getElementById('countdown-section'),
        deleteWarning: document.getElementById('delete-warning'),
        errorMessage: document.getElementById('error-message'),
    };

    // State
    let countdownInterval = null;

    /**
     * Initialize share page
     */
    function init() {
        // Parse URL fragment: #fileId#key#filename or #fileId#salt#filename#vault
        const fragment = window.location.hash.slice(1);
        const parts = fragment.split('#');

        const fileId = parts[0];
        const isVault = parts.length >= 4 && parts[parts.length - 1] === 'vault';

        if (isVault) {
            // Vault URL: #file_id#salt#filename#vault
            const salt = parts[1];
            const fileName = parts[2] ? decodeURIComponent(parts[2]) : null;

            if (!fileId || !salt) {
                showError('Invalid vault link. File ID or salt is missing.');
                return;
            }

            // Build vault download URL
            const downloadUrl = buildVaultDownloadUrl(fileId, salt, fileName);

            // Update labels for vault
            updateVaultLabels(fileName);

            // Generate QR code
            generateQRCode(downloadUrl);

            // Set share URL
            elements.shareUrl.value = downloadUrl;

            // Setup event listeners
            setupEventListeners(downloadUrl, fileName);

            // Fetch metadata and start countdown
            fetchMetadataAndStartCountdown(fileId);

            // Show share section
            elements.loadingSection.style.display = 'none';
            elements.shareSection.style.display = 'block';
        } else {
            // One-time URL: #file_id#key#filename
            const key = parts[1];
            const fileName = parts[2] ? decodeURIComponent(parts[2]) : null;

            if (!fileId || !key) {
                showError('Invalid share link. File ID or encryption key is missing.');
                return;
            }

            // Build download URL
            const downloadUrl = buildDownloadUrl(fileId, key, fileName);

            // Determine if this is a text secret (no filename) or file
            const isTextSecret = !fileName;
            updateContentTypeLabels(isTextSecret);

            // Generate QR code
            generateQRCode(downloadUrl);

            // Set share URL
            elements.shareUrl.value = downloadUrl;

            // Setup event listeners
            setupEventListeners(downloadUrl, fileName);

            // Fetch metadata and start countdown
            fetchMetadataAndStartCountdown(fileId);

            // Show share section
            elements.loadingSection.style.display = 'none';
            elements.shareSection.style.display = 'block';
        }
    }

    /**
     * Build download URL from components
     * @param {string} fileId - File ID
     * @param {string} key - Base64 encoded encryption key
     * @param {string|null} fileName - Original filename (null for text secrets)
     * @returns {string} Full download URL
     */
    function buildDownloadUrl(fileId, key, fileName) {
        let url = `${window.location.origin}/download.html#${fileId}#${key}`;
        if (fileName) {
            url += `#${encodeURIComponent(fileName)}`;
        }

        // Warn if URL is very long (QR codes become hard to scan)
        if (url.length > CONFIG.MAX_QR_URL_LENGTH) {
            console.warn(`Share URL is ${url.length} chars (>${CONFIG.MAX_QR_URL_LENGTH}), QR code may be hard to scan`);
        }

        return url;
    }

    /**
     * Build vault download URL from components
     * @param {string} fileId - File ID
     * @param {string} salt - Base64 encoded salt for PBKDF2
     * @param {string|null} fileName - Original filename (null for text)
     * @returns {string} Full vault download URL
     */
    function buildVaultDownloadUrl(fileId, salt, fileName) {
        let url = `${window.location.origin}/download.html#${fileId}#${salt}`;
        if (fileName) {
            url += `#${encodeURIComponent(fileName)}`;
        }
        url += '#vault';

        // Warn if URL is very long
        if (url.length > CONFIG.MAX_QR_URL_LENGTH) {
            console.warn(`Vault URL is ${url.length} chars (>${CONFIG.MAX_QR_URL_LENGTH}), QR code may be hard to scan`);
        }

        return url;
    }

    /**
     * Update labels based on content type (file vs text)
     * @param {boolean} isTextSecret - Whether this is a text secret
     */
    function updateContentTypeLabels(isTextSecret) {
        if (isTextSecret) {
            elements.contentTypeLabel.textContent = 'Your text secret has been encrypted and stored.';
            elements.deleteWarning.textContent = 'Text deleted after viewing or expiry';
        } else {
            elements.contentTypeLabel.textContent = 'Your file has been encrypted and uploaded.';
            elements.deleteWarning.textContent = 'File deleted after download or expiry';
        }
    }

    /**
     * Update labels for vault (password-protected, multi-access)
     * @param {string|null} fileName - Filename if file, null if text
     */
    function updateVaultLabels(fileName) {
        const isText = !fileName;

        if (isText) {
            elements.contentTypeLabel.innerHTML = `
                <span class="inline-flex items-center gap-2">
                    <svg class="w-5 h-5 text-blue-600 dark:text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                    </svg>
                    Your text has been stored in the vault.
                </span>
            `;
        } else {
            elements.contentTypeLabel.innerHTML = `
                <span class="inline-flex items-center gap-2">
                    <svg class="w-5 h-5 text-blue-600 dark:text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                    </svg>
                    Your file has been stored in the vault.
                </span>
            `;
        }

        // Update delete warning with vault-specific messaging
        elements.deleteWarning.innerHTML = `
            <span class="text-blue-600 dark:text-blue-400 font-medium">Password-protected</span>
            &bull; Can be accessed multiple times until expiry
        `;
    }

    /**
     * Generate QR code for the download URL
     * @param {string} url - Download URL to encode
     */
    function generateQRCode(url) {
        elements.qrContainer.innerHTML = '';

        try {
            new QRCode(elements.qrContainer, {
                text: url,
                width: CONFIG.QR_SIZE,
                height: CONFIG.QR_SIZE,
                colorDark: '#000000',
                colorLight: '#ffffff',
                correctLevel: QRCode.CorrectLevel.L,  // Use L for longer URLs
            });
        } catch (error) {
            // URL too long for QR code - show message instead
            console.warn('QR code generation failed:', error.message);
            elements.qrContainer.innerHTML = `
                <div class="flex items-center justify-center h-full text-center p-4">
                    <p class="text-gray-500 dark:text-slate-400 text-sm">
                        URL too long for QR code.<br>Use "Copy Link" instead.
                    </p>
                </div>
            `;
        }
    }

    /**
     * Setup event listeners for buttons
     * @param {string} downloadUrl - The share URL
     * @param {string|null} fileName - Original filename for QR download naming
     */
    function setupEventListeners(downloadUrl, fileName) {
        elements.copyLinkBtn.addEventListener('click', () => handleCopyLink(downloadUrl));
        elements.copyQrBtn.addEventListener('click', handleCopyQr);
        elements.downloadQrBtn.addEventListener('click', () => handleDownloadQr(fileName));
    }

    /**
     * Handle copy link to clipboard
     * @param {string} url - URL to copy
     */
    async function handleCopyLink(url) {
        const success = await Utils.copyToClipboard(url);
        if (success) {
            showButtonSuccess(elements.copyLinkBtn, 'Copied!', 'Copy');
        } else {
            Utils.showError('Failed to copy link to clipboard');
        }
    }

    /**
     * Handle copy QR code to clipboard as image
     */
    async function handleCopyQr() {
        const canvas = elements.qrContainer.querySelector('canvas');
        if (!canvas) {
            Utils.showError('QR code not ready');
            return;
        }

        try {
            const blob = await new Promise((resolve, reject) => {
                canvas.toBlob((b) => {
                    if (b) resolve(b);
                    else reject(new Error('Failed to create blob'));
                }, 'image/png');
            });

            await navigator.clipboard.write([
                new ClipboardItem({ 'image/png': blob })
            ]);

            showButtonSuccess(elements.copyQrBtn, 'Copied!', 'Copy QR');
        } catch (error) {
            // Firefox and some browsers don't support clipboard.write for images
            console.warn('Copy QR failed:', error);
            Utils.showError('Browser does not support copying images. Use "Download QR" instead.');
        }
    }

    /**
     * Handle download QR code as PNG file
     * @param {string|null} fileName - Original filename to derive QR filename
     */
    function handleDownloadQr(fileName) {
        const canvas = elements.qrContainer.querySelector('canvas');
        if (!canvas) {
            Utils.showError('QR code not ready');
            return;
        }

        canvas.toBlob((blob) => {
            if (!blob) {
                Utils.showError('Failed to generate QR code image');
                return;
            }

            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;

            // Generate filename based on original file or generic
            if (fileName) {
                const baseName = fileName.replace(/\.[^/.]+$/, ''); // Remove extension
                a.download = `sdbx-qr-${baseName}.png`;
            } else {
                a.download = 'sdbx-qr-code.png';
            }

            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            showButtonSuccess(elements.downloadQrBtn, 'Downloaded!', 'Download QR');
        }, 'image/png');
    }

    /**
     * Show temporary success state on button
     * @param {HTMLElement} button - Button element
     * @param {string} successText - Text to show on success
     * @param {string} originalText - Original button text to restore
     */
    function showButtonSuccess(button, successText, originalText) {
        const originalHtml = button.innerHTML;
        button.innerHTML = `<svg class="w-4 h-4 inline-block mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" /></svg>${successText}`;
        button.classList.add('btn-success');

        setTimeout(() => {
            button.innerHTML = originalHtml;
            button.classList.remove('btn-success');
        }, 2000);
    }

    /**
     * Fetch file metadata and start countdown timer
     * @param {string} fileId - File ID to fetch metadata for
     */
    async function fetchMetadataAndStartCountdown(fileId) {
        try {
            const response = await fetch(`${CONFIG.API_BASE_URL}/files/${fileId}/metadata`);

            if (!response.ok) {
                // Don't block the page, just hide countdown
                elements.countdownSection.style.display = 'none';
                return;
            }

            const data = await response.json();

            if (data.expires_at) {
                startCountdown(data.expires_at);
            } else {
                elements.countdownSection.style.display = 'none';
            }
        } catch (error) {
            console.warn('Failed to fetch metadata:', error);
            elements.countdownSection.style.display = 'none';
        }
    }

    /**
     * Start countdown timer to expiration
     * @param {number} expiresAt - Unix timestamp of expiration
     */
    function startCountdown(expiresAt) {
        const updateCountdown = () => {
            const now = Math.floor(Date.now() / 1000);
            const remaining = expiresAt - now;

            if (remaining <= 0) {
                elements.countdown.textContent = 'Expired';
                elements.countdown.classList.add('text-red-500');
                if (countdownInterval) {
                    clearInterval(countdownInterval);
                    countdownInterval = null;
                }
                return;
            }

            elements.countdown.textContent = Utils.formatTimeRemaining(remaining);
        };

        updateCountdown();
        countdownInterval = setInterval(updateCountdown, 60000); // Update every minute
    }

    /**
     * Show error section with message
     * @param {string} message - Error message to display
     */
    function showError(message) {
        elements.loadingSection.style.display = 'none';
        elements.shareSection.style.display = 'none';
        elements.errorSection.style.display = 'block';
        elements.errorMessage.textContent = message;
    }

    /**
     * Cleanup resources on page unload
     */
    function cleanup() {
        if (countdownInterval) {
            clearInterval(countdownInterval);
            countdownInterval = null;
        }
    }

    // Cleanup on page unload to prevent memory leaks
    window.addEventListener('beforeunload', cleanup);

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
