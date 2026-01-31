/**
 * PIN-based upload module for sdbx
 * Handles method selection, file upload with PIN encryption, and result display
 */

'use strict';

const PinUpload = (function() {
    // Configuration
    const API_BASE = '/prod';
    const RECAPTCHA_SITE_KEY = '6LdulTIsAAAAAJdhvyMU6B1og7GE7d5DySrQUQiv';
    const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500 MB
    const PIN_REGEX = /^[a-zA-Z0-9]{4}$/;

    // TTL display labels
    const TTL_LABELS = {
        '1h': '1 hour',
        '12h': '12 hours',
        '24h': '24 hours',
    };

    // DOM elements (cached on init)
    let els = {};

    // State
    let selectedFile = null;
    let isUploading = false;

    /**
     * Initialize the module - cache DOM elements and bind events
     */
    function init() {
        // Method selection elements
        els.methodSelection = document.getElementById('method-selection');
        els.methodLink = document.getElementById('method-link');
        els.methodPin = document.getElementById('method-pin');
        els.methodHelpBtn = document.getElementById('method-help-btn');
        els.methodHelpModal = document.getElementById('method-help-modal');
        els.helpModalClose = document.getElementById('help-modal-close');
        els.uploadSection = document.getElementById('upload-section');

        // PIN upload form elements
        els.pinUploadSection = document.getElementById('pin-upload-section');
        els.pinBackBtn = document.getElementById('pin-back-btn');
        els.pinDropZone = document.getElementById('pin-drop-zone');
        els.pinFileInput = document.getElementById('pin-file-input');
        els.pinFileInfo = document.getElementById('pin-file-info');
        els.pinFileName = document.getElementById('pin-file-name');
        els.pinFileSize = document.getElementById('pin-file-size');
        els.pinFileRemove = document.getElementById('pin-file-remove');
        els.pinInput = document.getElementById('pin-input');
        els.pinCharCount = document.getElementById('pin-char-count');
        els.pinValidationMsg = document.getElementById('pin-validation-msg');
        els.pinUploadBtn = document.getElementById('pin-upload-btn');
        els.pinProgress = document.getElementById('pin-progress');
        els.pinProgressFill = document.getElementById('pin-progress-fill');
        els.pinProgressText = document.getElementById('pin-progress-text');

        // PIN result elements
        els.pinResultSection = document.getElementById('pin-result-section');
        els.pinCodeValue = document.getElementById('pin-code-value');
        els.pinCopyCode = document.getElementById('pin-copy-code');
        els.pinDisplayMasked = document.getElementById('pin-display-masked');
        els.pinDisplayValue = document.getElementById('pin-display-value');
        els.pinRevealBtn = document.getElementById('pin-reveal-btn');
        els.pinExpiryLabel = document.getElementById('pin-expiry-label');
        els.pinDomain = document.getElementById('pin-domain');
        els.pinCodeRepeat = document.getElementById('pin-code-repeat');
        els.pinUploadAnother = document.getElementById('pin-upload-another');

        // Features section (hide when in PIN mode)
        els.featuresSection = document.querySelector('main > section.text-center');
        els.forYouSection = document.querySelector('main > section:last-of-type');

        bindEvents();
    }

    /**
     * Bind all event listeners
     */
    function bindEvents() {
        // Method selection
        els.methodLink.addEventListener('click', () => selectMethod('link'));
        els.methodPin.addEventListener('click', () => selectMethod('pin'));

        // Help modal
        els.methodHelpBtn.addEventListener('click', openHelpModal);
        els.helpModalClose.addEventListener('click', closeHelpModal);
        els.methodHelpModal.addEventListener('click', (e) => {
            if (e.target === els.methodHelpModal) closeHelpModal();
        });

        // Back button
        els.pinBackBtn.addEventListener('click', () => selectMethod(null));

        // File handling
        els.pinDropZone.addEventListener('click', () => els.pinFileInput.click());
        els.pinDropZone.addEventListener('dragover', handleDragOver);
        els.pinDropZone.addEventListener('dragleave', handleDragLeave);
        els.pinDropZone.addEventListener('drop', handleDrop);
        els.pinFileInput.addEventListener('change', handleFileSelect);
        els.pinFileRemove.addEventListener('click', removeFile);

        // PIN input
        els.pinInput.addEventListener('input', handlePinInput);

        // Upload button
        els.pinUploadBtn.addEventListener('click', handleUpload);

        // Result actions
        els.pinCopyCode.addEventListener('click', handleCopyCode);
        els.pinRevealBtn.addEventListener('click', togglePinReveal);
        els.pinUploadAnother.addEventListener('click', handleUploadAnother);

        // Keyboard support for drop zone
        els.pinDropZone.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                els.pinFileInput.click();
            }
        });
    }

    // ==========================================
    // Method Selection
    // ==========================================

    /**
     * Switch between sharing methods
     * @param {'link'|'pin'|null} method - Selected method or null for selection screen
     */
    function selectMethod(method) {
        // Hide everything first
        els.methodSelection.style.display = 'none';
        els.uploadSection.style.display = 'none';
        els.pinUploadSection.style.display = 'none';
        els.pinResultSection.style.display = 'none';

        if (method === 'link') {
            els.uploadSection.style.display = '';
        } else if (method === 'pin') {
            els.pinUploadSection.style.display = '';
        } else {
            // Show method selection screen
            els.methodSelection.style.display = '';
        }
    }

    // ==========================================
    // Help Modal
    // ==========================================

    function openHelpModal() {
        els.methodHelpModal.classList.remove('hidden');
    }

    function closeHelpModal() {
        els.methodHelpModal.classList.add('hidden');
    }

    // ==========================================
    // File Handling
    // ==========================================

    function handleDragOver(e) {
        e.preventDefault();
        els.pinDropZone.classList.add('border-blue-500', 'bg-gray-100', 'dark:bg-slate-800/50');
    }

    function handleDragLeave(e) {
        e.preventDefault();
        els.pinDropZone.classList.remove('border-blue-500', 'bg-gray-100', 'dark:bg-slate-800/50');
    }

    function handleDrop(e) {
        e.preventDefault();
        els.pinDropZone.classList.remove('border-blue-500', 'bg-gray-100', 'dark:bg-slate-800/50');

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            setFile(files[0]);
        }
    }

    function handleFileSelect(e) {
        const files = e.target.files;
        if (files.length > 0) {
            setFile(files[0]);
        }
    }

    /**
     * Set the selected file and update UI
     * @param {File} file
     */
    function setFile(file) {
        if (file.size > MAX_FILE_SIZE) {
            Utils.showError(`File size exceeds 500 MB limit. Selected: ${Utils.formatFileSize(file.size)}`);
            return;
        }

        if (file.size === 0) {
            Utils.showError('Cannot upload an empty file');
            return;
        }

        selectedFile = file;

        // Update UI
        els.pinFileName.textContent = file.name;
        els.pinFileSize.textContent = Utils.formatFileSize(file.size);
        els.pinFileInfo.style.display = '';
        els.pinDropZone.style.display = 'none';

        updateUploadButton();
    }

    function removeFile() {
        selectedFile = null;
        els.pinFileInput.value = '';
        els.pinFileInfo.style.display = 'none';
        els.pinDropZone.style.display = '';
        updateUploadButton();
    }

    // ==========================================
    // PIN Input
    // ==========================================

    function handlePinInput() {
        const value = els.pinInput.value;
        els.pinCharCount.textContent = `${value.length}/4`;

        // Validate on each keystroke
        if (value.length === 0) {
            setPinValidation('', '');
        } else if (value.length < 4) {
            setPinValidation(`${4 - value.length} more character${value.length === 3 ? '' : 's'} needed`, 'text-gray-500 dark:text-slate-400');
        } else if (!PIN_REGEX.test(value)) {
            setPinValidation('Only letters and numbers allowed', 'text-red-500 dark:text-red-400');
        } else {
            setPinValidation('Valid PIN', 'text-green-600 dark:text-green-400');
        }

        updateUploadButton();
    }

    /**
     * Set PIN validation message
     * @param {string} message
     * @param {string} colorClass - Tailwind color classes
     */
    function setPinValidation(message, colorClass) {
        els.pinValidationMsg.textContent = message;
        // Remove all color classes, then add new one
        els.pinValidationMsg.className = 'text-sm mt-1 min-h-[1.25rem]';
        if (colorClass) {
            colorClass.split(' ').forEach(cls => els.pinValidationMsg.classList.add(cls));
        }
    }

    // ==========================================
    // Upload Button State
    // ==========================================

    function updateUploadButton() {
        const hasFile = selectedFile !== null;
        const hasValidPin = PIN_REGEX.test(els.pinInput.value);
        els.pinUploadBtn.disabled = !hasFile || !hasValidPin || isUploading;
    }

    // ==========================================
    // Upload Flow
    // ==========================================

    /**
     * Handle the PIN upload flow:
     * 1. Get reCAPTCHA token
     * 2. Call API with PIN and file info (server generates salt, returns it)
     * 3. Derive encryption key from PIN + server salt via PBKDF2
     * 4. Encrypt file with derived key
     * 5. Upload encrypted data to S3
     * 6. Show result
     */
    async function handleUpload() {
        if (!selectedFile || isUploading) return;

        const pin = els.pinInput.value;
        if (!PIN_REGEX.test(pin)) {
            Utils.showError('Invalid PIN. Must be exactly 4 alphanumeric characters.');
            return;
        }

        const ttl = getSelectedTTL();

        try {
            isUploading = true;
            updateUploadButton();
            showProgress(0, 'Preparing...');

            // Step 1: Get reCAPTCHA token
            showProgress(5, 'Verifying...');
            const recaptchaToken = await Utils.getRecaptchaToken(RECAPTCHA_SITE_KEY, 'pin_upload');

            // Step 2: Call PIN upload API
            showProgress(10, 'Initializing upload...');
            const initResponse = await callPinUploadApi({
                content_type: 'file',
                file_size: selectedFile.size,
                pin: pin,
                ttl: ttl,
                recaptcha_token: recaptchaToken,
            });

            const { file_id, upload_url, salt, expires_at } = initResponse;

            // Step 3: Derive encryption key from PIN + server salt
            showProgress(20, 'Deriving encryption key...');
            const saltBytes = hexToUint8Array(salt);
            const encryptionKey = await CryptoModule.deriveKeyFromPassword(pin, saltBytes, true);

            // Step 4: Encrypt file
            showProgress(25, 'Encrypting... 0%');
            const encryptedData = await CryptoModule.encryptFile(
                selectedFile,
                encryptionKey,
                (progress) => {
                    const percent = 25 + (progress * 0.35);
                    showProgress(percent, `Encrypting... ${Math.round(progress)}%`);
                }
            );

            // Step 5: Upload encrypted data to S3
            showProgress(65, 'Uploading encrypted file...');
            await uploadToS3(upload_url, encryptedData);

            // Step 6: Show result
            showProgress(100, 'Upload complete!');
            showResult(file_id, pin, ttl, expires_at);

        } catch (error) {
            console.error('PIN upload error:', error);
            Utils.showError(error.message || 'Upload failed. Please try again.');
            resetUploadState();
        }
    }

    /**
     * Call the PIN upload API
     * @param {Object} body - Request body
     * @returns {Promise<Object>} API response data
     */
    async function callPinUploadApi(body) {
        const response = await fetch(`${API_BASE}/pin/upload`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || `Upload initialization failed: ${response.status}`);
        }

        return response.json();
    }

    /**
     * Upload encrypted data to S3 via presigned URL with progress tracking
     * @param {string} presignedUrl - S3 presigned URL
     * @param {Uint8Array} data - Encrypted data
     * @returns {Promise<void>}
     */
    function uploadToS3(presignedUrl, data) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();

            xhr.upload.onprogress = (event) => {
                if (event.lengthComputable) {
                    const percentComplete = (event.loaded / event.total) * 100;
                    const overallPercent = 65 + (percentComplete * 0.30);
                    showProgress(overallPercent, `Uploading... ${percentComplete.toFixed(1)}%`);
                }
            };

            xhr.onload = () => {
                if (xhr.status >= 200 && xhr.status < 300) {
                    resolve();
                } else {
                    reject(new Error(`S3 upload failed: ${xhr.status}`));
                }
            };

            xhr.onerror = () => reject(new Error('Network error during upload'));
            xhr.ontimeout = () => reject(new Error('Upload timeout'));

            xhr.open('PUT', presignedUrl);
            xhr.setRequestHeader('Content-Type', 'application/octet-stream');
            xhr.send(data);
        });
    }

    // ==========================================
    // Progress UI
    // ==========================================

    function showProgress(percent, text) {
        els.pinProgress.style.display = '';
        els.pinProgressFill.style.width = `${percent}%`;
        els.pinProgressText.textContent = text;
    }

    function hideProgress() {
        els.pinProgress.style.display = 'none';
        els.pinProgressFill.style.width = '0%';
        els.pinProgressText.textContent = '';
    }

    // ==========================================
    // Result Display
    // ==========================================

    /**
     * Show upload result with code and PIN
     * @param {string} fileId - 6-digit code
     * @param {string} pin - User's PIN
     * @param {string} ttl - TTL value used
     * @param {number} expiresAt - Unix timestamp
     */
    function showResult(fileId, pin, ttl, expiresAt) {
        // Hide upload section, show result
        els.pinUploadSection.style.display = 'none';
        els.pinResultSection.style.display = '';

        // Set code display
        els.pinCodeValue.textContent = fileId;
        els.pinCodeRepeat.textContent = fileId;

        // Set PIN display
        els.pinDisplayValue.textContent = pin;
        els.pinDisplayMasked.style.display = '';
        els.pinDisplayValue.style.display = 'none';
        els.pinRevealBtn.textContent = 'Show';

        // Set expiry label
        els.pinExpiryLabel.textContent = TTL_LABELS[ttl] || ttl;

        // Set domain
        els.pinDomain.textContent = window.location.hostname;

        isUploading = false;
    }

    // ==========================================
    // Result Actions
    // ==========================================

    async function handleCopyCode() {
        const code = els.pinCodeValue.textContent;
        const success = await Utils.copyToClipboard(code);
        if (success) {
            const originalText = els.pinCopyCode.textContent;
            els.pinCopyCode.textContent = 'Copied!';
            setTimeout(() => {
                els.pinCopyCode.textContent = originalText;
            }, 2000);
        }
    }

    function togglePinReveal() {
        const isHidden = els.pinDisplayValue.style.display === 'none';
        if (isHidden) {
            els.pinDisplayMasked.style.display = 'none';
            els.pinDisplayValue.style.display = '';
            els.pinRevealBtn.textContent = 'Hide';
        } else {
            els.pinDisplayMasked.style.display = '';
            els.pinDisplayValue.style.display = 'none';
            els.pinRevealBtn.textContent = 'Show';
        }
    }

    function handleUploadAnother() {
        // Reset everything and go back to method selection
        resetUploadState();
        selectedFile = null;
        els.pinInput.value = '';
        els.pinCharCount.textContent = '0/4';
        setPinValidation('', '');
        els.pinFileInput.value = '';
        els.pinFileInfo.style.display = 'none';
        els.pinDropZone.style.display = '';
        els.pinResultSection.style.display = 'none';
        selectMethod(null);
    }

    // ==========================================
    // Helpers
    // ==========================================

    function resetUploadState() {
        isUploading = false;
        hideProgress();
        updateUploadButton();
    }

    /**
     * Get selected TTL from radio buttons
     * @returns {string} TTL value ("1h", "12h", or "24h")
     */
    function getSelectedTTL() {
        const radio = document.querySelector('input[name="pin-ttl"]:checked');
        return radio ? radio.value : '24h';
    }

    /**
     * Convert hex string to Uint8Array
     * @param {string} hex - Hex string (e.g. "aabbcc")
     * @returns {Uint8Array}
     */
    function hexToUint8Array(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    // ==========================================
    // Public API
    // ==========================================

    return {
        init,
        selectMethod,
    };
})();

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Only initialize on pages that have the method selection
    if (document.getElementById('method-selection')) {
        PinUpload.init();
    }
});
