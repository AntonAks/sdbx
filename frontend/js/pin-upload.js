/**
 * PIN-based upload module for sdbx
 * Handles method selection, file/text upload with PIN encryption, and result display
 */

'use strict';

const PinUpload = (function() {
    // Configuration
    const API_BASE = '/prod';
    const RECAPTCHA_SITE_KEY = '6LdulTIsAAAAAJdhvyMU6B1og7GE7d5DySrQUQiv';
    const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500 MB
    const MAX_FILES = 10;
    const MAX_TEXT_LENGTH = 1000;
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
    let selectedFiles = []; // Array of File objects
    let activeTab = 'file'; // 'file' or 'text'
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
        // Tab elements
        els.pinFileTab = document.getElementById('pin-file-tab');
        els.pinTextTab = document.getElementById('pin-text-tab');
        els.pinTabBtns = document.querySelectorAll('.tab-btn[data-pin-tab]');

        // File elements
        els.pinDropZone = document.getElementById('pin-drop-zone');
        els.pinFileInput = document.getElementById('pin-file-input');
        els.pinFileInfo = document.getElementById('pin-file-info');
        els.pinFileName = document.getElementById('pin-file-name');
        els.pinFileSize = document.getElementById('pin-file-size');
        els.pinFileRemove = document.getElementById('pin-file-remove');
        els.pinFileList = document.getElementById('pin-file-list');
        els.pinFileCount = document.getElementById('pin-file-count');
        els.pinFilesClear = document.getElementById('pin-files-clear');
        els.pinFileListItems = document.getElementById('pin-file-list-items');

        // Text elements
        els.pinTextInput = document.getElementById('pin-text-input');
        els.pinTextCharCount = document.getElementById('pin-text-char-count');

        // Common form elements
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

        // Tab switching
        els.pinTabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const tab = btn.dataset.pinTab;
                switchTab(tab === 'pin-text-tab' ? 'text' : 'file');
            });
        });

        // File handling
        els.pinDropZone.addEventListener('click', () => els.pinFileInput.click());
        els.pinDropZone.addEventListener('dragover', handleDragOver);
        els.pinDropZone.addEventListener('dragleave', handleDragLeave);
        els.pinDropZone.addEventListener('drop', handleDrop);
        els.pinFileInput.addEventListener('change', handleFileSelect);
        els.pinFileRemove.addEventListener('click', clearFiles);
        els.pinFilesClear.addEventListener('click', clearFiles);

        // Text input
        els.pinTextInput.addEventListener('input', handleTextInput);

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
    // Tab Switching
    // ==========================================

    function switchTab(tab) {
        activeTab = tab;

        // Update tab button styles
        els.pinTabBtns.forEach(btn => {
            const isActive = (tab === 'text' && btn.dataset.pinTab === 'pin-text-tab') ||
                             (tab === 'file' && btn.dataset.pinTab === 'pin-file-tab');
            btn.classList.toggle('active', isActive);
        });

        // Show/hide panels
        els.pinFileTab.style.display = tab === 'file' ? '' : 'none';
        els.pinTextTab.style.display = tab === 'text' ? '' : 'none';

        // Update button text
        els.pinUploadBtn.textContent = tab === 'text' ? 'Encrypt & Share' : 'Encrypt & Upload';

        updateUploadButton();
    }

    // ==========================================
    // Method Selection
    // ==========================================

    function selectMethod(method) {
        els.methodSelection.style.display = 'none';
        els.uploadSection.style.display = 'none';
        els.pinUploadSection.style.display = 'none';
        els.pinResultSection.style.display = 'none';

        if (method === 'link') {
            els.uploadSection.style.display = '';
        } else if (method === 'pin') {
            els.pinUploadSection.style.display = '';
        } else {
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

        const files = Array.from(e.dataTransfer.files);
        if (files.length > 0) {
            setFiles(files);
        }
    }

    function handleFileSelect(e) {
        const files = Array.from(e.target.files);
        if (files.length > 0) {
            setFiles(files);
        }
    }

    /**
     * Set selected files and update UI
     * @param {File[]} files
     */
    function setFiles(files) {
        // Validate count
        if (files.length > MAX_FILES) {
            Utils.showError(`Maximum ${MAX_FILES} files allowed. You selected ${files.length}.`);
            return;
        }

        // Validate total size
        const totalSize = files.reduce((sum, f) => sum + f.size, 0);
        if (totalSize > MAX_FILE_SIZE) {
            Utils.showError(`Total size exceeds 500 MB limit. Selected: ${Utils.formatFileSize(totalSize)}`);
            return;
        }

        // Reject empty files
        const emptyFiles = files.filter(f => f.size === 0);
        if (emptyFiles.length > 0) {
            Utils.showError('Cannot upload empty files');
            return;
        }

        selectedFiles = files;

        if (files.length === 1) {
            // Single file display
            els.pinFileName.textContent = files[0].name;
            els.pinFileSize.textContent = Utils.formatFileSize(files[0].size);
            els.pinFileInfo.style.display = '';
            els.pinFileList.style.display = 'none';
        } else {
            // Multi-file list display
            els.pinFileCount.textContent = `${files.length} files (${Utils.formatFileSize(totalSize)})`;
            els.pinFileListItems.innerHTML = '';
            files.forEach(f => {
                const li = document.createElement('li');
                li.textContent = `${f.name} (${Utils.formatFileSize(f.size)})`;
                els.pinFileListItems.appendChild(li);
            });
            els.pinFileList.style.display = '';
            els.pinFileInfo.style.display = 'none';
        }

        els.pinDropZone.style.display = 'none';
        updateUploadButton();
    }

    function clearFiles() {
        selectedFiles = [];
        els.pinFileInput.value = '';
        els.pinFileInfo.style.display = 'none';
        els.pinFileList.style.display = 'none';
        els.pinDropZone.style.display = '';
        updateUploadButton();
    }

    // ==========================================
    // Text Input
    // ==========================================

    function handleTextInput() {
        const len = els.pinTextInput.value.length;
        els.pinTextCharCount.textContent = len;
        updateUploadButton();
    }

    // ==========================================
    // PIN Input
    // ==========================================

    function handlePinInput() {
        const value = els.pinInput.value;
        els.pinCharCount.textContent = `${value.length}/4`;

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

    function setPinValidation(message, colorClass) {
        els.pinValidationMsg.textContent = message;
        els.pinValidationMsg.className = 'text-sm mt-1 min-h-[1.25rem]';
        if (colorClass) {
            colorClass.split(' ').forEach(cls => els.pinValidationMsg.classList.add(cls));
        }
    }

    // ==========================================
    // Upload Button State
    // ==========================================

    function updateUploadButton() {
        const hasValidPin = PIN_REGEX.test(els.pinInput.value);
        let hasContent = false;

        if (activeTab === 'file') {
            hasContent = selectedFiles.length > 0;
        } else {
            const text = els.pinTextInput.value.trim();
            hasContent = text.length > 0 && text.length <= MAX_TEXT_LENGTH;
        }

        els.pinUploadBtn.disabled = !hasContent || !hasValidPin || isUploading;
    }

    // ==========================================
    // Upload Flow
    // ==========================================

    async function handleUpload() {
        if (isUploading) return;

        if (activeTab === 'text') {
            await handleTextUpload();
        } else {
            await handleFileUpload();
        }
    }

    /**
     * Handle file upload (single or multi-file bundle)
     */
    async function handleFileUpload() {
        if (selectedFiles.length === 0) return;

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

            // If multiple files, bundle into ZIP first
            let fileToUpload;
            let fileName;

            if (selectedFiles.length > 1) {
                showProgress(2, 'Creating ZIP bundle...');
                const bundle = await ZipBundle.createBundle(selectedFiles, (percent) => {
                    showProgress(2 + percent * 0.08, `Bundling files... ${Math.round(percent)}%`);
                });
                fileToUpload = new File([bundle.blob], bundle.filename, { type: 'application/zip' });
                fileName = bundle.filename;
            } else {
                fileToUpload = selectedFiles[0];
                fileName = selectedFiles[0].name;
            }

            // Step 1: Get reCAPTCHA token
            showProgress(10, 'Verifying...');
            const recaptchaToken = await Utils.getRecaptchaToken(RECAPTCHA_SITE_KEY, 'pin_upload');

            // Step 2: Call PIN upload API
            showProgress(15, 'Initializing upload...');
            const initResponse = await callPinUploadApi({
                content_type: 'file',
                file_size: fileToUpload.size,
                file_name: fileName,
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
                fileToUpload,
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
     * Handle text secret upload with PIN
     */
    async function handleTextUpload() {
        const text = els.pinTextInput.value.trim();
        if (!text) return;

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
            showProgress(10, 'Verifying...');
            const recaptchaToken = await Utils.getRecaptchaToken(RECAPTCHA_SITE_KEY, 'pin_upload');

            // Step 2: Upload text as an encrypted file via S3
            // (PIN mode needs server salt before encryption, so we use file flow)
            showProgress(20, 'Initializing...');
            const textBlob = new Blob([new TextEncoder().encode(text)], { type: 'text/plain' });

            const initResponse = await callPinUploadApi({
                content_type: 'file',
                file_size: textBlob.size,
                file_name: 'secret.txt',
                pin: pin,
                ttl: ttl,
                recaptcha_token: recaptchaToken,
            });

            const { file_id, upload_url, salt, expires_at } = initResponse;

            // Step 3: Derive encryption key from PIN + server salt
            showProgress(40, 'Deriving encryption key...');
            const saltBytes = hexToUint8Array(salt);
            const encryptionKey = await CryptoModule.deriveKeyFromPassword(pin, saltBytes, true);

            // Step 4: Encrypt text as file
            showProgress(50, 'Encrypting text...');
            const textFile = new File([textBlob], 'secret.txt', { type: 'text/plain' });
            const encryptedData = await CryptoModule.encryptFile(
                textFile,
                encryptionKey,
                (progress) => {
                    showProgress(50 + progress * 0.2, `Encrypting... ${Math.round(progress)}%`);
                }
            );

            // Step 5: Upload to S3
            showProgress(75, 'Uploading...');
            await uploadToS3(upload_url, encryptedData);

            // Step 6: Show result
            showProgress(100, 'Upload complete!');
            showResult(file_id, pin, ttl, expires_at);

        } catch (error) {
            console.error('PIN text upload error:', error);
            Utils.showError(error.message || 'Upload failed. Please try again.');
            resetUploadState();
        }
    }

    /**
     * Call the PIN upload API
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

    function showResult(fileId, pin, ttl, expiresAt) {
        els.pinUploadSection.style.display = 'none';
        els.pinResultSection.style.display = '';

        els.pinCodeValue.textContent = fileId;
        els.pinCodeRepeat.textContent = fileId;

        els.pinDisplayValue.textContent = pin;
        els.pinDisplayMasked.style.display = '';
        els.pinDisplayValue.style.display = 'none';
        els.pinRevealBtn.textContent = 'Show';

        els.pinExpiryLabel.textContent = TTL_LABELS[ttl] || ttl;
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
        resetUploadState();
        selectedFiles = [];
        activeTab = 'file';
        els.pinInput.value = '';
        els.pinCharCount.textContent = '0/4';
        setPinValidation('', '');
        els.pinFileInput.value = '';
        els.pinFileInfo.style.display = 'none';
        els.pinFileList.style.display = 'none';
        els.pinDropZone.style.display = '';
        els.pinTextInput.value = '';
        els.pinTextCharCount.textContent = '0';
        switchTab('file');
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

    function getSelectedTTL() {
        const radio = document.querySelector('input[name="pin-ttl"]:checked');
        return radio ? radio.value : '24h';
    }

    /**
     * Convert hex string to Uint8Array
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
    if (document.getElementById('method-selection')) {
        PinUpload.init();
    }
});
