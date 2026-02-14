/**
 * Vault upload functionality
 * Handles password-protected multi-access file and text sharing
 * Supports single files and multi-file ZIP bundles
 */

'use strict';

(function() {
    // Configuration
    const CONFIG = {
        API_BASE_URL: '/prod',
        MAX_FILE_SIZE: 500 * 1024 * 1024, // 500 MB
        RECAPTCHA_SITE_KEY: '6LdulTIsAAAAAJdhvyMU6B1og7GE7d5DySrQUQiv',
    };

    // DOM Elements
    const elements = {
        // Content type toggle
        contentTypeRadios: document.querySelectorAll('input[name="vault-content-type"]'),
        fileSection: document.getElementById('vault-file-section'),
        textSection: document.getElementById('vault-text-section'),
        // File input
        dropZone: document.getElementById('vault-drop-zone'),
        fileInput: document.getElementById('vault-file-input'),
        fileList: document.getElementById('vault-file-list'),
        fileItems: document.getElementById('vault-file-items'),
        fileCount: document.getElementById('vault-file-count'),
        totalSize: document.getElementById('vault-total-size'),
        clearFilesBtn: document.getElementById('vault-clear-files-btn'),
        // Text input
        textInput: document.getElementById('vault-text-input'),
        charCount: document.getElementById('vault-char-count'),
        // Password
        password: document.getElementById('vault-password'),
        togglePassword: document.getElementById('vault-toggle-password'),
        // TTL
        customTtlInput: document.getElementById('vault-custom-ttl-input'),
        customTtlValue: document.getElementById('vault-custom-ttl-value'),
        customTtlUnit: document.getElementById('vault-custom-ttl-unit'),
        ttlPreviewTime: document.getElementById('vault-ttl-preview-time'),
        // Upload
        uploadBtn: document.getElementById('vault-upload-btn'),
        progressSection: document.getElementById('vault-progress-section'),
        progressFill: document.getElementById('vault-progress-fill'),
        progressText: document.getElementById('vault-progress-text'),
    };

    // State
    let selectedFiles = [];

    /**
     * Initialize vault upload functionality
     */
    function init() {
        if (!elements.dropZone) return; // Not on the right page

        // Content type toggle
        elements.contentTypeRadios.forEach(radio => {
            radio.addEventListener('change', handleContentTypeChange);
        });

        // File handling
        elements.dropZone.addEventListener('click', () => elements.fileInput.click());
        elements.dropZone.addEventListener('dragover', handleDragOver);
        elements.dropZone.addEventListener('dragleave', handleDragLeave);
        elements.dropZone.addEventListener('drop', handleDrop);
        elements.fileInput.addEventListener('change', handleFileSelect);
        elements.clearFilesBtn.addEventListener('click', clearFiles);

        // Text input
        elements.textInput.addEventListener('input', handleTextInput);

        // Password toggle
        elements.togglePassword.addEventListener('click', togglePasswordVisibility);

        // Password input - update button state
        elements.password.addEventListener('input', updateUploadButtonState);

        // Upload button
        elements.uploadBtn.addEventListener('click', handleVaultUpload);

        // TTL handling
        document.querySelectorAll('input[name="vault-ttl"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                handleTtlChange(e);
                updateExpirationPreview();
            });
        });

        elements.customTtlUnit.addEventListener('change', () => {
            updateTtlValueOptions();
            updateExpirationPreview();
        });

        elements.customTtlValue.addEventListener('change', updateExpirationPreview);

        // Initialize
        updateTtlValueOptions();
        updateExpirationPreview();
    }

    /**
     * Handle content type toggle (file/text)
     */
    function handleContentTypeChange(e) {
        const contentType = e.target.value;

        if (contentType === 'file') {
            elements.fileSection.style.display = 'block';
            elements.textSection.style.display = 'none';
        } else {
            elements.fileSection.style.display = 'none';
            elements.textSection.style.display = 'block';
        }

        updateUploadButtonState();
    }

    /**
     * Handle drag over event
     */
    function handleDragOver(e) {
        e.preventDefault();
        elements.dropZone.classList.add('drag-over');
    }

    /**
     * Handle drag leave event
     */
    function handleDragLeave(e) {
        e.preventDefault();
        elements.dropZone.classList.remove('drag-over');
    }

    /**
     * Handle file drop
     */
    function handleDrop(e) {
        e.preventDefault();
        elements.dropZone.classList.remove('drag-over');

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            addFiles(files);
        }
    }

    /**
     * Handle file selection from input
     */
    function handleFileSelect(e) {
        const files = e.target.files;
        if (files.length > 0) {
            addFiles(files);
        }
    }

    /**
     * Add files to selection
     * @param {FileList} newFiles
     */
    function addFiles(newFiles) {
        const newFilesArray = Array.from(newFiles);

        // Combine with existing files
        const combinedFiles = [...selectedFiles, ...newFilesArray];

        // Validate combined files
        const validation = ZipBundle.validateFiles(combinedFiles);
        if (!validation.valid) {
            Utils.showError(validation.error);
            return;
        }

        // Update state
        selectedFiles = combinedFiles;
        updateFileListUI();
        updateUploadButtonState();
    }

    /**
     * Update file list UI
     */
    function updateFileListUI() {
        if (selectedFiles.length === 0) {
            elements.fileList.style.display = 'none';
            return;
        }

        // Show file list
        elements.fileList.style.display = 'block';

        // Update counts
        elements.fileCount.textContent = selectedFiles.length;

        // Calculate total size
        const totalSize = selectedFiles.reduce((sum, file) => sum + file.size, 0);
        elements.totalSize.textContent = Utils.formatFileSize(totalSize);

        // Render file items
        elements.fileItems.innerHTML = '';
        selectedFiles.forEach((file, index) => {
            const li = document.createElement('li');
            li.className = 'flex justify-between items-center text-sm py-1 border-b border-gray-200 dark:border-slate-700 last:border-0';
            li.innerHTML = `
                <span class="text-gray-700 dark:text-slate-300 truncate mr-2" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</span>
                <div class="flex items-center gap-3 flex-shrink-0">
                    <span class="text-gray-500 dark:text-slate-500">${Utils.formatFileSize(file.size)}</span>
                    <button type="button" class="text-red-500 hover:text-red-600 dark:text-red-400 dark:hover:text-red-300 p-1" data-remove-index="${index}" title="Remove file">
                        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                            <path d="M6 18L18 6M6 6l12 12"/>
                        </svg>
                    </button>
                </div>
            `;
            elements.fileItems.appendChild(li);
        });

        // Add event listeners to remove buttons
        elements.fileItems.querySelectorAll('[data-remove-index]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const index = parseInt(e.currentTarget.dataset.removeIndex, 10);
                removeFile(index);
            });
        });
    }

    /**
     * Escape HTML special characters
     * @param {string} text
     * @returns {string}
     */
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Remove file at index
     * @param {number} index
     */
    function removeFile(index) {
        if (index >= 0 && index < selectedFiles.length) {
            selectedFiles.splice(index, 1);
            updateFileListUI();
            updateUploadButtonState();
        }
    }

    /**
     * Clear all selected files
     */
    function clearFiles() {
        selectedFiles = [];
        elements.fileInput.value = '';
        updateFileListUI();
        updateUploadButtonState();
    }

    /**
     * Handle text input
     */
    function handleTextInput() {
        const length = elements.textInput.value.length;
        elements.charCount.textContent = length.toLocaleString();
        updateUploadButtonState();
    }

    /**
     * Toggle password visibility
     */
    function togglePasswordVisibility() {
        if (elements.password.type === 'password') {
            elements.password.type = 'text';
            elements.togglePassword.textContent = 'Hide';
        } else {
            elements.password.type = 'password';
            elements.togglePassword.textContent = 'Show';
        }
    }

    /**
     * Update upload button state
     */
    function updateUploadButtonState() {
        const contentType = document.querySelector('input[name="vault-content-type"]:checked')?.value || 'file';
        const password = elements.password.value;

        let hasContent = false;
        if (contentType === 'file') {
            hasContent = selectedFiles.length > 0;
        } else {
            hasContent = elements.textInput.value.trim().length > 0;
        }

        const hasPassword = password.length >= 4;

        elements.uploadBtn.disabled = !hasContent || !hasPassword;
    }

    /**
     * Handle TTL radio change
     */
    function handleTtlChange(e) {
        if (e.target.value === 'custom') {
            elements.customTtlInput.style.display = 'block';
        } else {
            elements.customTtlInput.style.display = 'none';
        }
    }

    /**
     * Update TTL value dropdown options based on unit
     */
    function updateTtlValueOptions() {
        const unit = elements.customTtlUnit.value;
        const options = {
            hours: [2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 24],
            days: Array.from({ length: 7 }, (_, i) => i + 1),
        };

        const values = options[unit] || options.hours;
        elements.customTtlValue.innerHTML = values.map(v => `<option value="${v}">${v}</option>`).join('');
    }

    /**
     * Update expiration preview
     */
    function updateExpirationPreview() {
        const ttl = getSelectedTTL();
        let minutes;

        if (typeof ttl === 'number') {
            minutes = ttl;
        } else {
            const presetMinutes = { '1h': 60, '12h': 720, '24h': 1440 };
            minutes = presetMinutes[ttl] || 60;
        }

        const expirationDate = new Date(Date.now() + minutes * 60 * 1000);
        elements.ttlPreviewTime.textContent = formatExpirationDate(expirationDate);
    }

    /**
     * Format expiration date for display
     */
    function formatExpirationDate(date) {
        const options = {
            weekday: 'short',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        };
        return date.toLocaleString(undefined, options);
    }

    /**
     * Get selected TTL value
     */
    function getSelectedTTL() {
        const ttlRadio = document.querySelector('input[name="vault-ttl"]:checked');
        if (!ttlRadio) return '1h';

        if (ttlRadio.value === 'custom') {
            const value = parseInt(elements.customTtlValue.value, 10);
            const unit = elements.customTtlUnit.value;

            if (unit === 'days') {
                return value * 60 * 24;
            }
            return value * 60; // hours to minutes
        }

        return ttlRadio.value;
    }

    /**
     * Handle vault upload
     */
    async function handleVaultUpload() {
        const contentType = document.querySelector('input[name="vault-content-type"]:checked')?.value || 'file';
        const password = elements.password.value;

        if (!password || password.length < 4) {
            Utils.showError('Password must be at least 4 characters');
            return;
        }

        try {
            elements.uploadBtn.disabled = true;
            elements.progressSection.style.display = 'block';

            // Get content to encrypt
            let fileToUpload, uploadFileName;
            if (contentType === 'file') {
                if (selectedFiles.length === 0) {
                    Utils.showError('Please select at least one file');
                    resetForm();
                    return;
                }

                if (selectedFiles.length === 1) {
                    // Single file: no ZIP needed
                    fileToUpload = selectedFiles[0];
                    uploadFileName = selectedFiles[0].name;
                    updateProgress(0, 'Preparing file...');
                } else {
                    // Multiple files: create ZIP bundle
                    updateProgress(0, 'Creating ZIP bundle...');
                    const bundle = await ZipBundle.createBundle(
                        selectedFiles,
                        (percent, message) => {
                            // Map bundle creation to 0-5% of overall progress
                            updateProgress(percent * 0.05, message);
                        }
                    );
                    fileToUpload = bundle.blob;
                    uploadFileName = bundle.filename;
                }
            } else {
                const text = elements.textInput.value.trim();
                if (!text) {
                    Utils.showError('Please enter text');
                    resetForm();
                    return;
                }
                fileToUpload = new TextEncoder().encode(text);
                uploadFileName = null;
            }

            // Step 1: Generate random data key
            updateProgress(5, 'Generating encryption key...');
            const dataKey = await CryptoModule.generateKey();

            // Step 2: Generate salt and derive password key
            updateProgress(10, 'Deriving password key...');
            const salt = CryptoModule.generateSalt();
            const passwordKey = await CryptoModule.deriveKeyFromPassword(password, salt);

            // Step 3: Encrypt the data key with password-derived key
            updateProgress(15, 'Securing encryption key...');
            const encryptedKeyData = await CryptoModule.encryptKey(dataKey, passwordKey);
            const encryptedKeyBase64 = CryptoModule.arrayToBase64(encryptedKeyData);
            const saltBase64 = CryptoModule.arrayToBase64(salt);

            // Step 4: Encrypt content with data key
            updateProgress(20, 'Encrypting content...');
            let encryptedData;
            if (contentType === 'file') {
                encryptedData = await CryptoModule.encryptFile(fileToUpload, dataKey, (p) => {
                    updateProgress(20 + p * 0.3, `Encrypting... ${Math.round(p)}%`);
                });
            } else {
                encryptedData = await CryptoModule.encrypt(fileToUpload, dataKey);
            }

            // Step 5: Initialize upload
            updateProgress(50, 'Initializing vault...');
            const ttl = getSelectedTTL();
            const recaptchaToken = await Utils.getRecaptchaToken(CONFIG.RECAPTCHA_SITE_KEY, 'vault');

            const requestBody = {
                content_type: contentType,
                ttl: ttl,
                recaptcha_token: recaptchaToken,
                access_mode: 'multi',
                salt: saltBase64,
                encrypted_key: encryptedKeyBase64,
            };

            if (contentType === 'file') {
                requestBody.file_size = encryptedData.byteLength;
            } else {
                // Convert to base64 for text
                requestBody.encrypted_text = CryptoModule.arrayToBase64(encryptedData);
            }

            const response = await fetch(`${CONFIG.API_BASE_URL}/upload/init`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestBody),
            });

            if (!response.ok) {
                const error = await response.json().catch(() => ({}));
                throw new Error(error.error || `Upload failed: ${response.status}`);
            }

            const data = await response.json();

            // Step 6: Upload file to S3 if content type is file
            if (contentType === 'file') {
                updateProgress(60, 'Uploading encrypted file...');
                await uploadToS3(data.upload_url, encryptedData);
            }

            updateProgress(100, 'Complete! Redirecting...');

            // Generate vault share URL
            // Format: #file_id#salt#filename#vault
            const encodedFileName = uploadFileName ? encodeURIComponent(uploadFileName) : '';
            const shareUrl = `/share.html#${data.file_id}#${saltBase64}#${encodedFileName}#vault`;

            setTimeout(() => {
                window.location.href = shareUrl;
            }, 500);

        } catch (error) {
            console.error('Vault upload error:', error);
            Utils.showError(error.message || 'Upload failed. Please try again.');
            resetForm();
        }
    }

    /**
     * Upload encrypted data to S3
     */
    async function uploadToS3(presignedUrl, data) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();

            xhr.upload.onprogress = (event) => {
                if (event.lengthComputable) {
                    const percentComplete = (event.loaded / event.total) * 100;
                    const overallPercent = 60 + (percentComplete * 0.35);
                    updateProgress(overallPercent, `Uploading... ${percentComplete.toFixed(1)}%`);
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

    /**
     * Update progress bar and text
     */
    function updateProgress(percent, text) {
        elements.progressFill.style.width = `${percent}%`;
        elements.progressText.textContent = text;
    }

    /**
     * Reset form to initial state
     */
    function resetForm() {
        selectedFiles = [];
        elements.fileInput.value = '';
        elements.fileList.style.display = 'none';
        elements.uploadBtn.disabled = true;
        elements.progressSection.style.display = 'none';
        elements.progressFill.style.width = '0%';
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
