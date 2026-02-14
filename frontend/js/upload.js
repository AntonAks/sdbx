/**
 * Upload page functionality
 * Supports single files and multi-file ZIP bundles
 */

'use strict';

// Configuration
const CONFIG = {
    API_BASE_URL: '/prod',  // Routed through CloudFront to API Gateway
    MAX_FILE_SIZE: 500 * 1024 * 1024, // 500 MB
    RECAPTCHA_SITE_KEY: '6LdulTIsAAAAAJdhvyMU6B1og7GE7d5DySrQUQiv',  // Public site key
};

// DOM elements
const elements = {
    dropZone: document.getElementById('drop-zone'),
    fileInput: document.getElementById('file-input'),
    fileList: document.getElementById('file-list'),
    fileItems: document.getElementById('file-items'),
    fileCount: document.getElementById('file-count'),
    totalSize: document.getElementById('total-size'),
    clearFilesBtn: document.getElementById('clear-files-btn'),
    uploadBtn: document.getElementById('upload-btn'),
    progressSection: document.getElementById('progress-section'),
    progressFill: document.getElementById('progress-fill'),
    progressText: document.getElementById('progress-text'),
    // Custom TTL elements
    customTtlInput: document.getElementById('custom-ttl-input'),
    customTtlValue: document.getElementById('custom-ttl-value'),
    customTtlUnit: document.getElementById('custom-ttl-unit'),
    ttlPreviewTime: document.getElementById('ttl-preview-time'),
};

// State
let selectedFiles = [];

// Event listeners
elements.dropZone.addEventListener('click', () => elements.fileInput.click());
elements.dropZone.addEventListener('dragover', handleDragOver);
elements.dropZone.addEventListener('dragleave', handleDragLeave);
elements.dropZone.addEventListener('drop', handleDrop);
elements.fileInput.addEventListener('change', handleFileSelect);
elements.uploadBtn.addEventListener('click', handleUpload);
elements.clearFilesBtn.addEventListener('click', clearFiles);

// Custom TTL toggle
document.querySelectorAll('input[name="ttl"]').forEach(radio => {
    radio.addEventListener('change', (e) => {
        handleTtlChange(e);
        updateExpirationPreview();
    });
});

// Custom TTL unit change - update value options and preview
elements.customTtlUnit.addEventListener('change', () => {
    updateTtlValueOptions(elements.customTtlValue, elements.customTtlUnit.value);
    updateExpirationPreview();
});

// Custom TTL value change - update preview
elements.customTtlValue.addEventListener('change', updateExpirationPreview);

// Initialize value dropdown with hours options (default)
updateTtlValueOptions(elements.customTtlValue, 'hours');

// Initialize expiration preview
updateExpirationPreview();

/**
 * Handle TTL radio change - show/hide custom input
 */
function handleTtlChange(e) {
    if (e.target.value === 'custom') {
        elements.customTtlInput.style.display = 'block';
    } else {
        elements.customTtlInput.style.display = 'none';
    }
}

/**
 * Update TTL value dropdown options based on selected unit
 */
function updateTtlValueOptions(selectElement, unit) {
    const options = {
        minutes: [5, 10, 20, 30, 40, 50],
        hours: [2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 24],
        days: Array.from({ length: 7 }, (_, i) => i + 1),
    };

    const values = options[unit] || options.hours;
    selectElement.innerHTML = values.map(v => `<option value="${v}">${v}</option>`).join('');
}

/**
 * Update expiration time preview based on selected TTL
 */
function updateExpirationPreview() {
    const ttl = getSelectedTTL();
    let minutes;

    if (typeof ttl === 'number') {
        minutes = ttl;
    } else {
        // Convert preset to minutes
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
}

/**
 * Update file list UI
 */
function updateFileListUI() {
    if (selectedFiles.length === 0) {
        elements.fileList.style.display = 'none';
        elements.uploadBtn.disabled = true;
        return;
    }

    // Show file list
    elements.fileList.style.display = 'block';
    elements.uploadBtn.disabled = false;

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
    }
}

/**
 * Clear all selected files
 */
function clearFiles() {
    selectedFiles = [];
    elements.fileInput.value = '';
    updateFileListUI();
}

/**
 * Get selected TTL value
 * Returns preset string ("1h", "12h", "24h") or minutes (number) for custom
 */
function getSelectedTTL() {
    const ttlRadio = document.querySelector('input[name="ttl"]:checked');
    if (!ttlRadio) return '1h';

    if (ttlRadio.value === 'custom') {
        const value = parseInt(elements.customTtlValue.value, 10);
        const unit = elements.customTtlUnit.value;

        switch (unit) {
            case 'hours':
                return value * 60;
            case 'days':
                return value * 60 * 24;
            default: // minutes
                return value;
        }
    }

    return ttlRadio.value;
}

/**
 * Handle file upload
 */
async function handleUpload() {
    if (selectedFiles.length === 0) return;

    try {
        elements.uploadBtn.disabled = true;
        elements.progressSection.style.display = 'block';

        let fileToUpload;
        let uploadFileName;

        if (selectedFiles.length === 1) {
            // Single file: existing flow (no ZIP)
            fileToUpload = selectedFiles[0];
            uploadFileName = selectedFiles[0].name;
            updateProgress(0, 'Preparing file...');
        } else {
            // Multiple files: create ZIP bundle
            updateProgress(0, 'Creating ZIP bundle...');
            const bundle = await ZipBundle.createBundle(
                selectedFiles,
                (percent, message) => {
                    // Map bundle creation to 0-15% of overall progress
                    updateProgress(percent * 0.15, message);
                }
            );
            fileToUpload = bundle.blob;
            uploadFileName = bundle.filename;
        }

        // Generate encryption key
        updateProgress(15, 'Generating encryption key...');
        const key = await CryptoModule.generateKey();

        // Encrypt file/bundle
        updateProgress(20, 'Encrypting... 0%');
        const encryptedData = await CryptoModule.encryptFile(
            fileToUpload,
            key,
            (progress) => {
                const percent = 20 + (progress * 0.3);
                updateProgress(percent, `Encrypting... ${Math.round(progress)}%`);
            }
        );

        // Initialize upload
        updateProgress(50, 'Initializing upload...');
        const ttl = getSelectedTTL();
        const fileSize = fileToUpload.size || fileToUpload.byteLength;
        const uploadData = await initializeUpload(fileSize, uploadFileName, ttl);

        // Upload to S3
        updateProgress(60, 'Uploading encrypted file...');
        await uploadToS3(uploadData.upload_url, encryptedData);

        // Generate share page URL and redirect
        updateProgress(100, 'Upload complete! Redirecting...');
        const keyBase64 = await CryptoModule.keyToBase64(key);
        const encodedFileName = encodeURIComponent(uploadFileName);
        const sharePageUrl = `/share.html#${uploadData.file_id}#${keyBase64}#${encodedFileName}`;

        // Small delay to show completion, then redirect
        setTimeout(() => {
            window.location.href = sharePageUrl;
        }, 500);

    } catch (error) {
        console.error('Upload error:', error);
        Utils.showError(error.message || 'Upload failed. Please try again.');
        resetForm();
    }
}

/**
 * Initialize upload with API
 */
async function initializeUpload(fileSize, fileName, ttl) {
    // Get reCAPTCHA token
    const recaptchaToken = await Utils.getRecaptchaToken(CONFIG.RECAPTCHA_SITE_KEY, 'upload');

    const response = await fetch(`${CONFIG.API_BASE_URL}/upload/init`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            file_size: fileSize,
            ttl: ttl,
            recaptcha_token: recaptchaToken,
        }),
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.error || `Upload initialization failed: ${response.status}`;
        throw new Error(errorMessage);
    }

    return response.json();
}

/**
 * Upload encrypted data to S3 with real progress tracking
 */
async function uploadToS3(presignedUrl, data) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();

        // Track upload progress
        xhr.upload.onprogress = (event) => {
            if (event.lengthComputable) {
                const percentComplete = (event.loaded / event.total) * 100;
                // Map to 60-90% of overall progress
                const overallPercent = 60 + (percentComplete * 0.3);
                updateProgress(overallPercent, `Uploading... ${percentComplete.toFixed(1)}%`);
            }
        };

        // Handle completion
        xhr.onload = () => {
            if (xhr.status >= 200 && xhr.status < 300) {
                resolve();
            } else {
                reject(new Error(`S3 upload failed: ${xhr.status}`));
            }
        };

        // Handle errors
        xhr.onerror = () => {
            reject(new Error('Network error during upload'));
        };

        xhr.ontimeout = () => {
            reject(new Error('Upload timeout'));
        };

        // Configure and send request
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
