/**
 * Upload page functionality
 */

'use strict';

// Configuration
const CONFIG = {
    API_BASE_URL: '/dev',  // Routed through CloudFront to API Gateway
    MAX_FILE_SIZE: 100 * 1024 * 1024, // 100 MB
    RECAPTCHA_SITE_KEY: '6LdV7DAsAAAAAI3U_2efIlWrcOuRiUDS4N3SQhQD',  // Public site key
};

// DOM elements
const elements = {
    dropZone: document.getElementById('drop-zone'),
    fileInput: document.getElementById('file-input'),
    fileInfo: document.getElementById('file-info'),
    fileName: document.getElementById('file-name'),
    fileSize: document.getElementById('file-size'),
    uploadBtn: document.getElementById('upload-btn'),
    progressSection: document.getElementById('progress-section'),
    progressFill: document.getElementById('progress-fill'),
    progressText: document.getElementById('progress-text'),
    resultSection: document.getElementById('result-section'),
    shareUrl: document.getElementById('share-url'),
    copyBtn: document.getElementById('copy-btn'),
    newUploadBtn: document.getElementById('new-upload-btn'),
};

// State
let selectedFile = null;

// Event listeners
elements.dropZone.addEventListener('click', () => elements.fileInput.click());
elements.dropZone.addEventListener('dragover', handleDragOver);
elements.dropZone.addEventListener('dragleave', handleDragLeave);
elements.dropZone.addEventListener('drop', handleDrop);
elements.fileInput.addEventListener('change', handleFileSelect);
elements.uploadBtn.addEventListener('click', handleUpload);
elements.copyBtn.addEventListener('click', handleCopy);
elements.newUploadBtn.addEventListener('click', resetForm);

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
        selectFile(files[0]);
    }
}

/**
 * Handle file selection from input
 */
function handleFileSelect(e) {
    const files = e.target.files;
    if (files.length > 0) {
        selectFile(files[0]);
    }
}

/**
 * Select and validate file
 */
function selectFile(file) {
    // Validate file size
    if (!Utils.validateFileSize(file.size, CONFIG.MAX_FILE_SIZE)) {
        Utils.showError(`File size exceeds maximum limit of ${Utils.formatFileSize(CONFIG.MAX_FILE_SIZE)}`);
        return;
    }

    selectedFile = file;

    // Update UI
    elements.fileName.textContent = file.name;
    elements.fileSize.textContent = Utils.formatFileSize(file.size);
    elements.fileInfo.style.display = 'block';
    elements.uploadBtn.disabled = false;
}

/**
 * Get selected TTL value
 */
function getSelectedTTL() {
    const ttlRadio = document.querySelector('input[name="ttl"]:checked');
    return ttlRadio ? ttlRadio.value : '1h';
}

/**
 * Handle file upload
 */
async function handleUpload() {
    if (!selectedFile) return;

    try {
        elements.uploadBtn.disabled = true;
        elements.progressSection.style.display = 'block';

        // Generate encryption key
        updateProgress(0, 'Generating encryption key...');
        const key = await CryptoModule.generateKey();

        // Encrypt file
        updateProgress(20, 'Encrypting file...');
        const encryptedData = await CryptoModule.encryptFile(
            selectedFile,
            key,
            (progress) => updateProgress(20 + (progress * 0.3), 'Encrypting file...')
        );

        // Initialize upload
        updateProgress(50, 'Initializing upload...');
        const ttl = getSelectedTTL();
        const uploadData = await initializeUpload(selectedFile.size, selectedFile.name, ttl);

        // Upload to S3
        updateProgress(60, 'Uploading encrypted file...');
        await uploadToS3(uploadData.upload_url, encryptedData);

        // Generate share URL
        updateProgress(90, 'Generating share link...');
        const keyBase64 = await CryptoModule.keyToBase64(key);
        // Encode filename in URL so it can be extracted on download page
        const encodedFileName = encodeURIComponent(selectedFile.name);
        const shareUrl = `${window.location.origin}/download.html#${uploadData.file_id}#${keyBase64}#${encodedFileName}`;

        // Show result
        updateProgress(100, 'Upload complete!');
        showResult(shareUrl);

    } catch (error) {
        console.error('Upload error:', error);
        Utils.showError('Upload failed. Please try again.');
        resetForm();
    }
}

/**
 * Get reCAPTCHA token
 */
async function getRecaptchaToken() {
    try {
        return await grecaptcha.execute(CONFIG.RECAPTCHA_SITE_KEY, { action: 'upload' });
    } catch (error) {
        console.error('reCAPTCHA error:', error);
        throw new Error('Failed to verify reCAPTCHA. Please refresh and try again.');
    }
}

/**
 * Initialize upload with API
 */
async function initializeUpload(fileSize, fileName, ttl) {
    // Get reCAPTCHA token
    const recaptchaToken = await getRecaptchaToken();

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
 * Upload encrypted data to S3
 */
async function uploadToS3(presignedUrl, data) {
    const response = await fetch(presignedUrl, {
        method: 'PUT',
        body: data,
        headers: {
            'Content-Type': 'application/octet-stream',
        },
    });

    if (!response.ok) {
        throw new Error(`S3 upload failed: ${response.status}`);
    }
}

/**
 * Update progress bar and text
 */
function updateProgress(percent, text) {
    elements.progressFill.style.width = `${percent}%`;
    elements.progressText.textContent = text;
}

/**
 * Show upload result
 */
function showResult(shareUrl) {
    elements.progressSection.style.display = 'none';
    elements.resultSection.style.display = 'block';
    elements.shareUrl.value = shareUrl;
    elements.shareUrl.select();
}

/**
 * Handle copy to clipboard
 */
async function handleCopy() {
    const success = await Utils.copyToClipboard(elements.shareUrl.value);
    if (success) {
        elements.copyBtn.textContent = 'Copied!';
        setTimeout(() => {
            elements.copyBtn.textContent = 'Copy';
        }, 2000);
    } else {
        Utils.showError('Failed to copy to clipboard');
    }
}

/**
 * Reset form to initial state
 */
function resetForm() {
    selectedFile = null;
    elements.fileInput.value = '';
    elements.fileInfo.style.display = 'none';
    elements.uploadBtn.disabled = true;
    elements.progressSection.style.display = 'none';
    elements.resultSection.style.display = 'none';
    elements.progressFill.style.width = '0%';
}
