/**
 * Download page functionality
 */

'use strict';

// Configuration
const CONFIG = {
    API_BASE_URL: '/prod',  // Routed through CloudFront to API Gateway
    RECAPTCHA_SITE_KEY: '6LdulTIsAAAAAJdhvyMU6B1og7GE7d5DySrQUQiv',  // Public site key
};

// DOM elements
const elements = {
    loadingSection: document.getElementById('loading-section'),
    availableSection: document.getElementById('available-section'),
    errorSection: document.getElementById('error-section'),
    successSection: document.getElementById('success-section'),
    textDisplaySection: document.getElementById('text-display-section'),
    contentTitle: document.getElementById('content-title'),
    sizeLabel: document.getElementById('size-label'),
    warningText: document.getElementById('warning-text'),
    fileSize: document.getElementById('file-size'),
    expiresIn: document.getElementById('expires-in'),
    downloadBtn: document.getElementById('download-btn'),
    downloadProgress: document.getElementById('download-progress'),
    progressFill: document.getElementById('progress-fill'),
    progressText: document.getElementById('progress-text'),
    errorMessage: document.getElementById('error-message'),
    reportAbuse: document.getElementById('report-abuse'),
    decryptedText: document.getElementById('decrypted-text'),
    copyTextBtn: document.getElementById('copy-text-btn'),
};

// State
let fileId = null;
let encryptionKey = null;
let fileName = null;
let countdownInterval = null;

// Initialize
init();

/**
 * Initialize download page
 */
async function init() {
    try {
        // Get file ID, key, and filename from URL
        fileId = Utils.getFileIdFromUrl();
        const keyBase64 = Utils.getKeyFromFragment();
        fileName = Utils.getFileNameFromFragment();

        console.log('Parsed from URL:', { fileId, keyBase64: keyBase64?.substring(0, 10) + '...', fileName });

        if (!fileId || !keyBase64) {
            showError('Invalid download link');
            return;
        }

        // Import encryption key
        encryptionKey = await CryptoModule.base64ToKey(keyBase64);

        // Check file availability
        await checkFileAvailability();

    } catch (error) {
        console.error('Initialization error:', error);
        showError('Failed to load file information');
    }
}

/**
 * Check if file is available for download
 */
async function checkFileAvailability() {
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/files/${fileId}/metadata`);

        if (response.status === 404) {
            showError('File not found');
            return;
        }

        if (response.status === 410) {
            showError('File has expired or was already downloaded');
            return;
        }

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const metadata = await response.json();

        if (!metadata.available) {
            showError('File has already been downloaded');
            return;
        }

        // Show file info
        showFileInfo(metadata);

    } catch (error) {
        console.error('Error checking file availability:', error);
        showError('Failed to check file availability');
    }
}

/**
 * Show file information
 */
function showFileInfo(metadata) {
    elements.loadingSection.style.display = 'none';
    elements.availableSection.style.display = 'block';

    // Update UI labels based on content type
    const isText = metadata.content_type === 'text';

    if (isText) {
        elements.contentTitle.textContent = 'Secret Text Ready';
        elements.sizeLabel.textContent = 'Text Size:';
        elements.warningText.textContent = 'This text can only be viewed ONCE';
        elements.downloadBtn.textContent = 'View Secret';
    } else {
        elements.contentTitle.textContent = 'File Ready to Download';
        elements.sizeLabel.textContent = 'File Size:';
        elements.warningText.textContent = 'This file can only be downloaded ONCE';
        elements.downloadBtn.textContent = 'Download Now';
    }

    // Display size
    elements.fileSize.textContent = Utils.formatFileSize(metadata.file_size);

    // Display expiration time
    updateExpirationCountdown(metadata.expires_at);

    // Set up download button
    elements.downloadBtn.addEventListener('click', handleDownload);

    // Set up report abuse link
    elements.reportAbuse.addEventListener('click', (e) => {
        e.preventDefault();
        handleReportAbuse();
    });
}

/**
 * Update expiration countdown
 */
function updateExpirationCountdown(expiresAt) {
    const update = () => {
        const now = Utils.getCurrentTimestamp();
        const remaining = expiresAt - now;

        if (remaining <= 0) {
            elements.expiresIn.textContent = 'Expired';
            clearInterval(countdownInterval);
            showError('File has expired');
            return;
        }

        elements.expiresIn.textContent = Utils.formatTimeRemaining(remaining);
    };

    update();
    countdownInterval = setInterval(update, 60000); // Update every minute
}

/**
 * Handle file download
 */
async function handleDownload() {
    try {
        elements.downloadBtn.disabled = true;
        elements.downloadProgress.style.display = 'block';

        // Request download URL or text
        updateProgress(0, 'Preparing download...');
        const downloadData = await requestDownload();

        // Check content type
        if (downloadData.content_type === 'text') {
            // Handle text secret
            updateProgress(50, 'Decrypting text... 0%');

            // Decode base64 encrypted text
            const encryptedBytes = Uint8Array.from(atob(downloadData.encrypted_text), c => c.charCodeAt(0));

            // Decrypt text
            const decryptedData = await CryptoModule.decryptFile(
                encryptedBytes,
                encryptionKey,
                (progress) => {
                    const percent = 50 + (progress * 0.4);
                    updateProgress(percent, `Decrypting text... ${Math.round(progress)}%`);
                }
            );

            // Convert to string
            const decoder = new TextDecoder();
            const decryptedText = decoder.decode(decryptedData);

            // Display text
            updateProgress(100, 'Complete!');
            showTextSecret(decryptedText);

            // Confirm successful download
            await confirmDownload();

        } else {
            // Handle file download
            updateProgress(30, 'Downloading encrypted file...');
            const encryptedData = await downloadFile(downloadData.download_url);

            // Decrypt file
            updateProgress(70, 'Decrypting file... 0%');
            const decryptedData = await CryptoModule.decryptFile(
                encryptedData,
                encryptionKey,
                (progress) => {
                    const percent = 70 + (progress * 0.2);
                    updateProgress(percent, `Decrypting file... ${Math.round(progress)}%`);
                }
            );

            // Save file
            updateProgress(90, 'Saving file...');
            // Use stored filename or fallback to generic name
            const downloadFileName = fileName || 'downloaded-file';
            console.log('Saving file as:', downloadFileName);
            saveFile(decryptedData, downloadFileName);

            // Show success
            updateProgress(100, 'Download complete!');
            showSuccess();

            // Confirm successful download
            await confirmDownload();
        }

    } catch (error) {
        console.error('Download error:', error);
        showError('Download failed. The file may have already been downloaded or expired.');
    }
}

/**
 * Request download URL from API
 */
async function requestDownload() {
    // Get reCAPTCHA token
    const recaptchaToken = await Utils.getRecaptchaToken(CONFIG.RECAPTCHA_SITE_KEY, 'download');

    const response = await fetch(`${CONFIG.API_BASE_URL}/files/${fileId}/download`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            recaptcha_token: recaptchaToken,
        }),
    });

    if (response.status === 404) {
        throw new Error('File not found');
    }

    if (response.status === 410) {
        throw new Error('File already downloaded or expired');
    }

    if (!response.ok) {
        throw new Error(`Download request failed: ${response.status}`);
    }

    return response.json();
}

/**
 * Confirm successful download to backend
 */
async function confirmDownload() {
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/files/${fileId}/confirm`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
        });

        if (response.ok) {
            console.log('Download confirmed successfully');
        } else {
            // Log but don't fail the download - user already has the content
            console.warn('Failed to confirm download:', response.status);
        }
    } catch (error) {
        // Log but don't fail the download - user already has the content
        console.warn('Error confirming download:', error);
    }
}

/**
 * Download file from S3 with real progress tracking
 */
async function downloadFile(url) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.responseType = 'arraybuffer';

        // Track download progress
        xhr.onprogress = (event) => {
            if (event.lengthComputable) {
                const percentComplete = (event.loaded / event.total) * 100;
                // Map to 30-70% of overall progress
                const overallPercent = 30 + (percentComplete * 0.4);
                updateProgress(overallPercent, `Downloading... ${percentComplete.toFixed(1)}%`);
            }
        };

        // Handle completion
        xhr.onload = () => {
            if (xhr.status >= 200 && xhr.status < 300) {
                resolve(new Uint8Array(xhr.response));
            } else {
                reject(new Error(`File download failed: ${xhr.status}`));
            }
        };

        // Handle errors
        xhr.onerror = () => {
            reject(new Error('Network error during download'));
        };

        xhr.ontimeout = () => {
            reject(new Error('Download timeout'));
        };

        // Configure and send request
        xhr.open('GET', url);
        xhr.send();
    });
}

/**
 * Save decrypted file
 */
function saveFile(data, filename) {
    const blob = new Blob([data]);
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    URL.revokeObjectURL(url);
}

/**
 * Update progress bar
 */
function updateProgress(percent, text) {
    elements.progressFill.style.width = `${percent}%`;
    elements.progressText.textContent = text;
}

/**
 * Show error message
 */
function showError(message) {
    clearInterval(countdownInterval);
    elements.loadingSection.style.display = 'none';
    elements.availableSection.style.display = 'none';
    elements.errorSection.style.display = 'block';
    elements.errorMessage.textContent = message;
}

/**
 * Show success message
 */
function showSuccess() {
    clearInterval(countdownInterval);
    elements.availableSection.style.display = 'none';
    elements.successSection.style.display = 'block';
}

/**
 * Show decrypted text secret
 */
function showTextSecret(text) {
    clearInterval(countdownInterval);
    elements.availableSection.style.display = 'none';
    elements.textDisplaySection.style.display = 'block';
    elements.decryptedText.value = text;

    // Set up copy button
    elements.copyTextBtn.addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(text);

            const originalText = elements.copyTextBtn.textContent;
            elements.copyTextBtn.textContent = '✓ Copied!';

            setTimeout(() => {
                elements.copyTextBtn.textContent = originalText;
            }, 2000);
        } catch (error) {
            // Fallback: select text
            elements.decryptedText.select();
            alert('Press Ctrl+C (or Cmd+C on Mac) to copy');
        }
    });
}

/**
 * Handle abuse report
 */
async function handleReportAbuse() {
    const reason = prompt('Please describe the issue (optional):');
    if (reason === null) return; // User cancelled

    try {
        // Get reCAPTCHA token
        const recaptchaToken = await Utils.getRecaptchaToken(CONFIG.RECAPTCHA_SITE_KEY, 'report');

        const response = await fetch(`${CONFIG.API_BASE_URL}/files/${fileId}/report`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                reason,
                recaptcha_token: recaptchaToken,
            }),
        });

        if (response.ok) {
            alert('Thank you for your report. We will review this file.');
        } else {
            alert('Failed to submit report. Please try again.');
        }
    } catch (error) {
        console.error('Report error:', error);
        alert('Failed to submit report. Please try again.');
    }
}

