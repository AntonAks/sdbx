/**
 * Download page functionality
 */

'use strict';

// Configuration
const CONFIG = {
    API_BASE_URL: 'https://laeg1n0efh.execute-api.eu-central-1.amazonaws.com/dev',
};

// DOM elements
const elements = {
    loadingSection: document.getElementById('loading-section'),
    availableSection: document.getElementById('available-section'),
    errorSection: document.getElementById('error-section'),
    successSection: document.getElementById('success-section'),
    fileSize: document.getElementById('file-size'),
    expiresIn: document.getElementById('expires-in'),
    downloadBtn: document.getElementById('download-btn'),
    downloadProgress: document.getElementById('download-progress'),
    progressFill: document.getElementById('progress-fill'),
    progressText: document.getElementById('progress-text'),
    errorMessage: document.getElementById('error-message'),
    reportAbuse: document.getElementById('report-abuse'),
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

    // Display file size
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

        // Request download URL
        updateProgress(0, 'Preparing download...');
        const downloadData = await requestDownload();

        // Download encrypted file
        updateProgress(30, 'Downloading encrypted file...');
        const encryptedData = await downloadFile(downloadData.download_url);

        // Decrypt file
        updateProgress(70, 'Decrypting file...');
        const decryptedData = await CryptoModule.decryptFile(
            encryptedData,
            encryptionKey,
            (progress) => updateProgress(70 + (progress * 0.2), 'Decrypting file...')
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

    } catch (error) {
        console.error('Download error:', error);
        showError('Download failed. The file may have already been downloaded or expired.');
    }
}

/**
 * Request download URL from API
 */
async function requestDownload() {
    const response = await fetch(`${CONFIG.API_BASE_URL}/files/${fileId}/download`, {
        method: 'POST',
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
 * Download file from S3
 */
async function downloadFile(url) {
    const response = await fetch(url);

    if (!response.ok) {
        throw new Error(`File download failed: ${response.status}`);
    }

    const arrayBuffer = await response.arrayBuffer();
    return new Uint8Array(arrayBuffer);
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
 * Handle abuse report
 */
async function handleReportAbuse() {
    const reason = prompt('Please describe the issue (optional):');
    if (reason === null) return; // User cancelled

    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/files/${fileId}/report`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ reason }),
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
