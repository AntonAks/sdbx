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
    // Vault elements
    vaultSection: document.getElementById('vault-section'),
    vaultPassword: document.getElementById('vault-password'),
    vaultTogglePassword: document.getElementById('vault-toggle-password'),
    vaultFileSize: document.getElementById('vault-file-size'),
    vaultExpiresIn: document.getElementById('vault-expires-in'),
    vaultDownloadCount: document.getElementById('vault-download-count'),
    vaultDownloadBtn: document.getElementById('vault-download-btn'),
    vaultProgress: document.getElementById('vault-progress'),
    vaultProgressFill: document.getElementById('vault-progress-fill'),
    vaultProgressText: document.getElementById('vault-progress-text'),
    vaultTextDisplaySection: document.getElementById('vault-text-display-section'),
    vaultDecryptedText: document.getElementById('vault-decrypted-text'),
    vaultCopyTextBtn: document.getElementById('vault-copy-text-btn'),
    vaultSuccessSection: document.getElementById('vault-success-section'),
};

// State
let fileId = null;
let encryptionKey = null;
let fileName = null;
let countdownInterval = null;
let isVault = false;
let vaultSalt = null;
let vaultMetadata = null;

// Initialize
init();

/**
 * Initialize download page
 */
async function init() {
    try {
        // Check for PIN download flow (no hash or non-URL hash)
        if (typeof PinDownload !== 'undefined' && PinDownload.shouldShowPinFlow()) {
            elements.loadingSection.style.display = 'none';
            PinDownload.init();
            PinDownload.showCodeEntry();
            return;
        }

        // Parse URL fragment (decode %23 back to # for URLs shared via platforms that encode them)
        const fragment = decodeURIComponent(window.location.hash.slice(1));
        const parts = fragment.split('#');

        fileId = parts[0];
        isVault = parts.length >= 2 && parts[parts.length - 1] === 'vault';

        if (isVault) {
            // Vault URL: #file_id#salt#filename#vault
            vaultSalt = parts[1];
            fileName = parts[2] ? decodeURIComponent(parts[2]) : null;

            console.log('Vault URL parsed:', { fileId, vaultSalt: vaultSalt?.substring(0, 10) + '...', fileName });

            if (!fileId || !vaultSalt) {
                showError('Invalid vault link');
                return;
            }

            // Check vault availability
            await checkVaultAvailability();

        } else {
            // One-time URL: #file_id#key#filename
            const keyBase64 = parts[1];
            fileName = parts[2] ? decodeURIComponent(parts[2]) : null;

            console.log('Parsed from URL:', { fileId, keyBase64: keyBase64?.substring(0, 10) + '...', fileName });

            if (!fileId || !keyBase64) {
                showError('Invalid download link');
                return;
            }

            // Import encryption key
            encryptionKey = await CryptoModule.base64ToKey(keyBase64);

            // Check file availability
            await checkFileAvailability();
        }

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

// ==========================================
// Vault-specific functions
// ==========================================

/**
 * Check vault availability
 */
async function checkVaultAvailability() {
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/files/${fileId}/metadata`);

        if (response.status === 404) {
            showError('Vault content not found');
            return;
        }

        if (response.status === 410) {
            showError('Vault content has expired');
            return;
        }

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const metadata = await response.json();

        if (!metadata.available) {
            showError('Vault content is no longer available');
            return;
        }

        // Store metadata for later use
        vaultMetadata = metadata;

        // Show vault password section
        showVaultSection(metadata);

    } catch (error) {
        console.error('Error checking vault availability:', error);
        showError('Failed to check vault availability');
    }
}

/**
 * Show vault password section
 */
function showVaultSection(metadata) {
    elements.loadingSection.style.display = 'none';
    elements.vaultSection.style.display = 'block';

    // Display size
    elements.vaultFileSize.textContent = Utils.formatFileSize(metadata.file_size);

    // Display expiration
    updateVaultExpirationCountdown(metadata.expires_at);

    // Display download count
    elements.vaultDownloadCount.textContent = metadata.download_count || 0;

    // Setup password toggle
    elements.vaultTogglePassword.addEventListener('click', () => {
        if (elements.vaultPassword.type === 'password') {
            elements.vaultPassword.type = 'text';
            elements.vaultTogglePassword.textContent = 'Hide';
        } else {
            elements.vaultPassword.type = 'password';
            elements.vaultTogglePassword.textContent = 'Show';
        }
    });

    // Setup download button
    elements.vaultDownloadBtn.addEventListener('click', handleVaultDownload);

    // Allow Enter key to trigger download
    elements.vaultPassword.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            handleVaultDownload();
        }
    });
}

/**
 * Update vault expiration countdown
 */
function updateVaultExpirationCountdown(expiresAt) {
    const update = () => {
        const now = Utils.getCurrentTimestamp();
        const remaining = expiresAt - now;

        if (remaining <= 0) {
            elements.vaultExpiresIn.textContent = 'Expired';
            clearInterval(countdownInterval);
            showError('Vault content has expired');
            return;
        }

        elements.vaultExpiresIn.textContent = Utils.formatTimeRemaining(remaining);
    };

    update();
    countdownInterval = setInterval(update, 60000);
}

/**
 * Handle vault download with password
 */
async function handleVaultDownload() {
    const password = elements.vaultPassword.value;

    if (!password) {
        Utils.showError('Please enter the password');
        return;
    }

    try {
        elements.vaultDownloadBtn.disabled = true;
        elements.vaultProgress.style.display = 'block';

        // Step 1: Derive key from password
        updateVaultProgress(5, 'Verifying password...');
        const salt = CryptoModule.base64ToArray(vaultSalt);
        const passwordKey = await CryptoModule.deriveKeyFromPassword(password, salt);

        // Step 2: Decrypt the encrypted key
        updateVaultProgress(15, 'Unlocking content...');
        const encryptedKeyData = CryptoModule.base64ToArray(vaultMetadata.encrypted_key);

        let dataKey;
        try {
            dataKey = await CryptoModule.decryptKey(encryptedKeyData, passwordKey);
        } catch (error) {
            // Decryption failed - wrong password
            console.error('Key decryption failed:', error);
            Utils.showError('Incorrect password');
            resetVaultForm();
            return;
        }

        // Step 3: Request download
        updateVaultProgress(25, 'Preparing download...');
        const downloadData = await requestDownload();

        // Step 4: Download and decrypt content
        if (downloadData.content_type === 'text') {
            // Handle text
            updateVaultProgress(40, 'Decrypting text...');
            const encryptedBytes = CryptoModule.base64ToArray(downloadData.encrypted_text);

            const decryptedData = await CryptoModule.decryptFile(
                encryptedBytes,
                dataKey,
                (progress) => {
                    updateVaultProgress(40 + progress * 0.5, `Decrypting... ${Math.round(progress)}%`);
                }
            );

            const decoder = new TextDecoder();
            const decryptedText = decoder.decode(decryptedData);

            updateVaultProgress(100, 'Complete!');
            showVaultTextSecret(decryptedText);

        } else {
            // Handle file
            updateVaultProgress(30, 'Downloading encrypted file...');
            const encryptedData = await downloadVaultFile(downloadData.download_url);

            updateVaultProgress(60, 'Decrypting file...');
            const decryptedData = await CryptoModule.decryptFile(
                encryptedData,
                dataKey,
                (progress) => {
                    updateVaultProgress(60 + progress * 0.35, `Decrypting... ${Math.round(progress)}%`);
                }
            );

            updateVaultProgress(95, 'Saving file...');
            const downloadFileName = fileName || 'downloaded-file';
            saveFile(decryptedData, downloadFileName);

            updateVaultProgress(100, 'Download complete!');
            showVaultSuccess();
        }

    } catch (error) {
        console.error('Vault download error:', error);
        if (error.name === 'OperationError') {
            Utils.showError('Incorrect password or corrupted data');
        } else {
            Utils.showError(error.message || 'Download failed. Please try again.');
        }
        resetVaultForm();
    }
}

/**
 * Download file for vault with progress tracking
 */
async function downloadVaultFile(url) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.responseType = 'arraybuffer';

        xhr.onprogress = (event) => {
            if (event.lengthComputable) {
                const percentComplete = (event.loaded / event.total) * 100;
                const overallPercent = 30 + (percentComplete * 0.3);
                updateVaultProgress(overallPercent, `Downloading... ${percentComplete.toFixed(1)}%`);
            }
        };

        xhr.onload = () => {
            if (xhr.status >= 200 && xhr.status < 300) {
                resolve(new Uint8Array(xhr.response));
            } else {
                reject(new Error(`Download failed: ${xhr.status}`));
            }
        };

        xhr.onerror = () => reject(new Error('Network error during download'));
        xhr.ontimeout = () => reject(new Error('Download timeout'));

        xhr.open('GET', url);
        xhr.send();
    });
}

/**
 * Update vault progress bar
 */
function updateVaultProgress(percent, text) {
    elements.vaultProgressFill.style.width = `${percent}%`;
    elements.vaultProgressText.textContent = text;
}

/**
 * Reset vault form after error
 */
function resetVaultForm() {
    elements.vaultDownloadBtn.disabled = false;
    elements.vaultProgress.style.display = 'none';
    elements.vaultProgressFill.style.width = '0%';
}

/**
 * Show vault text secret
 */
function showVaultTextSecret(text) {
    clearInterval(countdownInterval);
    elements.vaultSection.style.display = 'none';
    elements.vaultTextDisplaySection.style.display = 'block';
    elements.vaultDecryptedText.value = text;

    // Setup copy button
    elements.vaultCopyTextBtn.addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(text);
            const originalText = elements.vaultCopyTextBtn.textContent;
            elements.vaultCopyTextBtn.textContent = 'Copied!';
            setTimeout(() => {
                elements.vaultCopyTextBtn.textContent = originalText;
            }, 2000);
        } catch (error) {
            elements.vaultDecryptedText.select();
            alert('Press Ctrl+C (or Cmd+C on Mac) to copy');
        }
    });
}

/**
 * Show vault success
 */
function showVaultSuccess() {
    clearInterval(countdownInterval);
    elements.vaultSection.style.display = 'none';
    elements.vaultSuccessSection.style.display = 'block';
}

// ==========================================
// Common functions
// ==========================================

/**
 * Show error message
 */
function showError(message) {
    clearInterval(countdownInterval);
    elements.loadingSection.style.display = 'none';
    elements.availableSection.style.display = 'none';
    elements.vaultSection.style.display = 'none';
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

