/**
 * PIN-based download module for sdbx
 * Handles code entry, PIN verification with timer, and encrypted file download
 */

'use strict';

const PinDownload = (function() {
    // Configuration
    const API_BASE = '/prod';
    const RECAPTCHA_SITE_KEY = '6LdulTIsAAAAAJdhvyMU6B1og7GE7d5DySrQUQiv';
    const PIN_REGEX = /^[a-zA-Z0-9]{4}$/;
    const CODE_LENGTH = 6;

    // State
    let fileId = '';
    let sessionExpires = 0;
    let timerInterval = null;
    let attemptsLeft = 3;

    // DOM elements (cached on init)
    let els = {};

    /**
     * Determine if PIN flow should be shown instead of normal download
     * PIN flow activates when there's no hash or no UUID-like first part
     * @returns {boolean}
     */
    function shouldShowPinFlow() {
        const hash = window.location.hash;
        if (!hash || hash === '#') return true;
        const parts = hash.substring(1).split('#');
        // Existing formats have UUID-like first part (contains dashes)
        if (parts.length >= 2 && parts[0].includes('-')) return false;
        return true;
    }

    /**
     * Initialize module - cache DOM elements
     */
    function init() {
        // Code entry elements
        els.codeSection = document.getElementById('pin-code-section');
        els.codeInputBoxes = document.getElementById('code-input-boxes');
        els.codeContinueBtn = document.getElementById('code-continue-btn');
        els.codeError = document.getElementById('code-error');

        // PIN entry elements
        els.pinEntrySection = document.getElementById('pin-entry-section');
        els.pinFileCode = document.getElementById('pin-file-code');
        els.pinTimer = document.getElementById('pin-timer');
        els.pinTimerValue = document.getElementById('pin-timer-value');
        els.pinAttemptsValue = document.getElementById('pin-attempts-value');
        els.pinVerifyInput = document.getElementById('pin-verify-input');
        els.pinDownloadBtn = document.getElementById('pin-download-btn');
        els.pinVerifyError = document.getElementById('pin-verify-error');

        // Progress elements
        els.pinDownloadProgressSection = document.getElementById('pin-download-progress-section');
        els.pinDlProgressFill = document.getElementById('pin-dl-progress-fill');
        els.pinDlProgressText = document.getElementById('pin-dl-progress-text');

        // Result elements
        els.pinTextDisplaySection = document.getElementById('pin-text-display-section');
        els.pinDecryptedText = document.getElementById('pin-decrypted-text');
        els.pinCopyTextBtn = document.getElementById('pin-copy-text-btn');
        els.pinSuccessSection = document.getElementById('pin-success-section');

        // Special state elements
        els.pinTimeoutSection = document.getElementById('pin-timeout-section');
        els.pinTryAgainBtn = document.getElementById('pin-try-again-btn');
        els.pinLockedSection = document.getElementById('pin-locked-section');
        els.pinUnlockTime = document.getElementById('pin-unlock-time');

        // Loading section (from existing page)
        els.loadingSection = document.getElementById('loading-section');

        bindEvents();
    }

    /**
     * Bind event listeners
     */
    function bindEvents() {
        // Code continue button
        els.codeContinueBtn.addEventListener('click', handleCodeSubmit);

        // PIN input validation and Enter key
        els.pinVerifyInput.addEventListener('input', handlePinInput);
        els.pinVerifyInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !els.pinDownloadBtn.disabled) {
                handlePinVerify();
            }
        });

        // PIN download button
        els.pinDownloadBtn.addEventListener('click', handlePinVerify);

        // Try again button
        els.pinTryAgainBtn.addEventListener('click', handleTryAgain);

        // Copy text button
        els.pinCopyTextBtn.addEventListener('click', handleCopyText);

        // Setup code input boxes
        setupCodeInputBoxes();
    }

    // ==========================================
    // Code Input Boxes
    // ==========================================

    /**
     * Set up 6-digit code input boxes with auto-advance, backspace, and paste
     */
    function setupCodeInputBoxes() {
        const inputs = els.codeInputBoxes.querySelectorAll('.code-digit');

        inputs.forEach((input, index) => {
            // Handle input - auto advance on digit entry
            input.addEventListener('input', (e) => {
                const value = e.target.value;

                // Only allow digits
                if (value && !/^[0-9]$/.test(value)) {
                    e.target.value = '';
                    return;
                }

                if (value && index < CODE_LENGTH - 1) {
                    inputs[index + 1].focus();
                }

                updateContinueButton();
            });

            // Handle keydown for backspace navigation
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Backspace' && !e.target.value && index > 0) {
                    inputs[index - 1].focus();
                    inputs[index - 1].value = '';
                    updateContinueButton();
                }

                // Enter key submits when all digits filled
                if (e.key === 'Enter' && !els.codeContinueBtn.disabled) {
                    handleCodeSubmit();
                }
            });

            // Handle paste - distribute digits across boxes
            input.addEventListener('paste', (e) => {
                e.preventDefault();
                const pastedData = (e.clipboardData || window.clipboardData).getData('text').trim();
                const digits = pastedData.replace(/[^0-9]/g, '');

                if (digits.length === 0) return;

                for (let i = 0; i < CODE_LENGTH && i < digits.length; i++) {
                    inputs[i].value = digits[i];
                }

                // Focus the next empty box or the last box
                const nextEmpty = Array.from(inputs).findIndex(inp => !inp.value);
                if (nextEmpty >= 0) {
                    inputs[nextEmpty].focus();
                } else {
                    inputs[CODE_LENGTH - 1].focus();
                }

                updateContinueButton();
            });
        });
    }

    /**
     * Get the full code from all digit boxes
     * @returns {string}
     */
    function getCodeValue() {
        const inputs = els.codeInputBoxes.querySelectorAll('.code-digit');
        return Array.from(inputs).map(inp => inp.value).join('');
    }

    /**
     * Update the continue button enabled state
     */
    function updateContinueButton() {
        const code = getCodeValue();
        els.codeContinueBtn.disabled = code.length !== CODE_LENGTH;
    }

    /**
     * Clear all code input boxes
     */
    function clearCodeInputs() {
        const inputs = els.codeInputBoxes.querySelectorAll('.code-digit');
        inputs.forEach(inp => { inp.value = ''; });
        inputs[0].focus();
        updateContinueButton();
    }

    // ==========================================
    // Section Visibility
    // ==========================================

    /**
     * Hide all PIN-related sections and the loading section
     */
    function hideAllSections() {
        els.loadingSection.style.display = 'none';
        els.codeSection.style.display = 'none';
        els.pinEntrySection.style.display = 'none';
        els.pinDownloadProgressSection.style.display = 'none';
        els.pinTextDisplaySection.style.display = 'none';
        els.pinSuccessSection.style.display = 'none';
        els.pinTimeoutSection.style.display = 'none';
        els.pinLockedSection.style.display = 'none';
    }

    /**
     * Show the code entry section
     */
    function showCodeEntry() {
        hideAllSections();
        els.codeSection.style.display = '';
        els.codeError.style.display = 'none';

        // Focus the first input box
        const firstInput = els.codeInputBoxes.querySelector('.code-digit');
        if (firstInput) {
            setTimeout(() => firstInput.focus(), 100);
        }
    }

    /**
     * Show the PIN entry section with timer
     */
    function showPinEntry() {
        hideAllSections();
        els.pinEntrySection.style.display = '';
        els.pinVerifyError.style.display = 'none';
        els.pinVerifyInput.value = '';
        els.pinDownloadBtn.disabled = true;
        els.pinFileCode.textContent = fileId;
        els.pinAttemptsValue.textContent = attemptsLeft;

        // Focus PIN input
        setTimeout(() => els.pinVerifyInput.focus(), 100);
    }

    // ==========================================
    // Code Entry Flow
    // ==========================================

    /**
     * Handle code submission - initiate PIN session
     */
    async function handleCodeSubmit() {
        const code = getCodeValue();
        if (code.length !== CODE_LENGTH) return;

        fileId = code;
        els.codeContinueBtn.disabled = true;
        els.codeError.style.display = 'none';

        try {
            // Get reCAPTCHA token
            const recaptchaToken = await Utils.getRecaptchaToken(RECAPTCHA_SITE_KEY, 'pin_initiate');

            // Call initiate endpoint
            const response = await fetch(`${API_BASE}/pin/initiate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    file_id: code,
                    recaptcha_token: recaptchaToken,
                }),
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                const errorMsg = errorData.error || `Request failed: ${response.status}`;

                // Check for locked state
                if (errorMsg.toLowerCase().includes('locked')) {
                    showLockedSection(errorData.locked_until);
                    return;
                }

                showCodeError(errorMsg);
                return;
            }

            const data = await response.json();
            sessionExpires = data.session_expires;
            attemptsLeft = data.attempts_left || 3;

            // Move to PIN entry with timer
            showPinEntry();
            startTimer();

        } catch (error) {
            console.error('Code submit error:', error);
            showCodeError('Failed to verify code. Please try again.');
        } finally {
            els.codeContinueBtn.disabled = getCodeValue().length !== CODE_LENGTH;
        }
    }

    /**
     * Show error message in code section
     * @param {string} message
     */
    function showCodeError(message) {
        els.codeError.textContent = message;
        els.codeError.style.display = '';
    }

    // ==========================================
    // Timer
    // ==========================================

    /**
     * Start the countdown timer based on session_expires
     */
    function startTimer() {
        // Clear any existing timer
        if (timerInterval) {
            clearInterval(timerInterval);
        }

        updateTimerDisplay();

        timerInterval = setInterval(() => {
            updateTimerDisplay();
        }, 1000);
    }

    /**
     * Update the timer display with color coding
     */
    function updateTimerDisplay() {
        const now = Math.floor(Date.now() / 1000);
        const remaining = sessionExpires - now;

        if (remaining <= 0) {
            clearInterval(timerInterval);
            timerInterval = null;
            showTimeoutSection();
            return;
        }

        els.pinTimerValue.textContent = remaining;

        // Color coding based on remaining time
        // Remove all state classes first
        els.pinTimer.className = 'text-center py-3 px-4 rounded-lg mb-4 text-lg font-semibold';

        if (remaining > 20) {
            // Green - safe
            els.pinTimer.classList.add(
                'bg-green-100', 'dark:bg-green-900/30',
                'text-green-700', 'dark:text-green-300'
            );
        } else if (remaining > 10) {
            // Yellow - warning
            els.pinTimer.classList.add(
                'bg-yellow-100', 'dark:bg-yellow-900/30',
                'text-yellow-700', 'dark:text-yellow-300'
            );
        } else {
            // Red - danger with pulse
            els.pinTimer.classList.add(
                'bg-red-100', 'dark:bg-red-900/30',
                'text-red-600', 'dark:text-red-300',
                'animate-pulse'
            );
        }
    }

    // ==========================================
    // PIN Verification
    // ==========================================

    /**
     * Handle PIN input validation
     */
    function handlePinInput() {
        const value = els.pinVerifyInput.value;
        els.pinDownloadBtn.disabled = !PIN_REGEX.test(value);
    }

    /**
     * Handle PIN verification and download
     */
    async function handlePinVerify() {
        const pin = els.pinVerifyInput.value;
        if (!PIN_REGEX.test(pin)) return;

        els.pinDownloadBtn.disabled = true;
        els.pinVerifyError.style.display = 'none';

        try {
            // Get reCAPTCHA token
            const recaptchaToken = await Utils.getRecaptchaToken(RECAPTCHA_SITE_KEY, 'pin_verify');

            // Call verify endpoint
            const response = await fetch(`${API_BASE}/pin/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    file_id: fileId,
                    pin: pin,
                    recaptcha_token: recaptchaToken,
                }),
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                const errorMsg = errorData.error || `Verification failed: ${response.status}`;

                // Check for locked state
                if (errorMsg.toLowerCase().includes('locked')) {
                    clearInterval(timerInterval);
                    timerInterval = null;
                    showLockedSection(errorData.locked_until);
                    return;
                }

                // Check for session expired
                if (errorMsg.toLowerCase().includes('expired') || errorMsg.toLowerCase().includes('session')) {
                    clearInterval(timerInterval);
                    timerInterval = null;
                    showTimeoutSection();
                    return;
                }

                // Wrong PIN - update attempts
                if (errorData.attempts_left !== undefined) {
                    attemptsLeft = errorData.attempts_left;
                    els.pinAttemptsValue.textContent = attemptsLeft;
                } else {
                    attemptsLeft = Math.max(0, attemptsLeft - 1);
                    els.pinAttemptsValue.textContent = attemptsLeft;
                }

                showPinError(errorMsg);
                els.pinDownloadBtn.disabled = false;
                els.pinVerifyInput.value = '';
                els.pinVerifyInput.focus();
                return;
            }

            // Success - stop timer and start download
            clearInterval(timerInterval);
            timerInterval = null;

            const data = await response.json();
            await handleDecryptAndDownload(pin, data);

        } catch (error) {
            console.error('PIN verify error:', error);
            showPinError('Verification failed. Please try again.');
            els.pinDownloadBtn.disabled = false;
        }
    }

    /**
     * Show error in PIN entry section
     * @param {string} message
     */
    function showPinError(message) {
        els.pinVerifyError.textContent = message;
        els.pinVerifyError.style.display = '';
    }

    // ==========================================
    // Download and Decrypt
    // ==========================================

    /**
     * Handle file/text download and decryption after successful PIN verify
     * @param {string} pin - The verified PIN
     * @param {Object} data - Response from verify endpoint (salt, download_url/encrypted_text, content_type)
     */
    async function handleDecryptAndDownload(pin, data) {
        hideAllSections();
        els.pinDownloadProgressSection.style.display = '';

        try {
            // Step 1: Derive key from PIN + salt
            updateDownloadProgress(5, 'Deriving encryption key...');
            const saltBytes = hexToUint8Array(data.salt);
            const key = await CryptoModule.deriveKeyFromPassword(pin, saltBytes, true);

            if (data.content_type === 'text') {
                // Handle text secret
                updateDownloadProgress(30, 'Decrypting text...');
                const encryptedBytes = Uint8Array.from(atob(data.encrypted_text), c => c.charCodeAt(0));

                const decryptedData = await CryptoModule.decryptFile(
                    encryptedBytes,
                    key,
                    (progress) => {
                        updateDownloadProgress(30 + progress * 0.6, `Decrypting... ${Math.round(progress)}%`);
                    }
                );

                const decoder = new TextDecoder();
                const decryptedText = decoder.decode(decryptedData);

                updateDownloadProgress(100, 'Complete!');
                showPinTextSecret(decryptedText);

            } else {
                // Handle file download
                updateDownloadProgress(10, 'Downloading encrypted file...');
                const encryptedData = await downloadEncryptedFile(data.download_url);

                updateDownloadProgress(60, 'Decrypting file... 0%');
                const decryptedData = await CryptoModule.decryptFile(
                    encryptedData,
                    key,
                    (progress) => {
                        updateDownloadProgress(60 + progress * 0.35, `Decrypting... ${Math.round(progress)}%`);
                    }
                );

                const fileName = data.file_name || 'download';

                if (fileName === 'secret.txt') {
                    // Text secret stored as file — display inline
                    updateDownloadProgress(100, 'Complete!');
                    const decoder = new TextDecoder();
                    const decryptedText = decoder.decode(decryptedData);
                    showPinTextSecret(decryptedText);
                } else {
                    updateDownloadProgress(95, 'Saving file...');
                    saveFile(decryptedData, fileName);
                    updateDownloadProgress(100, 'Download complete!');
                    showPinSuccess();
                }
            }

            // Confirm download (fire and forget)
            confirmDownload(fileId);

        } catch (error) {
            console.error('Decrypt/download error:', error);
            hideAllSections();
            showCodeEntry();
            showCodeError('Decryption failed. Please check your PIN and try again.');
        }
    }

    /**
     * Download encrypted file from S3 with progress
     * @param {string} url - Presigned S3 URL
     * @returns {Promise<Uint8Array>}
     */
    function downloadEncryptedFile(url) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.responseType = 'arraybuffer';

            xhr.onprogress = (event) => {
                if (event.lengthComputable) {
                    const percentComplete = (event.loaded / event.total) * 100;
                    const overallPercent = 10 + (percentComplete * 0.5);
                    updateDownloadProgress(overallPercent, `Downloading... ${percentComplete.toFixed(1)}%`);
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
     * Save decrypted file to user's device
     * @param {ArrayBuffer} data - Decrypted data
     * @param {string} filename - Filename to save as
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
     * Confirm download to backend (fire and forget)
     * @param {string} id - File ID
     */
    function confirmDownload(id) {
        fetch(`${API_BASE}/files/${id}/confirm`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
        }).catch(err => console.warn('Confirm download error:', err));
    }

    /**
     * Update download progress bar
     * @param {number} percent
     * @param {string} text
     */
    function updateDownloadProgress(percent, text) {
        els.pinDlProgressFill.style.width = `${percent}%`;
        els.pinDlProgressText.textContent = text;
    }

    // ==========================================
    // Result Sections
    // ==========================================

    /**
     * Show decrypted text secret
     * @param {string} text
     */
    function showPinTextSecret(text) {
        hideAllSections();
        els.pinTextDisplaySection.style.display = '';
        els.pinDecryptedText.value = text;
    }

    /**
     * Show file download success
     */
    function showPinSuccess() {
        hideAllSections();
        els.pinSuccessSection.style.display = '';
    }

    /**
     * Handle copy text button
     */
    async function handleCopyText() {
        const text = els.pinDecryptedText.value;
        const success = await Utils.copyToClipboard(text);
        if (success) {
            const originalText = els.pinCopyTextBtn.textContent;
            els.pinCopyTextBtn.textContent = 'Copied!';
            setTimeout(() => {
                els.pinCopyTextBtn.textContent = originalText;
            }, 2000);
        } else {
            // Fallback: select text
            els.pinDecryptedText.select();
        }
    }

    // ==========================================
    // Special State Sections
    // ==========================================

    /**
     * Show session timeout section
     */
    function showTimeoutSection() {
        hideAllSections();
        els.pinTimeoutSection.style.display = '';
    }

    /**
     * Show locked section with estimated unlock time
     * @param {number|string} [lockedUntil] - Unix timestamp or ISO string
     */
    function showLockedSection(lockedUntil) {
        hideAllSections();
        els.pinLockedSection.style.display = '';

        if (lockedUntil) {
            let unlockDate;
            if (typeof lockedUntil === 'number') {
                unlockDate = new Date(lockedUntil * 1000);
            } else {
                unlockDate = new Date(lockedUntil);
            }
            els.pinUnlockTime.textContent = unlockDate.toLocaleString();
        } else {
            // Default: 12 hours from now
            const unlockDate = new Date(Date.now() + 12 * 60 * 60 * 1000);
            els.pinUnlockTime.textContent = unlockDate.toLocaleString();
        }
    }

    /**
     * Handle try again button - go back to code entry
     */
    function handleTryAgain() {
        clearCodeInputs();
        showCodeEntry();
    }

    // ==========================================
    // Helpers
    // ==========================================

    /**
     * Convert hex string to Uint8Array
     * @param {string} hex
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
        shouldShowPinFlow,
        init,
        showCodeEntry,
    };
})();
