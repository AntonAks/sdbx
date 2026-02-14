/**
 * Text Secret Upload Module
 */

(function() {
    'use strict';

    // Configuration
    const CONFIG = {
        API_BASE_URL: '/prod',
        RECAPTCHA_SITE_KEY: '6LdulTIsAAAAAJdhvyMU6B1og7GE7d5DySrQUQiv',
    };

    // DOM Elements
    const textInput = document.getElementById('text-input');
    const charCount = document.getElementById('char-count');
    const textUploadBtn = document.getElementById('text-upload-btn');
    const textProgressSection = document.getElementById('text-progress-section');
    const textProgressFill = document.getElementById('text-progress-fill');
    const textProgressText = document.getElementById('text-progress-text');
    // Custom TTL elements
    const textCustomTtlInput = document.getElementById('text-custom-ttl-input');
    const textCustomTtlValue = document.getElementById('text-custom-ttl-value');
    const textCustomTtlUnit = document.getElementById('text-custom-ttl-unit');
    const textTtlPreviewTime = document.getElementById('text-ttl-preview-time');

    // Tab switching
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanels = document.querySelectorAll('.tab-panel');

    /**
     * Initialize text upload module
     * Sets up event listeners for tabs, text input, and buttons
     */
    function init() {
        // Tab switching
        tabButtons.forEach(btn => {
            btn.addEventListener('click', handleTabSwitch);
        });

        // Text input
        textInput.addEventListener('input', handleTextInput);

        // Upload button
        textUploadBtn.addEventListener('click', handleTextUpload);

        // Custom TTL toggle for text tab
        document.querySelectorAll('input[name="text-ttl"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                handleTextTtlChange(e);
                updateTextExpirationPreview();
            });
        });

        // Custom TTL unit change - update value options and preview
        textCustomTtlUnit.addEventListener('change', () => {
            updateTextTtlValueOptions(textCustomTtlUnit.value);
            updateTextExpirationPreview();
        });

        // Custom TTL value change - update preview
        textCustomTtlValue.addEventListener('change', updateTextExpirationPreview);

        // Initialize value dropdown with hours options (default)
        updateTextTtlValueOptions('hours');

        // Initialize expiration preview
        updateTextExpirationPreview();
    }

    /**
     * Handle TTL radio change - show/hide custom input
     * @param {Event} e - Change event
     */
    function handleTextTtlChange(e) {
        if (e.target.value === 'custom') {
            textCustomTtlInput.style.display = 'block';
        } else {
            textCustomTtlInput.style.display = 'none';
        }
    }

    /**
     * Update TTL value dropdown options based on selected unit
     * @param {string} unit - Selected unit (minutes, hours, days)
     */
    function updateTextTtlValueOptions(unit) {
        const options = {
            minutes: [5, 10, 20, 30, 40, 50],
            hours: [2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 24],
            days: Array.from({ length: 7 }, (_, i) => i + 1),
        };

        const values = options[unit] || options.hours;
        textCustomTtlValue.innerHTML = values.map(v => `<option value="${v}">${v}</option>`).join('');
    }

    /**
     * Update expiration time preview based on selected TTL
     */
    function updateTextExpirationPreview() {
        const ttl = getTextTTL();
        let minutes;

        if (typeof ttl === 'number') {
            minutes = ttl;
        } else {
            // Convert preset to minutes
            const presetMinutes = { '1h': 60, '12h': 720, '24h': 1440 };
            minutes = presetMinutes[ttl] || 60;
        }

        const expirationDate = new Date(Date.now() + minutes * 60 * 1000);
        textTtlPreviewTime.textContent = formatTextExpirationDate(expirationDate);
    }

    /**
     * Format expiration date for display
     * @param {Date} date - Expiration date
     * @returns {string} Formatted date string
     */
    function formatTextExpirationDate(date) {
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
     * Handle tab switching between file and text tabs
     * @param {Event} e - Click event
     */
    function handleTabSwitch(e) {
        // Use currentTarget to always get the button, not the clicked child element (SVG/text)
        const button = e.currentTarget;
        const targetTab = button.dataset.tab;

        // Update tab buttons
        tabButtons.forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');

        // Update tab panels
        tabPanels.forEach(panel => {
            if (panel.id === targetTab) {
                panel.classList.add('active');
            } else {
                panel.classList.remove('active');
            }
        });
    }

    /**
     * Handle text input and update character counter
     * Enables/disables upload button based on text length
     */
    function handleTextInput() {
        const length = textInput.value.length;
        charCount.textContent = length;

        // Enable/disable upload button
        textUploadBtn.disabled = length === 0;
    }

    /**
     * Get selected TTL value for text secret
     * Returns preset string ("1h", "12h", "24h") or minutes (number) for custom
     * @returns {string|number} TTL value
     */
    function getTextTTL() {
        const selected = document.querySelector('input[name="text-ttl"]:checked');
        if (!selected) return '1h';

        if (selected.value === 'custom') {
            const value = parseInt(textCustomTtlValue.value, 10);
            const unit = textCustomTtlUnit.value;

            switch (unit) {
                case 'hours':
                    return value * 60;
                case 'days':
                    return value * 60 * 24;
                default: // minutes
                    return value;
            }
        }

        return selected.value;
    }

    /**
     * Handle text upload: encrypt and share text secret
     * @returns {Promise<void>}
     * @throws {Error} If upload fails
     */
    async function handleTextUpload() {
        const text = textInput.value.trim();

        if (!text) {
            Utils.showError('Please enter some text to share');
            return;
        }

        try {
            // Disable button and show progress
            textUploadBtn.disabled = true;
            textProgressSection.style.display = 'block';
            updateProgress(10, 'Generating encryption key...');

            // Generate encryption key
            const key = await CryptoModule.generateKey();
            updateProgress(30, 'Encrypting text...');

            // Encrypt text
            const encoder = new TextEncoder();
            const textBuffer = encoder.encode(text);
            const encryptedData = await CryptoModule.encrypt(textBuffer, key);
            updateProgress(50, 'Preparing upload...');

            // Convert encrypted data to base64
            const base64Text = btoa(String.fromCharCode(...encryptedData));

            // Export key for URL (use base64 like file uploads)
            const keyBase64 = await CryptoModule.keyToBase64(key);

            // Get reCAPTCHA token
            updateProgress(60, 'Verifying...');
            const recaptchaToken = await grecaptcha.execute(CONFIG.RECAPTCHA_SITE_KEY, { action: 'upload' });

            // Initialize upload
            updateProgress(70, 'Initializing...');
            const ttl = getTextTTL();
            const response = await fetch(`${CONFIG.API_BASE_URL}/upload/init`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    content_type: 'text',
                    encrypted_text: base64Text,
                    ttl: ttl,
                    recaptcha_token: recaptchaToken,
                }),
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Upload failed');
            }

            const data = await response.json();
            updateProgress(100, 'Complete! Redirecting...');

            // Generate share page URL (no filename for text secrets)
            const sharePageUrl = `/share.html#${data.file_id}#${keyBase64}`;

            // Small delay to show completion, then redirect
            setTimeout(() => {
                window.location.href = sharePageUrl;
            }, 500);

        } catch (error) {
            console.error('Upload error:', error);
            Utils.showError(`Upload failed: ${error.message}`);
            resetTextUpload();
        }
    }

    /**
     * Update progress indicator during upload
     * @param {number} percent - Progress percentage (0-100)
     * @param {string} message - Status message to display
     */
    function updateProgress(percent, message) {
        textProgressFill.style.width = `${percent}%`;
        textProgressText.textContent = message;
    }

    /**
     * Reset text upload form to initial state
     * Clears input and hides progress section
     */
    function resetTextUpload() {
        textInput.value = '';
        charCount.textContent = '0';
        textUploadBtn.disabled = true;
        textProgressSection.style.display = 'none';
        textProgressFill.style.width = '0%';
        textProgressText.textContent = '';
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
