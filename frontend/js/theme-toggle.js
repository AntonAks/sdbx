/**
 * Dark Mode Toggle Module
 * Manages manual dark/light theme switching with localStorage persistence
 * Initializes immediately to prevent theme flash on page load
 */

(function() {
    'use strict';

    const THEME_KEY = 'sdbx-theme';
    const DARK_CLASS = 'dark';

    /**
     * Initialize theme based on saved preference or system default
     * Runs immediately on script load (before DOM ready) to prevent flash
     */
    function initTheme() {
        const savedTheme = localStorage.getItem(THEME_KEY);
        const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

        // Apply theme: saved preference OR system preference (default to dark if no preference)
        const shouldBeDark = savedTheme === 'dark' || (!savedTheme && systemPrefersDark) || !savedTheme;

        if (shouldBeDark) {
            document.documentElement.classList.add(DARK_CLASS);
        } else {
            document.documentElement.classList.remove(DARK_CLASS);
        }
    }

    /**
     * Toggle between dark and light themes
     * Called by button click handler
     */
    function toggleTheme() {
        const isDark = document.documentElement.classList.toggle(DARK_CLASS);
        localStorage.setItem(THEME_KEY, isDark ? 'dark' : 'light');
        updateToggleButton(isDark);
    }

    /**
     * Update the toggle button icon based on current theme
     * @param {boolean} isDark - Whether dark mode is active
     */
    function updateToggleButton(isDark) {
        const btn = document.getElementById('theme-toggle');
        if (!btn) return;

        // Sun icon for dark mode (click to go light)
        // Moon icon for light mode (click to go dark)
        btn.innerHTML = isDark ? getSunIcon() : getMoonIcon();
        btn.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
    }

    /**
     * Sun icon SVG (shown in dark mode)
     */
    function getSunIcon() {
        return `<svg class="w-5 h-5 text-slate-300" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="4"/>
            <path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32l1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41m11.32-11.32l1.41-1.41"/>
        </svg>`;
    }

    /**
     * Moon icon SVG (shown in light mode)
     */
    function getMoonIcon() {
        return `<svg class="w-5 h-5 text-slate-700" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/>
        </svg>`;
    }

    /**
     * Setup event listeners when DOM is ready
     */
    function setupListeners() {
        const btn = document.getElementById('theme-toggle');
        if (btn) {
            btn.addEventListener('click', toggleTheme);
            updateToggleButton(document.documentElement.classList.contains(DARK_CLASS));
        }
    }

    // Initialize theme immediately (prevents wrong-theme flash)
    initTheme();

    // Setup button listener when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setupListeners);
    } else {
        setupListeners();
    }

    // Expose functions for external use (header.js calls setupListeners after rendering)
    window.ThemeToggle = { toggleTheme, initTheme, setupListeners };
})();
