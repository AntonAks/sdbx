'use strict';

/**
 * Shared header component for consistent navigation across all pages
 */
const Header = (function() {
    const CONFIG = {
        maxWidth: 'max-w-4xl',
        pages: {
            'index.html': 'Home',
            'about.html': 'About',
            'download.html': null  // No nav highlight for download page
        }
    };

    /**
     * Get current page name from URL
     * @returns {string}
     */
    function getCurrentPage() {
        const path = window.location.pathname;
        const page = path.substring(path.lastIndexOf('/') + 1) || 'index.html';
        return page;
    }

    /**
     * Generate navigation links HTML
     * @param {string} currentPage
     * @returns {string}
     */
    function renderNavLinks(currentPage) {
        const links = [];

        if (currentPage !== 'index.html') {
            links.push(`<a href="index.html" class="text-sm text-gray-600 dark:text-slate-400 hover:text-gray-900 dark:hover:text-slate-200 transition">Home</a>`);
        }

        const aboutClass = currentPage === 'about.html'
            ? 'text-sm text-blue-600 dark:text-blue-500'
            : 'text-sm text-gray-600 dark:text-slate-400 hover:text-gray-900 dark:hover:text-slate-200 transition';
        links.push(`<a href="about.html" class="${aboutClass}">About</a>`);

        const faqClass = currentPage === 'faq.html'
            ? 'text-sm text-blue-600 dark:text-blue-500'
            : 'text-sm text-gray-600 dark:text-slate-400 hover:text-gray-900 dark:hover:text-slate-200 transition';
        links.push(`<a href="faq.html" class="${faqClass}">FAQ</a>`);

        return links.join('\n                    ');
    }

    /**
     * Generate full header HTML
     * @returns {string}
     */
    function render() {
        const currentPage = getCurrentPage();

        return `
        <div class="${CONFIG.maxWidth} mx-auto px-6 py-6 flex items-center justify-between">
            <a href="index.html" class="flex items-center gap-3">
                <svg class="w-6 h-6 text-blue-600 dark:text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                </svg>
                <span class="text-xl font-semibold text-gray-900 dark:text-slate-100">sdbx</span>
            </a>
            <nav class="flex items-center gap-6">
                ${renderNavLinks(currentPage)}
                <button id="theme-toggle" class="p-2 rounded-lg hover:bg-gray-200 dark:hover:bg-slate-800 transition-colors" aria-label="Toggle theme">
                    <!-- Icon injected by theme-toggle.js -->
                </button>
            </nav>
        </div>`;
    }

    /**
     * Initialize header - call this after DOM is ready
     */
    function init() {
        const header = document.querySelector('header');
        if (header) {
            header.innerHTML = render();

            // Re-initialize theme toggle button after header is rendered
            if (window.ThemeToggle && window.ThemeToggle.setupListeners) {
                window.ThemeToggle.setupListeners();
            }
        }
    }

    return {
        init: init,
        render: render
    };
})();

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', Header.init);
} else {
    Header.init();
}
