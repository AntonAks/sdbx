/**
 * Page initialization - runs on all pages
 */

// Set current year in footer
document.addEventListener('DOMContentLoaded', () => {
    const yearElement = document.getElementById('year');
    if (yearElement) {
        yearElement.textContent = new Date().getFullYear();
    }

    // Load and display statistics if stats element exists
    const statsElement = document.getElementById('stats');
    if (statsElement) {
        loadStatistics();
    }
});

/**
 * Load and display global statistics
 */
async function loadStatistics() {
    const statsElement = document.getElementById('stats');

    try {
        const response = await fetch('/prod/stats', {
            method: 'GET',
            headers: {
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        const downloads = data.downloads || 0;
        const totalBytes = data.total_bytes || 0;

        // Format the numbers
        const formattedDownloads = downloads.toLocaleString();
        const formattedSize = formatBytes(totalBytes);

        // Display the stats
        statsElement.textContent = `${formattedDownloads} shares • ${formattedSize} transferred`;

    } catch (error) {
        console.error('Failed to load statistics:', error);
        // Hide stats on error
        statsElement.style.display = 'none';
    }
}

/**
 * Format bytes to human-readable size
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}
