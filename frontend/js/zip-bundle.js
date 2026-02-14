/**
 * ZIP Bundle Module
 * Creates ZIP archives from multiple files for bundled uploads.
 * Preserves zero-knowledge architecture - ZIP is created client-side.
 */

'use strict';

const ZipBundle = (function() {
    // Constants
    const MAX_FILES = 10;
    const MAX_TOTAL_SIZE = 500 * 1024 * 1024; // 500 MB

    /**
     * Check if JSZip is available
     * @returns {boolean}
     */
    function isAvailable() {
        return typeof JSZip !== 'undefined';
    }

    /**
     * Validate files for bundling
     * @param {FileList|File[]} files - Files to validate
     * @returns {{valid: boolean, error: string|null, totalSize: number}}
     */
    function validateFiles(files) {
        const fileArray = Array.from(files);

        // Check file count
        if (fileArray.length === 0) {
            return { valid: false, error: 'No files selected', totalSize: 0 };
        }

        if (fileArray.length > MAX_FILES) {
            return {
                valid: false,
                error: `Maximum ${MAX_FILES} files allowed. You selected ${fileArray.length} files.`,
                totalSize: 0
            };
        }

        // Calculate total size and check for empty files
        let totalSize = 0;
        const emptyFiles = [];

        for (const file of fileArray) {
            if (file.size === 0) {
                emptyFiles.push(file.name);
            }
            totalSize += file.size;
        }

        // Reject empty files
        if (emptyFiles.length > 0) {
            const fileNames = emptyFiles.slice(0, 3).join(', ');
            const suffix = emptyFiles.length > 3 ? ` and ${emptyFiles.length - 3} more` : '';
            return {
                valid: false,
                error: `Empty files are not allowed: ${fileNames}${suffix}`,
                totalSize
            };
        }

        // Check total size
        if (totalSize > MAX_TOTAL_SIZE) {
            const formattedMax = formatSize(MAX_TOTAL_SIZE);
            const formattedTotal = formatSize(totalSize);
            return {
                valid: false,
                error: `Total size (${formattedTotal}) exceeds ${formattedMax} limit`,
                totalSize
            };
        }

        return { valid: true, error: null, totalSize };
    }

    /**
     * Format file size for display
     * @param {number} bytes
     * @returns {string}
     */
    function formatSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    /**
     * Resolve duplicate filenames by adding suffix
     * @param {FileList|File[]} files - Files to process
     * @returns {Map<File, string>} Map of file to resolved filename
     */
    function resolveFilenames(files) {
        const fileArray = Array.from(files);
        const nameCount = new Map();
        const resolved = new Map();

        for (const file of fileArray) {
            const originalName = file.name;

            if (!nameCount.has(originalName)) {
                // First occurrence - use original name
                nameCount.set(originalName, 1);
                resolved.set(file, originalName);
            } else {
                // Duplicate found - add suffix
                const count = nameCount.get(originalName);
                const newName = addSuffix(originalName, count);
                nameCount.set(originalName, count + 1);
                resolved.set(file, newName);
            }
        }

        return resolved;
    }

    /**
     * Add numeric suffix to filename
     * @param {string} filename
     * @param {number} count
     * @returns {string}
     */
    function addSuffix(filename, count) {
        const lastDot = filename.lastIndexOf('.');
        if (lastDot === -1) {
            // No extension
            return `${filename} (${count})`;
        }
        const name = filename.substring(0, lastDot);
        const ext = filename.substring(lastDot);
        return `${name} (${count})${ext}`;
    }

    /**
     * Create ZIP bundle from files
     * @param {FileList|File[]} files - Files to bundle
     * @param {function(number, string): void} onProgress - Progress callback (0-100, message)
     * @returns {Promise<{blob: Blob, filename: string, fileCount: number}>}
     */
    async function createBundle(files, onProgress) {
        if (!isAvailable()) {
            throw new Error('JSZip library not loaded');
        }

        const fileArray = Array.from(files);
        const resolvedNames = resolveFilenames(fileArray);
        const zip = new JSZip();

        // Add files to ZIP
        const totalFiles = fileArray.length;
        let processedFiles = 0;

        for (const file of fileArray) {
            const resolvedName = resolvedNames.get(file);
            const arrayBuffer = await file.arrayBuffer();
            zip.file(resolvedName, arrayBuffer);

            processedFiles++;
            const percent = (processedFiles / totalFiles) * 50; // 0-50% for adding files
            onProgress(percent, `Adding file ${processedFiles}/${totalFiles}...`);
        }

        // Generate ZIP with compression
        onProgress(50, 'Compressing bundle...');

        const blob = await zip.generateAsync(
            {
                type: 'blob',
                compression: 'DEFLATE',
                compressionOptions: { level: 6 }
            },
            (metadata) => {
                // Map compression progress to 50-100%
                const percent = 50 + (metadata.percent / 2);
                onProgress(percent, `Compressing... ${Math.round(metadata.percent)}%`);
            }
        );

        // Generate filename with date
        const date = new Date();
        const dateStr = date.toISOString().split('T')[0]; // YYYY-MM-DD
        const filename = `sdbx-bundle-${dateStr}.zip`;

        onProgress(100, 'Bundle created');

        return {
            blob,
            filename,
            fileCount: fileArray.length
        };
    }

    // Public API
    return {
        MAX_FILES,
        MAX_TOTAL_SIZE,
        isAvailable,
        validateFiles,
        resolveFilenames,
        createBundle,
        formatSize
    };
})();
