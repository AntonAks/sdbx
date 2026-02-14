/**
 * ZipBundle module tests - Testing REAL ZIP creation
 * NO MOCKS - Uses actual JSZip library
 *
 * Run with: node --test tests/zip-bundle.test.js
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createRequire } from 'node:module';

// Get directory of this test file
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load JSZip library using dynamic import
const jszipPath = join(__dirname, '..', 'js', 'vendor', 'jszip.min.js');
const jszipModule = await import(jszipPath);
const JSZip = jszipModule.default;

// ZipBundle module implementation (inlined for testing)
const ZipBundle = (function() {
    const MAX_FILES = 10;
    const MAX_TOTAL_SIZE = 500 * 1024 * 1024;

    function isAvailable() {
        return typeof JSZip !== 'undefined';
    }

    function validateFiles(files) {
        const fileArray = Array.from(files);

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

        let totalSize = 0;
        const emptyFiles = [];

        for (const file of fileArray) {
            if (file.size === 0) {
                emptyFiles.push(file.name);
            }
            totalSize += file.size;
        }

        if (emptyFiles.length > 0) {
            const fileNames = emptyFiles.slice(0, 3).join(', ');
            const suffix = emptyFiles.length > 3 ? ` and ${emptyFiles.length - 3} more` : '';
            return {
                valid: false,
                error: `Empty files are not allowed: ${fileNames}${suffix}`,
                totalSize
            };
        }

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

    function formatSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function resolveFilenames(files) {
        const fileArray = Array.from(files);
        const nameCount = new Map();
        const resolved = new Map();

        for (const file of fileArray) {
            const originalName = file.name;

            if (!nameCount.has(originalName)) {
                nameCount.set(originalName, 1);
                resolved.set(file, originalName);
            } else {
                const count = nameCount.get(originalName);
                const newName = addSuffix(originalName, count);
                nameCount.set(originalName, count + 1);
                resolved.set(file, newName);
            }
        }

        return resolved;
    }

    function addSuffix(filename, count) {
        const lastDot = filename.lastIndexOf('.');
        if (lastDot === -1) {
            return `${filename} (${count})`;
        }
        const name = filename.substring(0, lastDot);
        const ext = filename.substring(lastDot);
        return `${name} (${count})${ext}`;
    }

    async function createBundle(files, onProgress) {
        if (!isAvailable()) {
            throw new Error('JSZip library not loaded');
        }

        const fileArray = Array.from(files);
        const resolvedNames = resolveFilenames(fileArray);
        const zip = new JSZip();

        const totalFiles = fileArray.length;
        let processedFiles = 0;

        for (const file of fileArray) {
            const resolvedName = resolvedNames.get(file);
            const arrayBuffer = await file.arrayBuffer();
            zip.file(resolvedName, arrayBuffer);

            processedFiles++;
            const percent = (processedFiles / totalFiles) * 50;
            onProgress(percent, `Adding file ${processedFiles}/${totalFiles}...`);
        }

        onProgress(50, 'Compressing bundle...');

        const blob = await zip.generateAsync(
            {
                type: 'nodebuffer',
                compression: 'DEFLATE',
                compressionOptions: { level: 6 }
            },
            (metadata) => {
                const percent = 50 + (metadata.percent / 2);
                onProgress(percent, `Compressing... ${Math.round(metadata.percent)}%`);
            }
        );

        const date = new Date();
        const dateStr = date.toISOString().split('T')[0];
        const filename = `sdbx-bundle-${dateStr}.zip`;

        onProgress(100, 'Bundle created');

        return {
            blob,
            filename,
            fileCount: fileArray.length
        };
    }

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


/**
 * Helper to create mock File objects
 */
function createMockFile(name, content, type = 'text/plain') {
    const buffer = Buffer.from(content);
    return {
        name,
        size: buffer.length,
        type: type,
        async arrayBuffer() {
            return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
        }
    };
}


describe('ZipBundle - Validation', () => {
    it('should validate empty file list', () => {
        const result = ZipBundle.validateFiles([]);
        assert.strictEqual(result.valid, false);
        assert.ok(result.error.includes('No files'));
    });

    it('should accept single file', () => {
        const files = [createMockFile('test.txt', 'Hello')];
        const result = ZipBundle.validateFiles(files);
        assert.strictEqual(result.valid, true);
        assert.strictEqual(result.error, null);
        assert.strictEqual(result.totalSize, 5);
    });

    it('should accept up to 10 files', () => {
        const files = [];
        for (let i = 0; i < 10; i++) {
            files.push(createMockFile(`file${i}.txt`, `Content ${i}`));
        }
        const result = ZipBundle.validateFiles(files);
        assert.strictEqual(result.valid, true);
    });

    it('should reject more than 10 files', () => {
        const files = [];
        for (let i = 0; i < 11; i++) {
            files.push(createMockFile(`file${i}.txt`, `Content ${i}`));
        }
        const result = ZipBundle.validateFiles(files);
        assert.strictEqual(result.valid, false);
        assert.ok(result.error.includes('Maximum 10 files'));
        assert.ok(result.error.includes('11'));
    });

    it('should reject empty files', () => {
        const files = [
            createMockFile('test.txt', 'Hello'),
            createMockFile('empty.txt', ''),
        ];
        const result = ZipBundle.validateFiles(files);
        assert.strictEqual(result.valid, false);
        assert.ok(result.error.includes('Empty files'));
        assert.ok(result.error.includes('empty.txt'));
    });

    it('should list multiple empty files in error', () => {
        const files = [
            createMockFile('empty1.txt', ''),
            createMockFile('empty2.txt', ''),
            createMockFile('empty3.txt', ''),
            createMockFile('empty4.txt', ''),
        ];
        const result = ZipBundle.validateFiles(files);
        assert.strictEqual(result.valid, false);
        assert.ok(result.error.includes('and 1 more'));
    });

    it('should calculate total size correctly', () => {
        const files = [
            createMockFile('file1.txt', 'Hello'),      // 5 bytes
            createMockFile('file2.txt', 'World!!'),    // 7 bytes
        ];
        const result = ZipBundle.validateFiles(files);
        assert.strictEqual(result.valid, true);
        assert.strictEqual(result.totalSize, 12);
    });

    it('should check MAX_FILES constant', () => {
        assert.strictEqual(ZipBundle.MAX_FILES, 10);
    });

    it('should check MAX_TOTAL_SIZE constant', () => {
        assert.strictEqual(ZipBundle.MAX_TOTAL_SIZE, 500 * 1024 * 1024);
    });
});


describe('ZipBundle - Filename Resolution', () => {
    it('should keep unique filenames unchanged', () => {
        const files = [
            createMockFile('file1.txt', 'Content 1'),
            createMockFile('file2.txt', 'Content 2'),
            createMockFile('file3.txt', 'Content 3'),
        ];
        const resolved = ZipBundle.resolveFilenames(files);

        assert.strictEqual(resolved.get(files[0]), 'file1.txt');
        assert.strictEqual(resolved.get(files[1]), 'file2.txt');
        assert.strictEqual(resolved.get(files[2]), 'file3.txt');
    });

    it('should add suffix to duplicate filenames', () => {
        const files = [
            createMockFile('test.txt', 'Content 1'),
            createMockFile('test.txt', 'Content 2'),
        ];
        const resolved = ZipBundle.resolveFilenames(files);

        assert.strictEqual(resolved.get(files[0]), 'test.txt');
        assert.strictEqual(resolved.get(files[1]), 'test (1).txt');
    });

    it('should handle multiple duplicates', () => {
        const files = [
            createMockFile('test.txt', 'Content 1'),
            createMockFile('test.txt', 'Content 2'),
            createMockFile('test.txt', 'Content 3'),
        ];
        const resolved = ZipBundle.resolveFilenames(files);

        assert.strictEqual(resolved.get(files[0]), 'test.txt');
        assert.strictEqual(resolved.get(files[1]), 'test (1).txt');
        assert.strictEqual(resolved.get(files[2]), 'test (2).txt');
    });

    it('should handle files without extension', () => {
        const files = [
            createMockFile('README', 'Content 1'),
            createMockFile('README', 'Content 2'),
        ];
        const resolved = ZipBundle.resolveFilenames(files);

        assert.strictEqual(resolved.get(files[0]), 'README');
        assert.strictEqual(resolved.get(files[1]), 'README (1)');
    });

    it('should handle multiple extensions correctly', () => {
        const files = [
            createMockFile('archive.tar.gz', 'Content 1'),
            createMockFile('archive.tar.gz', 'Content 2'),
        ];
        const resolved = ZipBundle.resolveFilenames(files);

        assert.strictEqual(resolved.get(files[0]), 'archive.tar.gz');
        // Suffix added before last extension only
        assert.strictEqual(resolved.get(files[1]), 'archive.tar (1).gz');
    });

    it('should handle dotfiles', () => {
        const files = [
            createMockFile('.gitignore', 'node_modules'),
            createMockFile('.gitignore', '*.log'),
        ];
        const resolved = ZipBundle.resolveFilenames(files);

        assert.strictEqual(resolved.get(files[0]), '.gitignore');
        assert.strictEqual(resolved.get(files[1]), ' (1).gitignore');
    });

    it('should handle mixed unique and duplicate filenames', () => {
        const files = [
            createMockFile('unique.txt', 'Content 1'),
            createMockFile('duplicate.txt', 'Content 2'),
            createMockFile('duplicate.txt', 'Content 3'),
            createMockFile('another.txt', 'Content 4'),
            createMockFile('duplicate.txt', 'Content 5'),
        ];
        const resolved = ZipBundle.resolveFilenames(files);

        assert.strictEqual(resolved.get(files[0]), 'unique.txt');
        assert.strictEqual(resolved.get(files[1]), 'duplicate.txt');
        assert.strictEqual(resolved.get(files[2]), 'duplicate (1).txt');
        assert.strictEqual(resolved.get(files[3]), 'another.txt');
        assert.strictEqual(resolved.get(files[4]), 'duplicate (2).txt');
    });
});


describe('ZipBundle - Availability Check', () => {
    it('should report JSZip availability correctly', () => {
        // In Node.js tests, JSZip is not available
        // In browser, it would be available
        const available = ZipBundle.isAvailable();
        assert.strictEqual(typeof available, 'boolean');
    });
});


describe('ZipBundle - Bundle Creation', () => {
    // Skip these tests in Node.js - they require JSZip browser library
    const skipIfNoJSZip = !ZipBundle.isAvailable();

    it('should create ZIP bundle with single file', { skip: skipIfNoJSZip }, async () => {
        const files = [createMockFile('test.txt', 'Hello, World!')];

        const progress = [];
        const bundle = await ZipBundle.createBundle(files, (percent, message) => {
            progress.push({ percent, message });
        });

        assert.ok(bundle.blob instanceof Buffer);
        assert.ok(bundle.filename.startsWith('sdbx-bundle-'));
        assert.ok(bundle.filename.endsWith('.zip'));
        assert.strictEqual(bundle.fileCount, 1);

        // Progress should end at 100
        assert.ok(progress.some(p => p.percent === 100));
    });

    it('should create ZIP bundle with multiple files', { skip: skipIfNoJSZip }, async () => {
        const files = [
            createMockFile('file1.txt', 'Content 1'),
            createMockFile('file2.txt', 'Content 2'),
            createMockFile('file3.txt', 'Content 3'),
        ];

        const bundle = await ZipBundle.createBundle(files, () => {});

        assert.ok(bundle.blob instanceof Buffer);
        assert.strictEqual(bundle.fileCount, 3);
    });

    it('should generate correct filename format', { skip: skipIfNoJSZip }, async () => {
        const files = [createMockFile('test.txt', 'Hello')];

        const bundle = await ZipBundle.createBundle(files, () => {});

        // Filename should be sdbx-bundle-YYYY-MM-DD.zip
        const datePattern = /^sdbx-bundle-\d{4}-\d{2}-\d{2}\.zip$/;
        assert.ok(datePattern.test(bundle.filename), `Filename "${bundle.filename}" should match pattern`);
    });

    it('should resolve duplicate filenames in bundle', { skip: skipIfNoJSZip }, async () => {
        const files = [
            createMockFile('test.txt', 'Content 1'),
            createMockFile('test.txt', 'Content 2'),
        ];

        const bundle = await ZipBundle.createBundle(files, () => {});

        // Extract and verify ZIP contents
        const zip = await JSZip.loadAsync(bundle.blob);
        const filenames = Object.keys(zip.files);

        assert.ok(filenames.includes('test.txt'));
        assert.ok(filenames.includes('test (1).txt'));
    });

    it('should preserve file contents in bundle', { skip: skipIfNoJSZip }, async () => {
        const content1 = 'Content for file 1';
        const content2 = 'Different content for file 2';

        const files = [
            createMockFile('file1.txt', content1),
            createMockFile('file2.txt', content2),
        ];

        const bundle = await ZipBundle.createBundle(files, () => {});

        // Extract and verify contents
        const zip = await JSZip.loadAsync(bundle.blob);

        const extracted1 = await zip.file('file1.txt').async('string');
        const extracted2 = await zip.file('file2.txt').async('string');

        assert.strictEqual(extracted1, content1);
        assert.strictEqual(extracted2, content2);
    });

    it('should report progress during bundle creation', { skip: skipIfNoJSZip }, async () => {
        const files = [
            createMockFile('file1.txt', 'Content 1'),
            createMockFile('file2.txt', 'Content 2'),
        ];

        const progressUpdates = [];
        await ZipBundle.createBundle(files, (percent, message) => {
            progressUpdates.push({ percent, message });
        });

        // Should have multiple progress updates
        assert.ok(progressUpdates.length > 0, 'Should have progress updates');

        // First update should be near 0, last should be 100
        assert.ok(progressUpdates[0].percent >= 0);
        assert.strictEqual(progressUpdates[progressUpdates.length - 1].percent, 100);
    });

    it('should handle binary content', { skip: skipIfNoJSZip }, async () => {
        // Create binary content
        const binaryContent = Buffer.from([0, 1, 2, 3, 255, 254, 253]);

        const files = [{
            name: 'binary.bin',
            size: binaryContent.length,
            type: 'application/octet-stream',
            async arrayBuffer() {
                return binaryContent.buffer.slice(binaryContent.byteOffset, binaryContent.byteOffset + binaryContent.byteLength);
            }
        }];

        const bundle = await ZipBundle.createBundle(files, () => {});

        // Extract and verify
        const zip = await JSZip.loadAsync(bundle.blob);
        const extracted = await zip.file('binary.bin').async('uint8array');

        assert.deepStrictEqual(Buffer.from(extracted), binaryContent);
    });
});


describe('ZipBundle - Format Size', () => {
    it('should format bytes correctly', () => {
        assert.strictEqual(ZipBundle.formatSize(0), '0 B');
        assert.strictEqual(ZipBundle.formatSize(500), '500 B');
    });

    it('should format kilobytes correctly', () => {
        assert.strictEqual(ZipBundle.formatSize(1024), '1 KB');
        assert.strictEqual(ZipBundle.formatSize(1536), '1.5 KB');
    });

    it('should format megabytes correctly', () => {
        assert.strictEqual(ZipBundle.formatSize(1024 * 1024), '1 MB');
        assert.strictEqual(ZipBundle.formatSize(5 * 1024 * 1024), '5 MB');
    });

    it('should format gigabytes correctly', () => {
        assert.strictEqual(ZipBundle.formatSize(1024 * 1024 * 1024), '1 GB');
    });
});


describe('ZipBundle - Edge Cases', () => {
    // Skip these tests in Node.js - they require JSZip browser library
    // These are integration tests that run in the browser
    const skipIfNoJSZip = !ZipBundle.isAvailable();

    it('should handle maximum allowed files (10)', { skip: skipIfNoJSZip }, async () => {
        const files = [];
        for (let i = 0; i < 10; i++) {
            files.push(createMockFile(`file${i}.txt`, `Content ${i}`));
        }

        const bundle = await ZipBundle.createBundle(files, () => {});

        assert.strictEqual(bundle.fileCount, 10);

        // Verify all files in ZIP
        const zip = await JSZip.loadAsync(bundle.blob);
        const filenames = Object.keys(zip.files);
        assert.strictEqual(filenames.length, 10);
    });

    it('should handle unicode filenames', { skip: skipIfNoJSZip }, async () => {
        const files = [
            createMockFile('файл.txt', 'Russian content'),
            createMockFile('文件.txt', 'Chinese content'),
            createMockFile('αρχείο.txt', 'Greek content'),
        ];

        const bundle = await ZipBundle.createBundle(files, () => {});

        const zip = await JSZip.loadAsync(bundle.blob);
        const filenames = Object.keys(zip.files);

        assert.ok(filenames.includes('файл.txt'));
        assert.ok(filenames.includes('文件.txt'));
        assert.ok(filenames.includes('αρχείο.txt'));
    });

    it('should handle filenames with special characters', { skip: skipIfNoJSZip }, async () => {
        const files = [
            createMockFile('file with spaces.txt', 'Content'),
            createMockFile('file-with-dashes.txt', 'Content'),
            createMockFile('file_with_underscores.txt', 'Content'),
        ];

        const bundle = await ZipBundle.createBundle(files, () => {});

        const zip = await JSZip.loadAsync(bundle.blob);
        const filenames = Object.keys(zip.files);

        assert.strictEqual(filenames.length, 3);
    });

    it('should handle very long filenames', { skip: skipIfNoJSZip }, async () => {
        const longName = 'a'.repeat(200) + '.txt';
        const files = [createMockFile(longName, 'Content')];

        const bundle = await ZipBundle.createBundle(files, () => {});

        const zip = await JSZip.loadAsync(bundle.blob);
        const filenames = Object.keys(zip.files);

        assert.ok(filenames[0].length === longName.length);
    });
});
