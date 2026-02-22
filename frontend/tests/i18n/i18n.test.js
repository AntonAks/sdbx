/**
 * i18n tests — locale file validation and switching
 *
 * Run with: npx vitest run tests/i18n/i18n.test.js
 */

import { describe, it, expect } from 'vitest';
import en from '../../src/i18n/locales/en.json';
import uk from '../../src/i18n/locales/uk.json';

// --- Helpers ---

function getKeys(obj, prefix = '') {
    return Object.keys(obj).flatMap(k => {
        const path = prefix ? `${prefix}.${k}` : k;
        return typeof obj[k] === 'object' && obj[k] !== null && !Array.isArray(obj[k])
            ? getKeys(obj[k], path)
            : [path];
    });
}

function getValue(obj, key) {
    return key.split('.').reduce((o, k) => o?.[k], obj);
}

// --- JSON structure tests ---

describe('en.json - completeness', () => {
    it('has all required top-level sections', () => {
        const required = ['nav', 'footer', 'home', 'upload', 'download', 'share', 'components', 'faq', 'about', 'language'];
        for (const section of required) {
            expect(en, `Missing top-level section: ${section}`).toHaveProperty(section);
        }
    });

    it('has non-empty string values for all keys', () => {
        const keys = getKeys(en);
        for (const key of keys) {
            const val = getValue(en, key);
            expect(typeof val, `Key "${key}" should be a string`).toBe('string');
            expect(val.length, `Key "${key}" should not be empty`).toBeGreaterThan(0);
        }
    });

    it('has nav keys for all navigation items', () => {
        expect(en.nav).toHaveProperty('about');
        expect(en.nav).toHaveProperty('faq');
        expect(en.nav).toHaveProperty('switchToLight');
        expect(en.nav).toHaveProperty('switchToDark');
    });

    it('has language keys for all supported locales', () => {
        expect(en.language).toHaveProperty('en');
        expect(en.language).toHaveProperty('uk');
    });

    it('has upload progress keys', () => {
        const progressKeys = ['generatingKey', 'encrypting', 'complete', 'completeRedirect'];
        for (const key of progressKeys) {
            expect(en.upload.progress, `Missing upload.progress.${key}`).toHaveProperty(key);
        }
    });

    it('has download progress keys', () => {
        const progressKeys = ['preparingDownload', 'downloading', 'decrypting', 'complete', 'downloadComplete'];
        for (const key of progressKeys) {
            expect(en.download.progress, `Missing download.progress.${key}`).toHaveProperty(key);
        }
    });

    it('has share keys for all share page elements', () => {
        const shareKeys = ['readyToShare', 'scanToDownload', 'copyQr', 'downloadQr', 'copy', 'warning', 'expired'];
        for (const key of shareKeys) {
            expect(en.share, `Missing share.${key}`).toHaveProperty(key);
        }
    });
});

describe('uk.json - key parity with en.json', () => {
    it('has exactly the same keys as en.json', () => {
        const enKeys = getKeys(en).sort();
        const ukKeys = getKeys(uk).sort();
        expect(ukKeys).toEqual(enKeys);
    });

    it('has no extra keys not present in en.json', () => {
        const enKeys = new Set(getKeys(en));
        const ukKeys = getKeys(uk);
        for (const key of ukKeys) {
            expect(enKeys.has(key), `uk.json has unexpected key: "${key}"`).toBe(true);
        }
    });

    it('has no missing keys from en.json', () => {
        const ukKeys = new Set(getKeys(uk));
        const enKeys = getKeys(en);
        for (const key of enKeys) {
            expect(ukKeys.has(key), `uk.json is missing key: "${key}"`).toBe(true);
        }
    });

    it('has pre-filled language keys', () => {
        expect(uk.language.en).toBe("English");
        expect(uk.language.uk).toBe("Солов'їна");
    });

    it('uk.json values are all strings (empty or filled)', () => {
        const keys = getKeys(uk);
        for (const key of keys) {
            const val = getValue(uk, key);
            expect(typeof val, `Key "${key}" in uk.json should be a string`).toBe('string');
        }
    });
});

