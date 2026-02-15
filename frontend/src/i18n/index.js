import { createI18n } from 'vue-i18n';
import en from './locales/en.json';
import uk from './locales/uk.json';

const LOCALE_KEY = 'sdbx-locale';
const SUPPORTED_LOCALES = ['en', 'uk'];

function detectLocale() {
  const saved = localStorage.getItem(LOCALE_KEY);
  if (saved && SUPPORTED_LOCALES.includes(saved)) return saved;

  const browserLang = navigator.language?.split('-')[0];
  if (browserLang && SUPPORTED_LOCALES.includes(browserLang)) return browserLang;

  return 'en';
}

const i18n = createI18n({
  legacy: false,
  locale: detectLocale(),
  fallbackLocale: 'en',
  messages: { en, uk },
});

export function setLocale(locale) {
  if (SUPPORTED_LOCALES.includes(locale)) {
    i18n.global.locale.value = locale;
    localStorage.setItem(LOCALE_KEY, locale);
    document.documentElement.setAttribute('lang', locale);
  }
}

export function getLocale() {
  return i18n.global.locale.value;
}

export { SUPPORTED_LOCALES };
export default i18n;
