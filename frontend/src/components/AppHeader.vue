<template>
  <header class="bg-gray-100 dark:bg-slate-900 border-b border-gray-200 dark:border-slate-800">
    <div class="max-w-4xl mx-auto px-6 py-6 flex items-center justify-between">
      <a @click.prevent="goHome" href="/" class="flex items-center gap-3 cursor-pointer">
        <img src="/img/logo.png" alt="sdbx logo" class="w-14 h-14">
        <span class="text-xl font-semibold text-gray-900 dark:text-slate-100">sdbx</span>
      </a>
      <nav class="flex items-center gap-6">
        <router-link
          v-if="route.path !== '/'"
          to="/"
          class="text-sm text-gray-600 dark:text-slate-400 hover:text-gray-900 dark:hover:text-slate-200 transition"
        >Home</router-link>
        <router-link
          to="/about"
          :class="route.path === '/about'
            ? 'text-sm text-blue-600 dark:text-blue-500'
            : 'text-sm text-gray-600 dark:text-slate-400 hover:text-gray-900 dark:hover:text-slate-200 transition'"
        >About</router-link>
        <router-link
          to="/faq"
          :class="route.path === '/faq'
            ? 'text-sm text-blue-600 dark:text-blue-500'
            : 'text-sm text-gray-600 dark:text-slate-400 hover:text-gray-900 dark:hover:text-slate-200 transition'"
        >FAQ</router-link>
        <button
          @click="themeStore.toggle()"
          class="p-2 rounded-lg hover:bg-gray-200 dark:hover:bg-slate-800 transition-colors"
          :aria-label="themeStore.isDark ? 'Switch to light mode' : 'Switch to dark mode'"
        >
          <!-- Sun icon (dark mode) -->
          <svg v-if="themeStore.isDark" class="w-5 h-5 text-slate-300" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="4"/>
            <path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32l1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41m11.32-11.32l1.41-1.41"/>
          </svg>
          <!-- Moon icon (light mode) -->
          <svg v-else class="w-5 h-5 text-slate-700" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/>
          </svg>
        </button>
      </nav>
    </div>
  </header>
</template>

<script setup>
import { inject } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useThemeStore } from '../stores/theme.js';

const route = useRoute();
const router = useRouter();
const themeStore = useThemeStore();
const triggerHomeReset = inject('triggerHomeReset');

function goHome() {
  triggerHomeReset();
  router.push('/');
}
</script>
