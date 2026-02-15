<template>
  <AppHeader />
  <router-view />
  <AppFooter />
</template>

<script setup>
import { ref, provide } from 'vue';
import AppHeader from './components/AppHeader.vue';
import AppFooter from './components/AppFooter.vue';

const homeResetKey = ref(0);
provide('homeResetKey', homeResetKey);
provide('triggerHomeReset', () => homeResetKey.value++);
</script>
