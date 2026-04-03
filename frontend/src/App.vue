<template>
  <div id="app-root">
    <template v-if="!initializing">
      <LoginView v-if="!isAuthenticated" />
      <DashboardView v-else />
    </template>

    <!-- Full-screen loading while restoring session -->
    <div v-else class="app-init-loading" aria-busy="true" aria-label="読み込み中">
      <div class="app-init-loading__spinner"></div>
    </div>

    <ToastContainer />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import LoginView from '@/views/LoginView.vue'
import DashboardView from '@/views/DashboardView.vue'
import ToastContainer from '@/components/organisms/ToastContainer.vue'
import { useAuthStore } from '@/stores/auth'
import { provideToast } from '@/composables/useToast'

// Provide toast context at root level
provideToast()

const authStore = useAuthStore()
const initializing = ref(true)

const isAuthenticated = computed(() => authStore.user !== null)

onMounted(async () => {
  try {
    await authStore.fetchMe()
  } finally {
    initializing.value = false
  }
})
</script>

<style scoped lang="scss">
.app-init-loading {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: #fafaf9;

  &__spinner {
    width: 36px;
    height: 36px;
    border: 3px solid rgba(26, 26, 46, 0.15);
    border-top-color: #1a1a2e;
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }
}

@keyframes spin {
  to { transform: rotate(360deg); }
}
</style>
