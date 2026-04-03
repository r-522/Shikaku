<template>
  <div class="dashboard">
    <AppHeader :user="user" @logout="handleLogout" />

    <main class="dashboard__main" role="main">
      <div class="dashboard__layout">
        <!-- Left column: Cert list -->
        <div class="dashboard__left">
          <CertList />
        </div>

        <!-- Right column: Global user list (sticky) -->
        <aside class="dashboard__right" aria-label="他のユーザー">
          <div class="dashboard__right-sticky">
            <GlobalUserList />
          </div>
        </aside>
      </div>
    </main>

    <ToastContainer />
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import AppHeader from '@/components/organisms/AppHeader.vue'
import CertList from '@/components/organisms/CertList.vue'
import GlobalUserList from '@/components/organisms/GlobalUserList.vue'
import ToastContainer from '@/components/organisms/ToastContainer.vue'
import { useAuthStore } from '@/stores/auth'
import { useToast } from '@/composables/useToast'
import type { User } from '@/types/auth'

const authStore = useAuthStore()
const { showToast } = useToast()

const user = computed(() => authStore.user as User)

async function handleLogout() {
  try {
    await authStore.logout()
    showToast('ログアウトしました', 'success')
  } catch {
    showToast('ログアウトに失敗しました', 'error')
  }
}
</script>

<style scoped lang="scss">
.dashboard {
  min-height: 100vh;
  background-color: #fafaf9;

  &__main {
    padding-top: 56px; // header height
  }

  &__layout {
    max-width: 1280px;
    margin: 0 auto;
    display: flex;
    align-items: flex-start;
    gap: 0;
    min-height: calc(100vh - 56px);
  }

  &__left {
    flex: 1 1 0;
    min-width: 0;
    border-right: 1px solid rgba(17, 24, 39, 0.08);
    min-height: calc(100vh - 56px);
  }

  &__right {
    width: 300px;
    flex-shrink: 0;
  }

  &__right-sticky {
    position: sticky;
    top: 56px;
    height: calc(100vh - 56px);
    overflow-y: auto;
  }

  @media (max-width: 768px) {
    &__layout {
      flex-direction: column;
    }

    &__left {
      width: 100%;
      border-right: none;
      border-bottom: 2px solid rgba(17, 24, 39, 0.08);
      min-height: unset;
    }

    &__right {
      width: 100%;
    }

    &__right-sticky {
      position: static;
      height: auto;
      overflow-y: visible;
    }
  }
}
</style>
