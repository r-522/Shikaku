<template>
  <section class="global-user-list" aria-label="みんなの状況">
    <div class="global-user-list__header">
      <h2 class="global-user-list__title">みんなの状況</h2>
    </div>

    <!-- Loading skeleton -->
    <div v-if="loading && sortedUsers.length === 0" class="global-user-list__loading" aria-busy="true">
      <div v-for="i in 5" :key="i" class="global-user-list__skeleton"></div>
    </div>

    <!-- Empty state -->
    <div
      v-else-if="!loading && sortedUsers.length === 0"
      class="global-user-list__empty"
      role="status"
    >
      <p class="global-user-list__empty-text">ユーザーがいません</p>
    </div>

    <!-- User list -->
    <div v-else class="global-user-list__list" role="list">
      <hr v-if="favoriteUsers.length > 0 && otherUsers.length > 0 && favoriteUsers.length < sortedUsers.length" class="global-user-list__divider" aria-hidden="true" />
      <UserRow
        v-for="user in sortedUsers"
        :key="user.useid"
        :user="user"
        :is-self="user.useid === currentUserId"
        role="listitem"
        @toggle-favorite="onToggleFavorite"
      />
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import UserRow from '@/components/molecules/UserRow.vue'
import { useUsersStore } from '@/stores/users'
import { useAuthStore } from '@/stores/auth'
import { useToast } from '@/composables/useToast'

const usersStore = useUsersStore()
const authStore = useAuthStore()
const { showToast } = useToast()

const loading = computed(() => usersStore.loading)
const currentUserId = computed(() => authStore.user?.useid ?? '')

const sortedUsers = computed(() => {
  const all = usersStore.users.slice()
  return all.sort((a, b) => {
    if (a.is_favorite && !b.is_favorite) return -1
    if (!a.is_favorite && b.is_favorite) return 1
    return a.usenm.localeCompare(b.usenm, 'ja')
  })
})

const favoriteUsers = computed(() => sortedUsers.value.filter((u) => u.is_favorite))
const otherUsers = computed(() => sortedUsers.value.filter((u) => !u.is_favorite))

async function onToggleFavorite(useid: string) {
  try {
    await usersStore.toggleFavorite(useid)
  } catch (e: unknown) {
    showToast(e instanceof Error ? e.message : 'お気に入りの更新に失敗しました', 'error')
  }
}

onMounted(async () => {
  try {
    await Promise.all([usersStore.fetchUsers(), usersStore.fetchFavorites()])
  } catch {
    showToast('ユーザー情報の取得に失敗しました', 'error')
  }
})
</script>

<style scoped lang="scss">
.global-user-list {
  &__header {
    padding: 20px 16px 12px;
    border-bottom: 1px solid rgba(17, 24, 39, 0.07);
  }

  &__title {
    font-size: 0.9rem;
    font-weight: 600;
    color: #6b7280;
    margin: 0;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  &__loading {
    padding: 12px 16px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  &__skeleton {
    height: 40px;
    border-radius: 6px;
    background: linear-gradient(90deg, #f3f4f6 25%, #e9ebee 50%, #f3f4f6 75%);
    background-size: 200% 100%;
    animation: shimmer 1.4s ease infinite;
  }

  &__empty {
    padding: 32px 16px;
    text-align: center;
  }

  &__empty-text {
    font-size: 0.875rem;
    color: #9ca3af;
    margin: 0;
  }

  &__list {
    // Items separated internally
  }

  &__divider {
    border: none;
    border-top: 1px solid rgba(17, 24, 39, 0.06);
    margin: 4px 16px;
  }
}

@keyframes shimmer {
  0%   { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}
</style>
