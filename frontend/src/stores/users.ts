import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'
import type { UserWithStats } from '@/types/user'

export const useUsersStore = defineStore('users', () => {
  const users = ref<UserWithStats[]>([])
  const favorites = ref<string[]>([])
  const loading = ref(false)

  async function fetchUsers() {
    loading.value = true
    try {
      const res = await axios.get<{ data: UserWithStats[]; error: string | null }>('/api/users')
      if (res.data.error) throw new Error(res.data.error)
      users.value = res.data.data ?? []
    } finally {
      loading.value = false
    }
  }

  async function fetchFavorites() {
    try {
      const res = await axios.get<{ data: string[]; error: string | null }>('/api/favorites')
      if (res.data.error) throw new Error(res.data.error)
      favorites.value = res.data.data ?? []
      // Sync is_favorite field on users
      users.value = users.value.map((u) => ({
        ...u,
        is_favorite: favorites.value.includes(u.useid),
      }))
    } catch {
      // Silently fail — favorites are non-critical
    }
  }

  async function toggleFavorite(useid: string) {
    const isFav = favorites.value.includes(useid)
    // Optimistic update
    if (isFav) {
      favorites.value = favorites.value.filter((id) => id !== useid)
    } else {
      favorites.value.push(useid)
    }
    users.value = users.value.map((u) =>
      u.useid === useid ? { ...u, is_favorite: !isFav } : u
    )

    try {
      if (isFav) {
        await axios.delete(`/api/favorites/${useid}`)
      } else {
        await axios.post(`/api/favorites/${useid}`)
      }
    } catch {
      // Roll back optimistic update on failure
      if (isFav) {
        favorites.value.push(useid)
      } else {
        favorites.value = favorites.value.filter((id) => id !== useid)
      }
      users.value = users.value.map((u) =>
        u.useid === useid ? { ...u, is_favorite: isFav } : u
      )
      throw new Error('お気に入りの更新に失敗しました')
    }
  }

  return { users, favorites, loading, fetchUsers, fetchFavorites, toggleFavorite }
})
