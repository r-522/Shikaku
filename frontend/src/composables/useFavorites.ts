import { useUsersStore } from '@/stores/users'

export function useFavorites() {
  const store = useUsersStore()

  return {
    users: () => store.users,
    favorites: () => store.favorites,
    loading: () => store.loading,
    fetchUsers: () => store.fetchUsers(),
    fetchFavorites: () => store.fetchFavorites(),
    toggleFavorite: (useid: string) => store.toggleFavorite(useid),
  }
}
