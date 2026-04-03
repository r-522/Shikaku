import { useAuthStore } from '@/stores/auth'
import type { LoginPayload, SignupPayload } from '@/types/auth'

export function useAuth() {
  const store = useAuthStore()

  return {
    user: store.$state,
    isAuthenticated: () => store.user !== null,
    loading: () => store.loading,
    login: (payload: LoginPayload) => store.login(payload),
    signup: (payload: SignupPayload) => store.signup(payload),
    logout: () => store.logout(),
    fetchMe: () => store.fetchMe(),
  }
}
