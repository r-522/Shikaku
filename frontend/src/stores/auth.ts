import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'
import type { User, LoginPayload, SignupPayload } from '@/types/auth'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const loading = ref(false)

  async function fetchMe() {
    loading.value = true
    try {
      const res = await axios.get<{ data: User | null; error: string | null }>('/api/auth/me')
      user.value = res.data.data
    } catch {
      user.value = null
    } finally {
      loading.value = false
    }
  }

  async function login(payload: LoginPayload) {
    loading.value = true
    try {
      const res = await axios.post<{ data: User; error: string | null }>('/api/auth/login', payload)
      if (res.data.error) throw new Error(res.data.error)
      user.value = res.data.data
      return res.data.data
    } finally {
      loading.value = false
    }
  }

  async function signup(payload: SignupPayload) {
    loading.value = true
    try {
      const res = await axios.post<{ data: User; error: string | null }>('/api/auth/signup', {
        email: payload.email,
        password: payload.password,
        username: payload.username,
      })
      if (res.data.error) throw new Error(res.data.error)
      user.value = res.data.data
      return res.data.data
    } finally {
      loading.value = false
    }
  }

  async function logout() {
    loading.value = true
    try {
      await axios.post('/api/auth/logout')
    } finally {
      user.value = null
      loading.value = false
    }
  }

  return { user, loading, fetchMe, login, signup, logout }
})
