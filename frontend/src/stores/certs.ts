import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'
import type { OwnCert, CreateCertPayload } from '@/types/certification'

export const useCertsStore = defineStore('certs', () => {
  const certs = ref<OwnCert[]>([])
  const loading = ref(false)

  async function fetchCerts() {
    loading.value = true
    try {
      const res = await axios.get<{ data: OwnCert[]; error: string | null }>('/api/my/certs')
      if (res.data.error) throw new Error(res.data.error)
      certs.value = res.data.data ?? []
    } finally {
      loading.value = false
    }
  }

  async function createCert(payload: CreateCertPayload) {
    loading.value = true
    try {
      const res = await axios.post<{ data: OwnCert; error: string | null }>('/api/my/certs', payload)
      if (res.data.error) throw new Error(res.data.error)
      certs.value.unshift(res.data.data)
      return res.data.data
    } finally {
      loading.value = false
    }
  }

  async function updateCert(id: string, payload: CreateCertPayload) {
    loading.value = true
    try {
      const res = await axios.put<{ data: OwnCert; error: string | null }>(
        `/api/my/certs/${id}`,
        payload
      )
      if (res.data.error) throw new Error(res.data.error)
      const idx = certs.value.findIndex((c) => c.ownid === id)
      if (idx !== -1) certs.value[idx] = res.data.data
      return res.data.data
    } finally {
      loading.value = false
    }
  }

  async function deleteCert(id: string) {
    loading.value = true
    try {
      await axios.delete(`/api/my/certs/${id}`)
      certs.value = certs.value.filter((c) => c.ownid !== id)
    } finally {
      loading.value = false
    }
  }

  async function updateHours(id: string, opts: { delta?: number; value?: number }) {
    try {
      const res = await axios.patch<{ data: { ownhr: number }; error: string | null }>(
        `/api/my/certs/${id}/hours`,
        opts
      )
      if (res.data.error) throw new Error(res.data.error)
      const idx = certs.value.findIndex((c) => c.ownid === id)
      if (idx !== -1) certs.value[idx] = { ...certs.value[idx], ownhr: res.data.data.ownhr }
      return res.data.data.ownhr
    } catch (err) {
      throw err
    }
  }

  async function abandonCert(id: string) {
    loading.value = true
    try {
      const res = await axios.post<{ data: OwnCert; error: string | null }>(
        `/api/my/certs/${id}/abandon`
      )
      if (res.data.error) throw new Error(res.data.error)
      const idx = certs.value.findIndex((c) => c.ownid === id)
      if (idx !== -1) certs.value[idx] = res.data.data
      return res.data.data
    } finally {
      loading.value = false
    }
  }

  async function restoreCert(id: string) {
    loading.value = true
    try {
      const res = await axios.post<{ data: OwnCert; error: string | null }>(
        `/api/my/certs/${id}/restore`
      )
      if (res.data.error) throw new Error(res.data.error)
      const idx = certs.value.findIndex((c) => c.ownid === id)
      if (idx !== -1) certs.value[idx] = res.data.data
      return res.data.data
    } finally {
      loading.value = false
    }
  }

  return {
    certs,
    loading,
    fetchCerts,
    createCert,
    updateCert,
    deleteCert,
    updateHours,
    abandonCert,
    restoreCert,
  }
})
