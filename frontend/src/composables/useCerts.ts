import { useCertsStore } from '@/stores/certs'
import type { CreateCertPayload } from '@/types/certification'

export function useCerts() {
  const store = useCertsStore()

  return {
    certs: () => store.certs,
    loading: () => store.loading,
    fetchCerts: () => store.fetchCerts(),
    createCert: (payload: CreateCertPayload) => store.createCert(payload),
    updateCert: (id: string, payload: CreateCertPayload) => store.updateCert(id, payload),
    deleteCert: (id: string) => store.deleteCert(id),
    updateHours: (id: string, opts: { delta?: number; value?: number }) =>
      store.updateHours(id, opts),
    abandonCert: (id: string) => store.abandonCert(id),
    restoreCert: (id: string) => store.restoreCert(id),
  }
}
