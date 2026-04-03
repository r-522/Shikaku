import { ref, provide, inject, type InjectionKey } from 'vue'

export interface Toast {
  id: number
  message: string
  type: 'success' | 'error'
}

export interface ToastContext {
  toasts: ReturnType<typeof ref<Toast[]>>
  showToast: (message: string, type: 'success' | 'error') => void
}

const TOAST_KEY: InjectionKey<ToastContext> = Symbol('toast')

let _nextId = 0

export function provideToast() {
  const toasts = ref<Toast[]>([])

  function showToast(message: string, type: 'success' | 'error' = 'success') {
    const id = ++_nextId
    toasts.value.push({ id, message, type })
    setTimeout(() => {
      dismissToast(id)
    }, 2400)
  }

  function dismissToast(id: number) {
    const idx = toasts.value.findIndex((t) => t.id === id)
    if (idx !== -1) toasts.value.splice(idx, 1)
  }

  const ctx: ToastContext = { toasts, showToast }
  provide(TOAST_KEY, ctx)
  return ctx
}

export function useToast(): ToastContext {
  const ctx = inject(TOAST_KEY)
  if (!ctx) throw new Error('useToast() must be used inside a component that called provideToast()')
  return ctx
}
