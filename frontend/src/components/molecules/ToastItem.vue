<template>
  <div
    :class="['toast-item', `toast-item--${toast.type}`, { 'toast-item--dismissing': dismissing }]"
    role="alert"
    aria-live="assertive"
    aria-atomic="true"
  >
    <span class="toast-item__message">{{ toast.message }}</span>
    <button
      type="button"
      class="toast-item__close"
      aria-label="通知を閉じる"
      @click="handleDismiss"
    >
      ×
    </button>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import type { Toast } from '@/composables/useToast'

const props = defineProps<{
  toast: Toast
}>()

const emit = defineEmits<{
  dismiss: [id: number]
}>()

const dismissing = ref(false)

function handleDismiss() {
  dismissing.value = true
  setTimeout(() => {
    emit('dismiss', props.toast.id)
  }, 280)
}
</script>

<style scoped lang="scss">
.toast-item {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
  min-width: 260px;
  max-width: 360px;
  padding: 12px 14px;
  border-radius: 8px;
  font-size: 0.875rem;
  font-family: inherit;
  line-height: 1.5;
  animation: slideInRight 220ms ease forwards;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);

  &--dismissing {
    animation: fadeOutRight 280ms ease forwards;
  }

  &--success {
    background-color: #ffffff;
    border-left: 3px solid #059669;
    color: #111827;
  }

  &--error {
    background-color: #fef2f2;
    border-left: 3px solid #dc2626;
    color: #7f1d1d;
  }

  &__message {
    flex: 1;
    word-break: break-word;
  }

  &__close {
    flex-shrink: 0;
    background: none;
    border: none;
    cursor: pointer;
    font-size: 1.1rem;
    line-height: 1;
    color: currentColor;
    opacity: 0.55;
    padding: 0 2px;
    transition: opacity 150ms ease;

    &:hover {
      opacity: 0.85;
    }

    &:focus-visible {
      outline: 2px solid #e85d04;
      outline-offset: 2px;
      border-radius: 2px;
    }
  }
}

@keyframes slideInRight {
  from {
    transform: translateX(110%);
    opacity: 0;
  }
  to {
    transform: translateX(0);
    opacity: 1;
  }
}

@keyframes fadeOutRight {
  from {
    transform: translateX(0);
    opacity: 1;
  }
  to {
    transform: translateX(110%);
    opacity: 0;
  }
}
</style>
