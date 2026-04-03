<template>
  <div
    class="toast-container"
    role="region"
    aria-label="通知"
    aria-live="polite"
  >
    <TransitionGroup name="toast-list" tag="div" class="toast-container__stack">
      <ToastItem
        v-for="toast in toasts"
        :key="toast.id"
        :toast="toast"
        @dismiss="dismissToast"
      />
    </TransitionGroup>
  </div>
</template>

<script setup lang="ts">
import ToastItem from '@/components/molecules/ToastItem.vue'
import { useToast } from '@/composables/useToast'

const { toasts } = useToast()

function dismissToast(id: number) {
  const idx = toasts.value.findIndex((t) => t.id === id)
  if (idx !== -1) toasts.value.splice(idx, 1)
}
</script>

<style scoped lang="scss">
.toast-container {
  position: fixed;
  bottom: 24px;
  right: 24px;
  z-index: 9999;
  pointer-events: none;

  &__stack {
    display: flex;
    flex-direction: column;
    gap: 8px;
    align-items: flex-end;
  }

  // Each toast item needs pointer events re-enabled
  :deep(.toast-item) {
    pointer-events: auto;
  }
}

.toast-list-enter-active {
  animation: slideInRight 220ms ease forwards;
}

.toast-list-leave-active {
  animation: fadeOutRight 280ms ease forwards;
}

.toast-list-move {
  transition: transform 200ms ease;
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
