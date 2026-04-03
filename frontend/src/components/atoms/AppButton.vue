<template>
  <button
    :type="type"
    :class="['app-btn', `app-btn--${variant}`, `app-btn--${size}`, { 'app-btn--loading': loading }]"
    :disabled="disabled || loading"
    :aria-busy="loading || undefined"
    :aria-disabled="disabled || loading || undefined"
  >
    <span v-if="loading" class="app-btn__spinner" aria-hidden="true"></span>
    <span :class="{ 'app-btn__content--hidden': loading }">
      <slot />
    </span>
  </button>
</template>

<script setup lang="ts">
withDefaults(
  defineProps<{
    variant?: 'primary' | 'secondary' | 'danger' | 'ghost'
    size?: 'sm' | 'md' | 'lg'
    loading?: boolean
    disabled?: boolean
    type?: 'button' | 'submit' | 'reset'
  }>(),
  {
    variant: 'primary',
    size: 'md',
    loading: false,
    disabled: false,
    type: 'button',
  }
)
</script>

<style scoped lang="scss">
.app-btn {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.375rem;
  border: none;
  border-radius: 6px;
  font-family: inherit;
  font-weight: 500;
  letter-spacing: -0.01em;
  cursor: pointer;
  transition: transform 150ms ease, background-color 150ms ease, color 150ms ease,
    box-shadow 150ms ease, opacity 150ms ease;
  white-space: nowrap;
  line-height: 1;

  &:not(:disabled):hover {
    transform: scale(1.02);
  }

  &:focus-visible {
    outline: 2px solid #e85d04;
    outline-offset: 2px;
  }

  &:disabled {
    cursor: not-allowed;
    opacity: 0.55;
  }

  // Sizes
  &--sm {
    font-size: 0.8125rem;
    padding: 5px 12px;
    height: 30px;
  }

  &--md {
    font-size: 0.875rem;
    padding: 8px 18px;
    height: 38px;
  }

  &--lg {
    font-size: 0.9375rem;
    padding: 11px 24px;
    height: 46px;
  }

  // Variants
  &--primary {
    background-color: #1a1a2e;
    color: #fafaf9;

    &:not(:disabled):hover {
      background-color: #252545;
    }
    &:not(:disabled):active {
      background-color: #141428;
      transform: scale(0.99);
    }
  }

  &--secondary {
    background-color: #f3f4f6;
    color: #374151;
    border: 1px solid #e5e7eb;

    &:not(:disabled):hover {
      background-color: #e9ebee;
    }
    &:not(:disabled):active {
      background-color: #e0e2e7;
      transform: scale(0.99);
    }
  }

  &--danger {
    background-color: #dc2626;
    color: #ffffff;

    &:not(:disabled):hover {
      background-color: #b91c1c;
    }
    &:not(:disabled):active {
      background-color: #991b1b;
      transform: scale(0.99);
    }
  }

  &--ghost {
    background-color: transparent;
    color: #4b5563;
    border: 1px solid transparent;

    &:not(:disabled):hover {
      background-color: rgba(17, 24, 39, 0.06);
      border-color: rgba(17, 24, 39, 0.1);
    }
    &:not(:disabled):active {
      background-color: rgba(17, 24, 39, 0.1);
      transform: scale(0.99);
    }
  }

  // Loading state
  &--loading {
    cursor: wait;
  }

  &__spinner {
    position: absolute;
    width: 14px;
    height: 14px;
    border: 2px solid currentColor;
    border-right-color: transparent;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
    opacity: 0.8;
  }

  &__content--hidden {
    visibility: hidden;
  }
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
