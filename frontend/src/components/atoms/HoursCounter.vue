<template>
  <div class="hours-counter" role="group" aria-label="学習時間">
    <button
      type="button"
      class="hours-counter__btn"
      :disabled="loading || modelValue <= 0"
      aria-label="0.5時間減らす"
      @click="decrement"
    >
      −
    </button>
    <input
      type="number"
      :value="modelValue"
      :min="0"
      :step="0.5"
      :disabled="loading"
      :class="['hours-counter__input', { 'hours-counter__input--pulse': pulsing }]"
      aria-label="学習時間（時間）"
      @change="onInputChange"
      @blur="onBlur"
    />
    <button
      type="button"
      class="hours-counter__btn"
      :disabled="loading"
      aria-label="0.5時間増やす"
      @click="increment"
    >
      ＋
    </button>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'

const props = withDefaults(
  defineProps<{
    modelValue: number
    loading?: boolean
  }>(),
  {
    loading: false,
  }
)

const emit = defineEmits<{
  'update:modelValue': [value: number]
  change: [value: number]
}>()

const pulsing = ref(false)

function triggerPulse() {
  pulsing.value = false
  requestAnimationFrame(() => {
    pulsing.value = true
    setTimeout(() => {
      pulsing.value = false
    }, 320)
  })
}

function clamp(v: number): number {
  return Math.max(0, Math.round(v * 2) / 2)
}

function decrement() {
  const next = clamp(props.modelValue - 0.5)
  emit('update:modelValue', next)
  emit('change', next)
  triggerPulse()
}

function increment() {
  const next = clamp(props.modelValue + 0.5)
  emit('update:modelValue', next)
  emit('change', next)
  triggerPulse()
}

function onInputChange(e: Event) {
  const raw = parseFloat((e.target as HTMLInputElement).value)
  if (!isNaN(raw)) {
    const next = clamp(raw)
    emit('update:modelValue', next)
    emit('change', next)
    triggerPulse()
  }
}

function onBlur(e: Event) {
  const raw = parseFloat((e.target as HTMLInputElement).value)
  if (isNaN(raw)) {
    ;(e.target as HTMLInputElement).value = String(props.modelValue)
  }
}
</script>

<style scoped lang="scss">
.hours-counter {
  display: inline-flex;
  align-items: center;
  gap: 0;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  overflow: hidden;
  height: 30px;

  &__btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 100%;
    background: #f9fafb;
    border: none;
    color: #374151;
    font-size: 1rem;
    cursor: pointer;
    transition: background-color 150ms ease, color 150ms ease;
    flex-shrink: 0;
    line-height: 1;

    &:hover:not(:disabled) {
      background-color: #e5e7eb;
      color: #111827;
    }

    &:active:not(:disabled) {
      background-color: #d1d5db;
    }

    &:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    &:focus-visible {
      outline: 2px solid #e85d04;
      outline-offset: -2px;
    }
  }

  &__input {
    width: 52px;
    height: 100%;
    border: none;
    border-left: 1px solid #e5e7eb;
    border-right: 1px solid #e5e7eb;
    text-align: center;
    font-size: 0.85rem;
    font-family: inherit;
    color: #111827;
    background: #ffffff;
    padding: 0 4px;
    outline: none;
    transition: transform 150ms ease;

    &:focus {
      background-color: #fafaf9;
      box-shadow: inset 0 0 0 2px rgba(26, 26, 46, 0.1);
    }

    &:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    // Remove number input arrows
    &::-webkit-outer-spin-button,
    &::-webkit-inner-spin-button {
      -webkit-appearance: none;
      margin: 0;
    }
    & {
      -moz-appearance: textfield;
    }

    &--pulse {
      animation: scalePulse 320ms ease;
    }
  }
}

@keyframes scalePulse {
  0%   { transform: scale(1); }
  40%  { transform: scale(1.12); }
  100% { transform: scale(1); }
}
</style>
