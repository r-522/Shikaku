<template>
  <div class="app-input">
    <label v-if="label" :for="inputId" class="app-input__label">{{ label }}</label>
    <input
      :id="inputId"
      :type="type"
      :value="modelValue"
      :placeholder="placeholder"
      :class="['app-input__field', { 'app-input__field--error': error }]"
      :aria-describedby="error ? `${inputId}-error` : undefined"
      :aria-invalid="error ? 'true' : undefined"
      v-bind="$attrs"
      @input="$emit('update:modelValue', ($event.target as HTMLInputElement).value)"
    />
    <p
      v-if="error"
      :id="`${inputId}-error`"
      class="app-input__error"
      role="alert"
    >
      {{ error }}
    </p>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

defineOptions({ inheritAttrs: false })

const props = withDefaults(
  defineProps<{
    modelValue: string
    label?: string
    type?: 'text' | 'email' | 'password' | 'date' | 'number'
    placeholder?: string
    error?: string
    id?: string
  }>(),
  {
    label: '',
    type: 'text',
    placeholder: '',
    error: '',
    id: '',
  }
)

defineEmits<{
  'update:modelValue': [value: string]
}>()

let _idCounter = 0
const inputId = computed(() => props.id || `app-input-${++_idCounter}`)
</script>

<style scoped lang="scss">
.app-input {
  display: flex;
  flex-direction: column;
  gap: 4px;

  &__label {
    font-size: 0.8125rem;
    font-weight: 500;
    color: #374151;
    letter-spacing: -0.005em;
  }

  &__field {
    width: 100%;
    padding: 8px 12px;
    font-size: 0.9rem;
    font-family: inherit;
    color: #111827;
    background-color: #ffffff;
    border: 1px solid #d1d5db;
    border-radius: 6px;
    line-height: 1.5;
    transition: border-color 150ms ease, box-shadow 150ms ease;
    outline: none;

    &::placeholder {
      color: #9ca3af;
    }

    &:focus {
      border-color: #1a1a2e;
      box-shadow: 0 0 0 3px rgba(26, 26, 46, 0.1);
    }

    &--error {
      border-color: #dc2626;

      &:focus {
        box-shadow: 0 0 0 3px rgba(220, 38, 38, 0.12);
      }
    }
  }

  &__error {
    font-size: 0.78rem;
    color: #dc2626;
    margin: 0;
    letter-spacing: 0;
  }
}
</style>
