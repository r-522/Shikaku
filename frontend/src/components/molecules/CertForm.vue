<template>
  <form class="cert-form" @submit.prevent="handleSubmit" novalidate>
    <div class="cert-form__field">
      <div class="cert-form__autocomplete-wrap">
        <AppInput
          v-model="form.ownnm"
          label="資格名 *"
          type="text"
          placeholder="例：基本情報技術者試験"
          :error="errors.ownnm"
          autocomplete="off"
          @input="onNameInput"
          @keydown="onNameKeydown"
        />
        <ul
          v-if="suggestions.length > 0 && showDropdown"
          class="cert-form__suggestions"
          role="listbox"
          aria-label="資格名の候補"
        >
          <li
            v-for="(sug, idx) in suggestions"
            :key="sug.cerid"
            :class="['cert-form__suggestion', { 'cert-form__suggestion--active': idx === activeIndex }]"
            role="option"
            :aria-selected="idx === activeIndex"
            @mousedown.prevent="selectSuggestion(sug)"
          >
            <span class="cert-form__suggestion-name">{{ sug.cernm }}</span>
            <span class="cert-form__suggestion-cat">{{ sug.cerct }}</span>
          </li>
        </ul>
      </div>
    </div>

    <div class="cert-form__field">
      <label class="cert-form__label" for="cert-form-status">ステータス *</label>
      <select
        id="cert-form-status"
        v-model="form.ownst"
        class="cert-form__select"
        :class="{ 'cert-form__select--error': errors.ownst }"
        aria-required="true"
      >
        <option value="studying">勉強中</option>
        <option value="passed">合格</option>
        <option value="failed">不合格</option>
      </select>
      <p v-if="errors.ownst" class="cert-form__error" role="alert">{{ errors.ownst }}</p>
    </div>

    <div class="cert-form__field">
      <AppInput
        v-model="form.owntg"
        label="目標日"
        type="date"
        placeholder=""
        :error="errors.owntg"
      />
    </div>

    <div class="cert-form__field">
      <label class="cert-form__label">学習時間（時間）</label>
      <HoursCounter
        :model-value="form.ownhr"
        @update:model-value="form.ownhr = $event"
      />
    </div>

    <div class="cert-form__actions">
      <AppButton type="submit" variant="primary" size="sm" :loading="submitting">
        {{ mode === 'create' ? '追加' : '保存' }}
      </AppButton>
      <AppButton type="button" variant="ghost" size="sm" @click="$emit('cancel')">
        キャンセル
      </AppButton>
    </div>
  </form>
</template>

<script setup lang="ts">
import { ref, reactive, watch } from 'vue'
import axios from 'axios'
import AppInput from '@/components/atoms/AppInput.vue'
import AppButton from '@/components/atoms/AppButton.vue'
import HoursCounter from '@/components/atoms/HoursCounter.vue'
import type { OwnCert, CreateCertPayload, CertStatus, CertMaster } from '@/types/certification'

const props = withDefaults(
  defineProps<{
    cert?: OwnCert
    mode: 'create' | 'edit'
  }>(),
  {
    cert: undefined,
  }
)

const emit = defineEmits<{
  submit: [payload: CreateCertPayload]
  cancel: []
}>()

const form = reactive({
  ownnm: props.cert?.ownnm ?? '',
  ownst: (props.cert?.ownst ?? 'studying') as CertStatus,
  owntg: props.cert?.owntg ?? '',
  ownhr: props.cert?.ownhr ?? 0,
})

const errors = reactive({
  ownnm: '',
  ownst: '',
  owntg: '',
})

const suggestions = ref<CertMaster[]>([])
const showDropdown = ref(false)
const activeIndex = ref(-1)
const submitting = ref(false)

let debounceTimer: ReturnType<typeof setTimeout> | null = null

function onNameInput() {
  errors.ownnm = ''
  activeIndex.value = -1
  if (debounceTimer) clearTimeout(debounceTimer)
  if (form.ownnm.trim().length < 1) {
    suggestions.value = []
    showDropdown.value = false
    return
  }
  debounceTimer = setTimeout(async () => {
    try {
      const res = await axios.get<{ data: CertMaster[]; error: string | null }>(
        `/api/cert-master?q=${encodeURIComponent(form.ownnm)}`
      )
      if (res.data.data && res.data.data.length > 0) {
        suggestions.value = res.data.data
        showDropdown.value = true
      } else {
        suggestions.value = []
        showDropdown.value = false
      }
    } catch {
      suggestions.value = []
    }
  }, 280)
}

function onNameKeydown(e: KeyboardEvent) {
  if (!showDropdown.value || suggestions.value.length === 0) return
  if (e.key === 'ArrowDown') {
    e.preventDefault()
    activeIndex.value = (activeIndex.value + 1) % suggestions.value.length
  } else if (e.key === 'ArrowUp') {
    e.preventDefault()
    activeIndex.value =
      activeIndex.value <= 0 ? suggestions.value.length - 1 : activeIndex.value - 1
  } else if (e.key === 'Enter') {
    if (activeIndex.value >= 0) {
      e.preventDefault()
      selectSuggestion(suggestions.value[activeIndex.value])
    }
  } else if (e.key === 'Escape') {
    showDropdown.value = false
  }
}

function selectSuggestion(sug: CertMaster) {
  form.ownnm = sug.cernm
  suggestions.value = []
  showDropdown.value = false
  activeIndex.value = -1
}

function validate(): boolean {
  let valid = true
  errors.ownnm = ''
  errors.ownst = ''
  errors.owntg = ''

  if (!form.ownnm.trim()) {
    errors.ownnm = '資格名を入力してください'
    valid = false
  }
  if (!form.ownst) {
    errors.ownst = 'ステータスを選択してください'
    valid = false
  }
  return valid
}

async function handleSubmit() {
  if (!validate()) return
  submitting.value = true
  try {
    const payload: CreateCertPayload = {
      ownnm: form.ownnm.trim(),
      ownst: form.ownst,
    }
    if (form.owntg) payload.owntg = form.owntg
    if (form.ownhr > 0) payload.ownhr = form.ownhr
    emit('submit', payload)
  } finally {
    submitting.value = false
  }
}

// Reset form when cert prop changes (e.g., switching to edit mode)
watch(
  () => props.cert,
  (c) => {
    if (c) {
      form.ownnm = c.ownnm
      form.ownst = c.ownst
      form.owntg = c.owntg ?? ''
      form.ownhr = c.ownhr
    }
  }
)
</script>

<style scoped lang="scss">
.cert-form {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 16px 0 8px;

  &__field {
    position: relative;
  }

  &__label {
    display: block;
    font-size: 0.8125rem;
    font-weight: 500;
    color: #374151;
    margin-bottom: 4px;
    letter-spacing: -0.005em;
  }

  &__select {
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
    appearance: none;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%236b7280' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 12px center;
    padding-right: 32px;

    &:focus {
      border-color: #1a1a2e;
      box-shadow: 0 0 0 3px rgba(26, 26, 46, 0.1);
    }

    &--error {
      border-color: #dc2626;
    }
  }

  &__error {
    font-size: 0.78rem;
    color: #dc2626;
    margin: 4px 0 0;
  }

  &__autocomplete-wrap {
    position: relative;
  }

  &__suggestions {
    position: absolute;
    top: calc(100% + 2px);
    left: 0;
    right: 0;
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
    z-index: 100;
    max-height: 220px;
    overflow-y: auto;
    padding: 4px 0;
    margin: 0;
    list-style: none;
  }

  &__suggestion {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 8px 14px;
    cursor: pointer;
    transition: background-color 150ms ease;

    &:hover,
    &--active {
      background-color: rgba(26, 26, 46, 0.05);
    }
  }

  &__suggestion-name {
    font-size: 0.875rem;
    color: #111827;
    flex: 1;
  }

  &__suggestion-cat {
    font-size: 0.75rem;
    color: #9ca3af;
    flex-shrink: 0;
  }

  &__actions {
    display: flex;
    gap: 8px;
    align-items: center;
    padding-top: 4px;
  }
}
</style>
