<template>
  <div class="cert-row">
    <div class="cert-row__main">
      <div class="cert-row__info">
        <span class="cert-row__name">{{ cert.ownnm }}</span>
        <StatusBadge :status="cert.ownst" />
        <span v-if="cert.owntg" class="cert-row__target">
          <span class="cert-row__target-label" aria-label="目標日">目標：</span>
          {{ formatDate(cert.owntg) }}
        </span>
      </div>

      <div class="cert-row__controls">
        <HoursCounter
          :model-value="cert.ownhr"
          :loading="hoursLoading"
          @change="onHoursChange"
          @update:model-value="onHoursChange"
        />

        <div class="cert-row__actions" role="group" :aria-label="`${cert.ownnm}の操作`">
          <template v-if="cert.ownst !== 'abandoned'">
            <AppButton variant="ghost" size="sm" @click="$emit('edit', cert.ownid)">
              編集
            </AppButton>
            <AppButton
              variant="secondary"
              size="sm"
              @click="$emit('abandon', cert.ownid)"
            >
              断念
            </AppButton>
          </template>
          <template v-else>
            <AppButton variant="secondary" size="sm" @click="$emit('restore', cert.ownid)">
              復活
            </AppButton>
            <AppButton
              variant="danger"
              size="sm"
              @click="showConfirm = !showConfirm"
            >
              完全削除
            </AppButton>
          </template>
        </div>
      </div>
    </div>

    <!-- Edit form (expanded) -->
    <Transition name="expand">
      <div v-if="expanded" class="cert-row__edit">
        <CertForm
          :cert="cert"
          mode="edit"
          @submit="(payload) => $emit('edit-submit', cert.ownid, payload)"
          @cancel="$emit('edit-cancel')"
        />
      </div>
    </Transition>

    <!-- Confirm delete (inline) -->
    <ConfirmDelete
      :visible="showConfirm"
      :cert-name="cert.ownnm"
      @confirm="onConfirmDelete"
      @cancel="showConfirm = false"
    />
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import StatusBadge from '@/components/atoms/StatusBadge.vue'
import HoursCounter from '@/components/atoms/HoursCounter.vue'
import AppButton from '@/components/atoms/AppButton.vue'
import CertForm from '@/components/molecules/CertForm.vue'
import ConfirmDelete from '@/components/molecules/ConfirmDelete.vue'
import type { OwnCert, CreateCertPayload } from '@/types/certification'

const props = defineProps<{
  cert: OwnCert
  expanded: boolean
}>()

const emit = defineEmits<{
  edit: [id: string]
  'edit-submit': [id: string, payload: CreateCertPayload]
  'edit-cancel': []
  abandon: [id: string]
  restore: [id: string]
  delete: [id: string]
  hoursChange: [id: string, value: number]
}>()

const showConfirm = ref(false)
const hoursLoading = ref(false)

function formatDate(iso: string): string {
  const d = new Date(iso)
  if (isNaN(d.getTime())) return iso
  return `${d.getFullYear()}/${String(d.getMonth() + 1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')}`
}

function onHoursChange(value: number) {
  emit('hoursChange', props.cert.ownid, value)
}

function onConfirmDelete() {
  showConfirm.value = false
  emit('delete', props.cert.ownid)
}
</script>

<style scoped lang="scss">
.cert-row {
  border-bottom: 1px solid rgba(17, 24, 39, 0.07);

  &:last-child {
    border-bottom: none;
  }

  &__main {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 12px 16px;
    flex-wrap: wrap;
  }

  &__info {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    min-width: 0;
    flex: 1;
  }

  &__name {
    font-size: 0.9375rem;
    font-weight: 500;
    color: #111827;
    letter-spacing: -0.01em;
    word-break: break-word;
  }

  &__target {
    font-size: 0.78rem;
    color: #9ca3af;
    white-space: nowrap;
  }

  &__target-label {
    color: #d1d5db;
  }

  &__controls {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-shrink: 0;
    flex-wrap: wrap;
    justify-content: flex-end;
  }

  &__actions {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  &__edit {
    padding: 0 16px 16px;
    border-top: 1px solid rgba(17, 24, 39, 0.06);
    background-color: rgba(26, 26, 46, 0.02);
  }
}

.expand-enter-active,
.expand-leave-active {
  transition: max-height 220ms ease, opacity 220ms ease;
  overflow: hidden;
  max-height: 500px;
}

.expand-enter-from,
.expand-leave-to {
  max-height: 0;
  opacity: 0;
}
</style>
