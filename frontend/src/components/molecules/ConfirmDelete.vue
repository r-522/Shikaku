<template>
  <Transition name="confirm-expand">
    <div
      v-if="visible"
      class="confirm-delete"
      role="alertdialog"
      aria-modal="false"
      :aria-label="`「${certName}」を削除しますか？`"
    >
      <p class="confirm-delete__text">
        <span class="confirm-delete__icon" aria-hidden="true">⚠</span>
        「<strong>{{ certName }}</strong>」を完全に削除します。この操作は取り消せません。
      </p>
      <div class="confirm-delete__actions">
        <AppButton variant="danger" size="sm" @click="$emit('confirm')">
          完全削除
        </AppButton>
        <AppButton variant="ghost" size="sm" @click="$emit('cancel')">
          キャンセル
        </AppButton>
      </div>
    </div>
  </Transition>
</template>

<script setup lang="ts">
import AppButton from '@/components/atoms/AppButton.vue'

defineProps<{
  visible: boolean
  certName: string
}>()

defineEmits<{
  confirm: []
  cancel: []
}>()
</script>

<style scoped lang="scss">
.confirm-delete {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 12px 16px;
  background-color: rgba(220, 38, 38, 0.04);
  border-top: 1px solid rgba(220, 38, 38, 0.15);

  &__text {
    margin: 0;
    font-size: 0.875rem;
    color: #7f1d1d;
    line-height: 1.5;
    display: flex;
    align-items: flex-start;
    gap: 8px;
  }

  &__icon {
    flex-shrink: 0;
    color: #dc2626;
    font-size: 0.9rem;
    margin-top: 1px;
  }

  &__actions {
    display: flex;
    gap: 8px;
    align-items: center;
  }
}

.confirm-expand-enter-active,
.confirm-expand-leave-active {
  transition: max-height 200ms ease, opacity 200ms ease;
  overflow: hidden;
  max-height: 120px;
}

.confirm-expand-enter-from,
.confirm-expand-leave-to {
  max-height: 0;
  opacity: 0;
}
</style>
