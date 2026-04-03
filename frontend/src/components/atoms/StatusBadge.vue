<template>
  <span :class="['status-badge', `status-badge--${status}`]" :aria-label="label">
    {{ label }}
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { CertStatus } from '@/types/certification'

const props = defineProps<{
  status: CertStatus
}>()

const LABELS: Record<CertStatus, string> = {
  studying: '勉強中',
  passed: '合格',
  failed: '不合格',
  abandoned: '断念',
}

const label = computed(() => LABELS[props.status])
</script>

<style scoped lang="scss">
// Styles defined globally in main.scss under .status-badge
// Scoped additions for component isolation
.status-badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 9px;
  border-radius: 99px;
  font-size: 0.72rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  line-height: 1.6;
  white-space: nowrap;

  &--studying {
    background-color: rgba(8, 145, 178, 0.12);
    color: #0e7490;
  }

  &--passed {
    background-color: rgba(5, 150, 105, 0.12);
    color: #047857;
  }

  &--failed {
    background-color: rgba(220, 38, 38, 0.1);
    color: #b91c1c;
  }

  &--abandoned {
    background-color: rgba(107, 114, 128, 0.12);
    color: #6b7280;
  }
}
</style>
