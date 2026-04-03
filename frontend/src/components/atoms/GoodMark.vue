<template>
  <span
    v-if="show"
    class="good-mark"
    aria-label="合格実績あり"
    title="合格実績あり"
  >
    ✓
  </span>
</template>

<script setup lang="ts">
defineProps<{
  show: boolean
}>()
</script>

<style scoped lang="scss">
.good-mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 20px;
  height: 20px;
  border-radius: 50%;
  background-color: rgba(5, 150, 105, 0.14);
  color: #047857;
  font-size: 0.7rem;
  font-weight: 700;
  flex-shrink: 0;
  line-height: 1;
}
</style>
