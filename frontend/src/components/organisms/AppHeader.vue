<template>
  <header class="app-header" role="banner">
    <div class="app-header__inner">
      <div class="app-header__brand">
        <span class="app-header__title" aria-label="資格取るぞーアプリ">
          資格取るぞー！
        </span>
      </div>
      <div class="app-header__user" role="navigation" aria-label="ユーザーメニュー">
        <span class="app-header__username" aria-label="ログイン中のユーザー">
          {{ user.usenm }}
        </span>
        <AppButton
          variant="ghost"
          size="sm"
          class="app-header__logout-btn"
          aria-label="ログアウト"
          @click="$emit('logout')"
        >
          ログアウト
        </AppButton>
      </div>
    </div>
  </header>
</template>

<script setup lang="ts">
import AppButton from '@/components/atoms/AppButton.vue'
import type { User } from '@/types/auth'

defineProps<{
  user: User
}>()

defineEmits<{
  logout: []
}>()
</script>

<style scoped lang="scss">
.app-header {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  height: 56px;
  background-color: #1a1a2e;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  z-index: 1000;

  &__inner {
    max-width: 1280px;
    margin: 0 auto;
    height: 100%;
    padding: 0 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }

  &__brand {
    display: flex;
    align-items: center;
  }

  &__title {
    font-size: 1.05rem;
    font-weight: 700;
    color: #fafaf9;
    letter-spacing: 0.04em;
    white-space: nowrap;
  }

  &__user {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  &__username {
    font-size: 0.85rem;
    color: rgba(250, 250, 249, 0.75);
    font-weight: 400;
    letter-spacing: -0.005em;
    max-width: 160px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  &__logout-btn {
    // Override ghost variant colors for dark header
    color: rgba(250, 250, 249, 0.8) !important;

    &:hover {
      background-color: rgba(255, 255, 255, 0.08) !important;
      border-color: rgba(255, 255, 255, 0.15) !important;
      color: #fafaf9 !important;
    }
  }
}
</style>
