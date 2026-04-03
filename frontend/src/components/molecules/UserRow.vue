<template>
  <div :class="['user-row', { 'user-row--self': isSelf }]" role="listitem">
    <div class="user-row__main">
      <div class="user-row__identity">
        <span class="user-row__name">
          {{ user.usenm }}
          <span v-if="isSelf" class="user-row__self-tag">（あなた）</span>
        </span>
        <GoodMark :show="user.passed_count > 0" />
      </div>
      <div class="user-row__stats">
        <span class="user-row__stat">
          <span class="user-row__stat-value">{{ user.cert_count }}</span>
          <span class="user-row__stat-label">件</span>
        </span>
        <span class="user-row__stat-divider" aria-hidden="true">/</span>
        <span class="user-row__stat">
          <span class="user-row__stat-value user-row__stat-value--passed">{{ user.passed_count }}</span>
          <span class="user-row__stat-label">合格</span>
        </span>
      </div>
    </div>

    <button
      v-if="!isSelf"
      type="button"
      :class="['user-row__fav-btn', { 'user-row__fav-btn--active': user.is_favorite }]"
      :aria-label="user.is_favorite ? 'お気に入りから外す' : 'お気に入りに追加'"
      :aria-pressed="user.is_favorite"
      @click="$emit('toggleFavorite', user.useid)"
    >
      <span class="user-row__fav-icon" aria-hidden="true">
        {{ user.is_favorite ? '★' : '☆' }}
      </span>
    </button>
  </div>
</template>

<script setup lang="ts">
import GoodMark from '@/components/atoms/GoodMark.vue'
import type { UserWithStats } from '@/types/user'

defineProps<{
  user: UserWithStats
  isSelf: boolean
}>()

defineEmits<{
  toggleFavorite: [useid: string]
}>()
</script>

<style scoped lang="scss">
.user-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 16px;
  transition: background-color 150ms ease;

  &:hover {
    background-color: rgba(17, 24, 39, 0.025);
  }

  &--self {
    background-color: rgba(26, 26, 46, 0.03);
  }

  &__main {
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    flex-wrap: wrap;
  }

  &__identity {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }

  &__name {
    font-size: 0.9rem;
    font-weight: 500;
    color: #1a1a2e;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    letter-spacing: -0.01em;
  }

  &__self-tag {
    font-size: 0.75rem;
    font-weight: 400;
    color: #6b7280;
  }

  &__stats {
    display: flex;
    align-items: center;
    gap: 4px;
    flex-shrink: 0;
  }

  &__stat {
    display: flex;
    align-items: baseline;
    gap: 2px;
  }

  &__stat-value {
    font-size: 0.95rem;
    font-weight: 600;
    color: #374151;

    &--passed {
      color: #047857;
    }
  }

  &__stat-label {
    font-size: 0.72rem;
    color: #9ca3af;
    letter-spacing: 0;
  }

  &__stat-divider {
    color: #d1d5db;
    font-size: 0.75rem;
    margin: 0 2px;
  }

  &__fav-btn {
    flex-shrink: 0;
    background: none;
    border: none;
    cursor: pointer;
    width: 30px;
    height: 30px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    transition: background-color 150ms ease, transform 150ms ease;

    &:hover {
      background-color: rgba(217, 119, 6, 0.1);
      transform: scale(1.1);
    }

    &:active {
      transform: scale(0.95);
    }

    &:focus-visible {
      outline: 2px solid #e85d04;
      outline-offset: 2px;
    }

    &--active .user-row__fav-icon {
      color: #d97706;
    }
  }

  &__fav-icon {
    font-size: 1.05rem;
    color: #d1d5db;
    transition: color 150ms ease, transform 150ms ease;
    line-height: 1;
  }
}
</style>
