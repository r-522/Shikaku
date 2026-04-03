<template>
  <section class="cert-list" aria-label="資格一覧">
    <div class="cert-list__header">
      <h2 class="cert-list__title">わたしの資格</h2>
      <AppButton
        variant="primary"
        size="sm"
        aria-label="資格を追加"
        :aria-expanded="showCreateForm"
        @click="toggleCreateForm"
      >
        {{ showCreateForm ? '× 閉じる' : '+ 追加' }}
      </AppButton>
    </div>

    <!-- Create form -->
    <Transition name="expand">
      <div v-if="showCreateForm" class="cert-list__create-form">
        <CertForm mode="create" @submit="onCreateSubmit" @cancel="showCreateForm = false" />
      </div>
    </Transition>

    <!-- Loading state -->
    <div v-if="loading && certs.length === 0" class="cert-list__loading" aria-busy="true">
      <div v-for="i in 3" :key="i" class="cert-list__skeleton"></div>
    </div>

    <!-- Empty state -->
    <div v-else-if="!loading && certs.length === 0" class="cert-list__empty" role="status">
      <p class="cert-list__empty-text">まだ資格がありません。「+ 追加」から始めましょう！</p>
    </div>

    <!-- Active certs section -->
    <template v-else>
      <div v-if="activeCerts.length > 0" class="cert-list__section">
        <div class="cert-list__section-header">
          <span class="cert-list__section-label">進行中・完了</span>
          <span class="cert-list__section-count">{{ activeCerts.length }}件</span>
        </div>
        <div class="cert-list__items" role="list">
          <CertRow
            v-for="cert in activeCerts"
            :key="cert.ownid"
            :cert="cert"
            :expanded="expandedId === cert.ownid"
            role="listitem"
            @edit="onEditClick"
            @edit-submit="onEditSubmit"
            @edit-cancel="expandedId = null"
            @abandon="onAbandon"
            @restore="onRestore"
            @delete="onDelete"
            @hours-change="onHoursChange"
          />
        </div>
      </div>

      <!-- Abandoned section -->
      <div v-if="abandonedCerts.length > 0" class="cert-list__section cert-list__section--abandoned">
        <div class="cert-list__section-header">
          <span class="cert-list__section-label">断念したもの</span>
          <span class="cert-list__section-count">{{ abandonedCerts.length }}件</span>
        </div>
        <div class="cert-list__items" role="list">
          <CertRow
            v-for="cert in abandonedCerts"
            :key="cert.ownid"
            :cert="cert"
            :expanded="expandedId === cert.ownid"
            role="listitem"
            @edit="onEditClick"
            @edit-submit="onEditSubmit"
            @edit-cancel="expandedId = null"
            @abandon="onAbandon"
            @restore="onRestore"
            @delete="onDelete"
            @hours-change="onHoursChange"
          />
        </div>
      </div>
    </template>
  </section>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import AppButton from '@/components/atoms/AppButton.vue'
import CertRow from '@/components/molecules/CertRow.vue'
import CertForm from '@/components/molecules/CertForm.vue'
import { useCertsStore } from '@/stores/certs'
import { useToast } from '@/composables/useToast'
import type { CreateCertPayload } from '@/types/certification'

const certsStore = useCertsStore()
const { showToast } = useToast()

const certs = computed(() => certsStore.certs)
const loading = computed(() => certsStore.loading)

const activeCerts = computed(() =>
  certs.value.filter((c) => c.ownst !== 'abandoned')
)
const abandonedCerts = computed(() =>
  certs.value.filter((c) => c.ownst === 'abandoned')
)

const showCreateForm = ref(false)
const expandedId = ref<string | null>(null)

function toggleCreateForm() {
  showCreateForm.value = !showCreateForm.value
  if (showCreateForm.value) expandedId.value = null
}

async function onCreateSubmit(payload: CreateCertPayload) {
  try {
    await certsStore.createCert(payload)
    showCreateForm.value = false
    showToast('資格を追加しました', 'success')
  } catch (e: unknown) {
    showToast(e instanceof Error ? e.message : '追加に失敗しました', 'error')
  }
}

function onEditClick(id: string) {
  expandedId.value = expandedId.value === id ? null : id
  showCreateForm.value = false
}

async function onEditSubmit(id: string, payload: CreateCertPayload) {
  try {
    await certsStore.updateCert(id, payload)
    expandedId.value = null
    showToast('更新しました', 'success')
  } catch (e: unknown) {
    showToast(e instanceof Error ? e.message : '更新に失敗しました', 'error')
  }
}

async function onAbandon(id: string) {
  try {
    await certsStore.abandonCert(id)
    showToast('断念しました', 'success')
  } catch (e: unknown) {
    showToast(e instanceof Error ? e.message : '操作に失敗しました', 'error')
  }
}

async function onRestore(id: string) {
  try {
    await certsStore.restoreCert(id)
    showToast('復活しました！', 'success')
  } catch (e: unknown) {
    showToast(e instanceof Error ? e.message : '操作に失敗しました', 'error')
  }
}

async function onDelete(id: string) {
  try {
    await certsStore.deleteCert(id)
    showToast('削除しました', 'success')
  } catch (e: unknown) {
    showToast(e instanceof Error ? e.message : '削除に失敗しました', 'error')
  }
}

async function onHoursChange(id: string, value: number) {
  try {
    await certsStore.updateHours(id, { value })
  } catch {
    showToast('学習時間の更新に失敗しました', 'error')
  }
}

onMounted(async () => {
  if (certs.value.length === 0) {
    try {
      await certsStore.fetchCerts()
    } catch {
      showToast('資格の取得に失敗しました', 'error')
    }
  }
})
</script>

<style scoped lang="scss">
.cert-list {
  &__header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 0;
    padding: 20px 20px 16px;
  }

  &__title {
    font-size: 1.05rem;
    font-weight: 600;
    color: #1a1a2e;
    margin: 0;
    letter-spacing: -0.02em;
  }

  &__create-form {
    padding: 0 20px 16px;
    border-bottom: 1px solid rgba(17, 24, 39, 0.08);
    background-color: rgba(26, 26, 46, 0.02);
  }

  &__loading {
    padding: 12px 20px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  &__skeleton {
    height: 52px;
    border-radius: 6px;
    background: linear-gradient(90deg, #f3f4f6 25%, #e9ebee 50%, #f3f4f6 75%);
    background-size: 200% 100%;
    animation: shimmer 1.4s ease infinite;
  }

  &__empty {
    padding: 40px 20px;
    text-align: center;
  }

  &__empty-text {
    font-size: 0.9rem;
    color: #9ca3af;
    margin: 0;
  }

  &__section {
    &--abandoned {
      background-color: rgba(107, 114, 128, 0.04);
      border-top: 2px solid rgba(107, 114, 128, 0.1);
    }
  }

  &__section-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 20px 6px;
    gap: 8px;
  }

  &__section-label {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #9ca3af;
  }

  &__section-count {
    font-size: 0.75rem;
    color: #d1d5db;
  }

  &__items {
    // List items separated by borders (in CertRow)
  }
}

.expand-enter-active,
.expand-leave-active {
  transition: max-height 220ms ease, opacity 220ms ease;
  overflow: hidden;
  max-height: 400px;
}

.expand-enter-from,
.expand-leave-to {
  max-height: 0;
  opacity: 0;
}

@keyframes shimmer {
  0%   { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}
</style>
