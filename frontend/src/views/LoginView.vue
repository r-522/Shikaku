<template>
  <div class="login-view" role="main">
    <div class="login-view__inner">
      <div class="login-view__brand" aria-label="アプリ名">
        <h1 class="login-view__app-title">資格取るぞー！</h1>
        <p class="login-view__app-subtitle">資格管理・学習進捗トラッカー</p>
      </div>

      <div class="login-view__card">
        <!-- Tab bar -->
        <div class="login-view__tabs" role="tablist" aria-label="ログイン・新規登録">
          <button
            id="tab-login"
            type="button"
            role="tab"
            :aria-selected="activeTab === 'login'"
            :class="['login-view__tab', { 'login-view__tab--active': activeTab === 'login' }]"
            aria-controls="panel-login"
            @click="switchTab('login')"
          >
            ログイン
          </button>
          <button
            id="tab-signup"
            type="button"
            role="tab"
            :aria-selected="activeTab === 'signup'"
            :class="['login-view__tab', { 'login-view__tab--active': activeTab === 'signup' }]"
            aria-controls="panel-signup"
            @click="switchTab('signup')"
          >
            新規登録
          </button>
          <div
            class="login-view__tab-indicator"
            :style="{ transform: `translateX(${activeTab === 'login' ? '0%' : '100%'})` }"
            aria-hidden="true"
          ></div>
        </div>

        <!-- Login panel -->
        <div
          id="panel-login"
          role="tabpanel"
          aria-labelledby="tab-login"
          :hidden="activeTab !== 'login'"
        >
          <form class="login-view__form" novalidate @submit.prevent="handleLogin">
            <AppInput
              v-model="loginForm.email"
              label="メールアドレス"
              type="email"
              placeholder="you@example.com"
              :error="loginErrors.email"
              autocomplete="email"
            />
            <AppInput
              v-model="loginForm.password"
              label="パスワード"
              type="password"
              placeholder="••••••••"
              :error="loginErrors.password"
              autocomplete="current-password"
            />
            <p v-if="loginErrors.general" class="login-view__form-error" role="alert">
              {{ loginErrors.general }}
            </p>
            <AppButton
              type="submit"
              variant="primary"
              size="lg"
              :loading="authStore.loading"
              class="login-view__submit-btn"
              style="width: 100%"
            >
              ログイン
            </AppButton>
          </form>
        </div>

        <!-- Signup panel -->
        <div
          id="panel-signup"
          role="tabpanel"
          aria-labelledby="tab-signup"
          :hidden="activeTab !== 'signup'"
        >
          <form class="login-view__form" novalidate @submit.prevent="handleSignup">
            <AppInput
              v-model="signupForm.username"
              label="ユーザー名"
              type="text"
              placeholder="あなたの名前"
              :error="signupErrors.username"
              autocomplete="username"
            />
            <AppInput
              v-model="signupForm.email"
              label="メールアドレス"
              type="email"
              placeholder="you@example.com"
              :error="signupErrors.email"
              autocomplete="email"
            />
            <AppInput
              v-model="signupForm.password"
              label="パスワード"
              type="password"
              placeholder="8文字以上"
              :error="signupErrors.password"
              autocomplete="new-password"
            />
            <p v-if="signupErrors.general" class="login-view__form-error" role="alert">
              {{ signupErrors.general }}
            </p>
            <AppButton
              type="submit"
              variant="primary"
              size="lg"
              :loading="authStore.loading"
              style="width: 100%"
            >
              登録する
            </AppButton>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue'
import AppInput from '@/components/atoms/AppInput.vue'
import AppButton from '@/components/atoms/AppButton.vue'
import { useAuthStore } from '@/stores/auth'
import { useToast } from '@/composables/useToast'

const authStore = useAuthStore()
const { showToast } = useToast()

type Tab = 'login' | 'signup'
const activeTab = ref<Tab>('login')

function switchTab(tab: Tab) {
  activeTab.value = tab
  // Clear errors on tab switch
  Object.keys(loginErrors).forEach((k) => (loginErrors[k as keyof typeof loginErrors] = ''))
  Object.keys(signupErrors).forEach((k) => (signupErrors[k as keyof typeof signupErrors] = ''))
}

// ─── Login ────────────────────────────────────────────────────────────────────
const loginForm = reactive({ email: '', password: '' })
const loginErrors = reactive({ email: '', password: '', general: '' })

function validateLogin(): boolean {
  loginErrors.email = ''
  loginErrors.password = ''
  loginErrors.general = ''
  let ok = true
  if (!loginForm.email.trim()) {
    loginErrors.email = 'メールアドレスを入力してください'
    ok = false
  }
  if (!loginForm.password) {
    loginErrors.password = 'パスワードを入力してください'
    ok = false
  }
  return ok
}

async function handleLogin() {
  if (!validateLogin()) return
  try {
    await authStore.login({ email: loginForm.email, password: loginForm.password })
    showToast('ログインしました', 'success')
  } catch (e: unknown) {
    loginErrors.general =
      e instanceof Error ? e.message : 'ログインに失敗しました。メールアドレスとパスワードをご確認ください。'
  }
}

// ─── Signup ───────────────────────────────────────────────────────────────────
const signupForm = reactive({ username: '', email: '', password: '' })
const signupErrors = reactive({ username: '', email: '', password: '', general: '' })

function validateSignup(): boolean {
  signupErrors.username = ''
  signupErrors.email = ''
  signupErrors.password = ''
  signupErrors.general = ''
  let ok = true
  if (!signupForm.username.trim()) {
    signupErrors.username = 'ユーザー名を入力してください'
    ok = false
  }
  if (!signupForm.email.trim()) {
    signupErrors.email = 'メールアドレスを入力してください'
    ok = false
  }
  if (signupForm.password.length < 8) {
    signupErrors.password = 'パスワードは8文字以上で入力してください'
    ok = false
  }
  return ok
}

async function handleSignup() {
  if (!validateSignup()) return
  try {
    await authStore.signup({
      email: signupForm.email,
      password: signupForm.password,
      username: signupForm.username,
    })
    showToast('登録が完了しました！', 'success')
  } catch (e: unknown) {
    signupErrors.general =
      e instanceof Error ? e.message : '登録に失敗しました。再度お試しください。'
  }
}
</script>

<style scoped lang="scss">
.login-view {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: #fafaf9;
  // Subtle grid pattern
  background-image:
    linear-gradient(rgba(26, 26, 46, 0.035) 1px, transparent 1px),
    linear-gradient(90deg, rgba(26, 26, 46, 0.035) 1px, transparent 1px);
  background-size: 32px 32px;
  padding: 24px 16px;

  &__inner {
    width: 100%;
    max-width: 420px;
    display: flex;
    flex-direction: column;
    gap: 28px;
  }

  &__brand {
    text-align: center;
  }

  &__app-title {
    font-size: 2rem;
    font-weight: 700;
    color: #1a1a2e;
    letter-spacing: 0.02em;
    margin: 0 0 6px;
  }

  &__app-subtitle {
    font-size: 0.875rem;
    color: #9ca3af;
    margin: 0;
    letter-spacing: 0.01em;
  }

  &__card {
    background-color: #ffffff;
    border: 1px solid rgba(0, 0, 0, 0.08);
    border-radius: 12px;
    overflow: hidden;
  }

  &__tabs {
    display: flex;
    position: relative;
    border-bottom: 1px solid rgba(17, 24, 39, 0.08);
  }

  &__tab {
    flex: 1;
    padding: 14px 16px;
    background: none;
    border: none;
    font-family: inherit;
    font-size: 0.9rem;
    font-weight: 500;
    color: #9ca3af;
    cursor: pointer;
    position: relative;
    z-index: 1;
    transition: color 150ms ease;
    letter-spacing: -0.01em;

    &--active {
      color: #1a1a2e;
    }

    &:focus-visible {
      outline: 2px solid #e85d04;
      outline-offset: -2px;
    }
  }

  &__tab-indicator {
    position: absolute;
    bottom: 0;
    left: 0;
    width: 50%;
    height: 2px;
    background-color: #e85d04;
    transition: transform 200ms ease;
    border-radius: 2px 2px 0 0;
  }

  &__form {
    display: flex;
    flex-direction: column;
    gap: 16px;
    padding: 24px;
  }

  &__form-error {
    font-size: 0.825rem;
    color: #dc2626;
    margin: 0;
    padding: 10px 12px;
    background-color: rgba(220, 38, 38, 0.05);
    border: 1px solid rgba(220, 38, 38, 0.2);
    border-radius: 6px;
  }
}
</style>
