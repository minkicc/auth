/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

<template>
  <div class="profile-page">
    <div v-if="loading" class="profile-card profile-state">
      <div class="spinner"></div>
      <p>{{ $t('profile.loading') }}</p>
    </div>

    <div v-else-if="error" class="profile-card profile-state profile-error">
      <h1>{{ $t('profile.loadFailed') }}</h1>
      <p>{{ error }}</p>
      <button class="secondary-btn" @click="goToLogin">{{ $t('profile.backToLogin') }}</button>
    </div>

    <div v-else-if="user" class="profile-card">
      <div class="profile-header">
        <div class="avatar-shell">
          <img v-if="user.avatar" :src="user.avatar" :alt="user.nickname || user.user_id" class="avatar-image" />
          <div v-else class="avatar-fallback">{{ initials }}</div>
        </div>
        <div class="profile-copy">
          <p class="eyebrow">MKAuth</p>
          <h1>{{ $t('profile.title') }}</h1>
          <p>{{ $t('profile.subtitle') }}</p>
        </div>
      </div>

      <div class="profile-grid">
        <div class="profile-field">
          <span class="field-label">{{ $t('profile.userId') }}</span>
          <strong>{{ user.user_id }}</strong>
        </div>
        <div class="profile-field">
          <span class="field-label">{{ $t('profile.nickname') }}</span>
          <strong>{{ user.nickname || '-' }}</strong>
        </div>
        <div class="profile-field">
          <span class="field-label">{{ $t('profile.avatar') }}</span>
          <strong>{{ user.avatar ? user.avatar : $t('profile.noAvatar') }}</strong>
        </div>
        <div class="profile-field">
          <span class="field-label">{{ $t('profile.sessionExpiresAt') }}</span>
          <strong>{{ sessionExpiresAt }}</strong>
        </div>
      </div>

      <div class="profile-actions">
        <button class="secondary-btn" @click="refreshProfile">{{ $t('common.refresh') }}</button>
        <button class="primary-btn" @click="handleLogout">{{ $t('common.logout') }}</button>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { serverApi } from '@/api/serverApi'
import { context } from '@/context'

interface ProfileUser {
  user_id: string
  nickname?: string
  avatar?: string
}

const router = useRouter()
const loading = ref(true)
const error = ref('')
const user = ref<ProfileUser | null>(null)
const sessionExpiresAt = ref('-')

const initials = computed(() => {
  const base = user.value?.nickname || user.value?.user_id || 'U'
  return base.slice(0, 1).toUpperCase()
})

const goToLogin = async () => {
  await router.push('/login')
}

const loadProfile = async () => {
  try {
    loading.value = true
    error.value = ''

    const [currentUser, session] = await Promise.all([
      serverApi.fetchCurrentUser(),
      serverApi.fetchBrowserSession(),
    ])

    context.setAuthenticated(true)
    user.value = currentUser
    sessionExpiresAt.value = session?.expires_at
      ? new Date(session.expires_at).toLocaleString()
      : '-'
  } catch (err: any) {
    if (err?.response?.status === 401) {
      context.setAuthenticated(false)
      await router.replace('/login')
      return
    }

    error.value = err?.response?.data?.error || err?.message || 'Failed to load profile'
  } finally {
    loading.value = false
  }
}

const refreshProfile = async () => {
  await loadProfile()
}

const handleLogout = async () => {
  await serverApi.logout()
  context.setAuthenticated(false)
  await router.replace('/login')
}

onMounted(async () => {
  serverApi.updateAuthData('', undefined)
  await loadProfile()
})
</script>

<style scoped>
.profile-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 32px 16px;
}

.profile-card {
  width: min(100%, 720px);
  padding: 32px;
  border-radius: 24px;
  background:
    radial-gradient(circle at top right, rgba(17, 63, 84, 0.12), transparent 36%),
    linear-gradient(180deg, #ffffff 0%, #f7fbfd 100%);
  box-shadow: 0 20px 60px rgba(17, 63, 84, 0.14);
}

.profile-state {
  text-align: center;
}

.profile-error {
  color: #b42318;
}

.profile-header {
  display: flex;
  align-items: center;
  gap: 20px;
  margin-bottom: 28px;
}

.avatar-shell {
  width: 88px;
  height: 88px;
  border-radius: 24px;
  overflow: hidden;
  background: linear-gradient(135deg, #113f54, #1d6a7a);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.avatar-image {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.avatar-fallback {
  color: #fff;
  font-size: 32px;
  font-weight: 700;
}

.profile-copy h1 {
  margin: 0 0 8px;
  font-size: 32px;
  color: #113f54;
}

.profile-copy p {
  margin: 0;
  color: #4c6570;
  line-height: 1.6;
}

.eyebrow {
  margin-bottom: 8px !important;
  font-size: 12px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: #6b8794 !important;
}

.profile-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

.profile-field {
  padding: 18px;
  border-radius: 18px;
  background: rgba(255, 255, 255, 0.85);
  border: 1px solid rgba(17, 63, 84, 0.08);
  min-width: 0;
}

.field-label {
  display: block;
  margin-bottom: 8px;
  color: #6b8794;
  font-size: 13px;
}

.profile-field strong {
  display: block;
  color: #163746;
  word-break: break-word;
}

.profile-actions {
  margin-top: 24px;
  display: flex;
  justify-content: flex-end;
  gap: 12px;
}

.primary-btn,
.secondary-btn {
  border: none;
  border-radius: 999px;
  padding: 12px 18px;
  cursor: pointer;
  font-size: 14px;
  transition: transform 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
}

.primary-btn {
  background: #113f54;
  color: #fff;
  box-shadow: 0 12px 24px rgba(17, 63, 84, 0.18);
}

.secondary-btn {
  background: #e8f1f4;
  color: #113f54;
}

.primary-btn:hover,
.secondary-btn:hover {
  transform: translateY(-1px);
}

.spinner {
  width: 40px;
  height: 40px;
  margin: 0 auto 16px;
  border: 4px solid rgba(17, 63, 84, 0.12);
  border-top-color: #113f54;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

@media (max-width: 640px) {
  .profile-card {
    padding: 24px;
  }

  .profile-header {
    flex-direction: column;
    align-items: flex-start;
  }

  .profile-grid {
    grid-template-columns: 1fr;
  }

  .profile-actions {
    flex-direction: column;
  }
}
</style>
