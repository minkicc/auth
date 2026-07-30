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
        <div class="profile-header-main">
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
        <div v-if="canOpenAdmin" class="profile-header-actions">
          <button class="secondary-btn admin-entry-btn" @click="openAdminPath('')">
            {{ $t('profile.adminPage') }}
          </button>
        </div>
      </div>

      <div class="profile-grid">
        <div class="profile-field">
          <span class="field-label">{{ $t('profile.userId') }}</span>
          <strong>{{ user.user_id }}</strong>
        </div>
        <div v-if="user.username" class="profile-field">
          <span class="field-label">{{ $t('profile.username') }}</span>
          <strong>{{ user.username }}</strong>
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

      <div v-if="identitySelectionOptions.length > 0 || organizationAuthorization || organizationAuthorizationError" class="profile-section">
        <div class="section-header">
          <h2>{{ $t('profile.organizationAuthorization') }}</h2>
          <button v-if="identitySelectionOptions.length > 1" class="secondary-btn compact-btn" @click="refreshIdentityContext">
            {{ $t('common.refresh') }}
          </button>
        </div>

        <p v-if="identitySelectionOptions.length > 1" class="section-copy">
          {{ $t('profile.organizationAuthorizationHint') }}
        </p>

        <div v-if="identitySelectionOptions.length > 0" class="selection-chips">
          <button
            v-for="option in identitySelectionOptions"
            :key="option.key"
            type="button"
            class="selection-chip"
            :class="{ active: option.current }"
            :disabled="!!switchingScopeKey"
            @click="selectActiveScope(option)"
          >
            {{ option.label }}
          </button>
        </div>

        <p v-if="organizationAuthorizationError" class="section-error">{{ organizationAuthorizationError }}</p>
        <p v-if="activePlatformSelected && !organizationAuthorizationError" class="section-copy">
          {{ $t('profile.platformAuthorizationHint') }}
        </p>

        <div v-if="organizationAuthorization" class="authorization-grid">
          <div class="profile-field">
            <span class="field-label">{{ $t('profile.organizationId') }}</span>
            <strong>{{ organizationAuthorization.organization_id }}</strong>
          </div>
          <div class="profile-field">
            <span class="field-label">{{ $t('profile.organizationSlug') }}</span>
            <strong>{{ organizationAuthorization.organization_slug || '-' }}</strong>
          </div>
          <div class="profile-field full-span">
            <span class="field-label">{{ $t('profile.organizationRoles') }}</span>
            <div class="tag-list">
              <span v-for="role in organizationAuthorization.roles || []" :key="role" class="tag">{{ role }}</span>
              <strong v-if="!organizationAuthorization.roles?.length">-</strong>
            </div>
          </div>
          <div class="profile-field full-span">
            <span class="field-label">{{ $t('profile.organizationGroups') }}</span>
            <div class="tag-list">
              <span v-for="group in organizationAuthorization.groups || []" :key="group" class="tag tag-muted">{{ group }}</span>
              <strong v-if="!organizationAuthorization.groups?.length">-</strong>
            </div>
          </div>
          <div class="profile-field full-span">
            <span class="field-label">{{ $t('profile.organizationPermissions') }}</span>
            <div class="tag-list">
              <span v-for="permission in organizationAuthorization.permissions || []" :key="permission" class="tag tag-plain">{{ permission }}</span>
              <strong v-if="!organizationAuthorization.permissions?.length">-</strong>
            </div>
          </div>
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
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { getApiErrorMessage, serverApi, type CurrentUserActiveScope, type CurrentUserOrganization, type CurrentUserOrganizationsResponse } from '@/api/serverApi'
import { context } from '@/context'

interface ProfileUser {
  user_id: string
  username?: string
  nickname?: string
  avatar?: string
}

interface ProfileOrganizationAuthorization {
  organization_id: string
  organization_slug?: string
  roles?: string[]
  groups?: string[]
  permissions?: string[]
}

interface ProfileAdminAccess {
  enabled: boolean
  is_admin: boolean
  entry_url?: string
  sources?: string[]
}

interface ProfileIdentityOption {
  key: string
  type: 'platform' | 'organization'
  label: string
  current: boolean
  organization?: CurrentUserOrganization
}

const router = useRouter()
const { t } = useI18n()
const loading = ref(true)
const error = ref('')
const user = ref<ProfileUser | null>(null)
const sessionExpiresAt = ref('-')
const organizationAuthorization = ref<ProfileOrganizationAuthorization | null>(null)
const organizationAuthorizationError = ref('')
const organizationSelectionOptions = ref<CurrentUserOrganization[]>([])
const platformAvailable = ref(false)
const selectedOrganizationHint = ref('')
const activeScopeKey = ref('')
const switchingScopeKey = ref('')
const adminAccess = ref<ProfileAdminAccess | null>(null)
const canOpenAdmin = computed(() => Boolean(adminAccess.value?.enabled && adminAccess.value?.is_admin && adminAccess.value?.entry_url))
const platformSelectionKey = '__platform__'

const identitySelectionOptions = computed<ProfileIdentityOption[]>(() => {
  const options: ProfileIdentityOption[] = []
  if (platformAvailable.value) {
    options.push({
      key: platformSelectionKey,
      type: 'platform',
      label: t('profile.platformIdentity'),
      current: activeScopeKey.value === platformSelectionKey
    })
  }
  for (const organization of organizationSelectionOptions.value) {
    const key = organizationScopeKey(organization)
    options.push({
      key,
      type: 'organization',
      label: organizationLabel(organization),
      current: activeScopeKey.value === key,
      organization
    })
  }
  return options
})
const activePlatformSelected = computed(() => activeScopeKey.value === platformSelectionKey)

const initials = computed(() => {
  const base = user.value?.nickname || user.value?.user_id || 'U'
  return base.slice(0, 1).toUpperCase()
})

const organizationLabel = (organization: CurrentUserOrganization) => {
  return organization.display_name || organization.name || organization.slug || organization.organization_id
}

const organizationHint = (organization: CurrentUserOrganization) => {
  return organization.slug || organization.organization_id || ''
}

const organizationScopeKey = (organization: CurrentUserOrganization) => {
  return `org:${organization.organization_id}`
}

const activeScopeOrganizationID = (scope: CurrentUserActiveScope | null) => {
  return scope?.organization_id || scope?.scope_id || scope?.active_scope?.organization_id || ''
}

const activeScopeOrganizationSlug = (scope: CurrentUserActiveScope | null) => {
  return scope?.organization_slug || scope?.active_scope?.organization_slug || ''
}

const applyIdentityContext = (organizationsResponse: CurrentUserOrganizationsResponse, activeScope: CurrentUserActiveScope | null) => {
  organizationSelectionOptions.value = organizationsResponse.organizations || []
  platformAvailable.value = !!organizationsResponse.platform_available

  const scopeType = (activeScope?.scope_type || activeScope?.active_scope?.scope_type || '').trim().toLowerCase()
  const activeOrgID = activeScopeOrganizationID(activeScope)
  const activeOrgSlug = activeScopeOrganizationSlug(activeScope)
  const activeOrganization = organizationSelectionOptions.value.find((organization) => {
    if (activeOrgID && organization.organization_id === activeOrgID) return true
    return !!activeOrgSlug && organization.slug === activeOrgSlug
  }) || organizationSelectionOptions.value.find((organization) => organization.current)

  if (scopeType === 'enterprise' && activeOrganization) {
    activeScopeKey.value = organizationScopeKey(activeOrganization)
    selectedOrganizationHint.value = organizationHint(activeOrganization)
    return
  }
  if (scopeType === 'platform') {
    activeScopeKey.value = platformSelectionKey
    selectedOrganizationHint.value = ''
    return
  }
  if (activeOrganization) {
    activeScopeKey.value = organizationScopeKey(activeOrganization)
    selectedOrganizationHint.value = organizationHint(activeOrganization)
    return
  }
  if (platformAvailable.value) {
    activeScopeKey.value = platformSelectionKey
    selectedOrganizationHint.value = ''
    return
  }
  activeScopeKey.value = ''
  selectedOrganizationHint.value = ''
}

const loadSelectedScopeAuthorization = async () => {
  if (activeScopeKey.value === platformSelectionKey) {
    organizationAuthorization.value = null
    organizationAuthorizationError.value = ''
    return
  }
  if (selectedOrganizationHint.value) {
    await loadOrganizationAuthorization(selectedOrganizationHint.value)
  }
}

const goToLogin = async () => {
  await router.push('/login')
}

const loadOrganizationAuthorization = async (orgHint?: string) => {
  try {
    organizationAuthorizationError.value = ''
    const response = await serverApi.fetchCurrentOrganizationAuthorization(orgHint)
    organizationAuthorization.value = response.authorization
    if (response.authorization) {
      selectedOrganizationHint.value = response.authorization.organization_slug || response.authorization.organization_id
    }
  } catch (err: any) {
    organizationAuthorization.value = null
    const apiError = err?.response?.data?.error
    if (apiError === 'organization_selection_required') {
      const response = await serverApi.fetchCurrentUserOrganizations()
      applyIdentityContext(response, await serverApi.fetchCurrentUserActiveScope().catch(() => null))
      organizationAuthorizationError.value = ''
      return
    }
    if (apiError === 'organization_not_found') {
      organizationSelectionOptions.value = []
      organizationAuthorizationError.value = ''
      return
    }
    organizationAuthorizationError.value = getApiErrorMessage(err, 'Failed to load organization authorization')
  }
}

const refreshIdentityContext = async () => {
  const [organizations, activeScope] = await Promise.all([
    serverApi.fetchCurrentUserOrganizations(),
    serverApi.fetchCurrentUserActiveScope().catch(() => null)
  ])
  applyIdentityContext(organizations, activeScope)
  await loadSelectedScopeAuthorization()
}

const selectActiveScope = async (option: ProfileIdentityOption) => {
  if (option.current || switchingScopeKey.value) return
  switchingScopeKey.value = option.key
  organizationAuthorizationError.value = ''
  try {
    if (option.type === 'platform') {
      await serverApi.setCurrentUserActiveScope({ scope_type: 'platform' })
    } else if (option.organization?.organization_id) {
      await serverApi.setCurrentUserActiveScope({
        scope_type: 'enterprise',
        organization_id: option.organization.organization_id
      })
    }
    await refreshIdentityContext()
  } catch (err: any) {
    organizationAuthorizationError.value = getApiErrorMessage(err, t('profile.activeScopeUpdateFailed'))
  } finally {
    switchingScopeKey.value = ''
  }
}

const loadProfile = async () => {
  try {
    loading.value = true
    error.value = ''

    const [currentUser, session, currentAdminAccess, organizations, activeScope] = await Promise.all([
      serverApi.fetchCurrentUser(),
      serverApi.fetchBrowserSession(),
      serverApi.fetchCurrentUserAdminAccess().catch(() => ({ enabled: false, is_admin: false })),
      serverApi.fetchCurrentUserOrganizations(),
      serverApi.fetchCurrentUserActiveScope().catch(() => null),
    ])

    context.setAuthenticated(true)
    user.value = currentUser
    adminAccess.value = currentAdminAccess
    sessionExpiresAt.value = session?.expires_at
      ? new Date(session.expires_at).toLocaleString()
      : '-'
    applyIdentityContext(organizations, activeScope)
    await loadSelectedScopeAuthorization()
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

const buildAdminURL = (path: string) => {
  const baseURL = (adminAccess.value?.entry_url || '').replace(/\/+$/, '')
  if (!baseURL) return ''
  const normalizedPath = path ? `/${path.replace(/^\/+/, '')}` : ''
  return `${baseURL}${normalizedPath}`
}

const openAdminPath = (path: string) => {
  const targetURL = buildAdminURL(path)
  if (!targetURL) return
  window.location.href = targetURL
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
  justify-content: space-between;
  gap: 20px;
  margin-bottom: 28px;
}

.profile-header-main {
  display: flex;
  align-items: center;
  gap: 20px;
  min-width: 0;
}

.profile-header-actions {
  display: flex;
  align-items: flex-start;
  justify-content: flex-end;
  flex-shrink: 0;
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

.profile-section {
  margin-top: 28px;
  padding-top: 24px;
  border-top: 1px solid rgba(17, 63, 84, 0.08);
}

.section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 10px;
}

.section-header h2 {
  margin: 0;
  font-size: 20px;
  color: #113f54;
}

.section-copy {
  margin: 0 0 12px;
  color: #4c6570;
  line-height: 1.6;
}

.section-error {
  margin: 0 0 12px;
  color: #b42318;
}

.authorization-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

.full-span {
  grid-column: 1 / -1;
}

.selection-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 14px;
}

.selection-chip {
  border: 1px solid rgba(17, 63, 84, 0.14);
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.92);
  color: #113f54;
  padding: 8px 14px;
  cursor: pointer;
  transition: background 0.2s ease, color 0.2s ease, transform 0.2s ease;
}

.selection-chip:hover {
  transform: translateY(-1px);
}

.selection-chip:disabled {
  cursor: wait;
  opacity: 0.72;
  transform: none;
}

.selection-chip.active {
  background: #113f54;
  color: #fff;
}

.tag-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.tag {
  display: inline-flex;
  align-items: center;
  padding: 6px 10px;
  border-radius: 999px;
  background: rgba(17, 63, 84, 0.1);
  color: #113f54;
  font-size: 13px;
}

.tag-muted {
  background: rgba(29, 106, 122, 0.12);
  color: #1d6a7a;
}

.tag-plain {
  background: rgba(76, 101, 112, 0.12);
  color: #4c6570;
}

.profile-actions {
  margin-top: 24px;
  display: flex;
  justify-content: flex-end;
  gap: 12px;
}

.compact-btn {
  padding: 10px 14px;
}

.admin-entry-btn {
  min-width: 132px;
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

  .profile-header-main {
    width: 100%;
    flex-direction: column;
    align-items: flex-start;
  }

  .profile-header-actions {
    width: 100%;
    justify-content: flex-start;
  }

  .profile-grid {
    grid-template-columns: 1fr;
  }

  .authorization-grid {
    grid-template-columns: 1fr;
  }

  .profile-actions {
    flex-direction: column;
  }
}
</style>
