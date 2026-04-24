/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

<template>
  <div class="organization-select-page">
    <div v-if="loading" class="organization-select-shell organization-select-state">
      <div class="spinner"></div>
      <p>{{ $t('organizationSelect.loading') }}</p>
    </div>

    <div v-else-if="error" class="organization-select-shell organization-select-state organization-select-error">
      <p class="eyebrow">{{ $t('organizationSelect.eyebrow') }}</p>
      <h1>{{ $t('organizationSelect.errorTitle') }}</h1>
      <p>{{ error }}</p>
      <div class="organization-select-actions">
        <button class="secondary-btn" type="button" @click="refreshOrganizations">
          {{ $t('common.refresh') }}
        </button>
        <button class="ghost-btn" type="button" @click="goToLogin">
          {{ $t('auth.backToLogin') }}
        </button>
      </div>
    </div>

    <div v-else class="organization-select-shell">
      <div class="hero-panel">
        <div class="hero-copy">
          <p class="eyebrow">{{ $t('organizationSelect.eyebrow') }}</p>
          <h1>{{ $t('organizationSelect.title') }}</h1>
          <p class="hero-description">{{ $t('organizationSelect.subtitle') }}</p>
        </div>
        <div class="hero-meta">
          <div class="meta-chip">
            <span class="meta-label">{{ $t('organizationSelect.clientId') }}</span>
            <strong>{{ serverApi.clientId || '-' }}</strong>
          </div>
          <div class="meta-chip">
            <span class="meta-label">{{ $t('organizationSelect.organizationCount') }}</span>
            <strong>{{ organizations.length }}</strong>
          </div>
        </div>
      </div>

      <div v-if="organizations.length === 0" class="empty-state">
        <h2>{{ $t('organizationSelect.emptyTitle') }}</h2>
        <p>{{ $t('organizationSelect.emptySubtitle') }}</p>
        <div class="organization-select-actions">
          <button class="secondary-btn" type="button" @click="refreshOrganizations">
            {{ $t('common.refresh') }}
          </button>
          <button class="ghost-btn" type="button" @click="goToLogin">
            {{ $t('auth.backToLogin') }}
          </button>
        </div>
      </div>

      <div v-else class="organization-grid">
        <button
          v-for="organization in organizations"
          :key="organization.organization_id"
          class="organization-card"
          type="button"
          :disabled="!!selectingOrganizationId"
          @click="selectOrganization(organization)"
        >
          <div class="organization-card-top">
            <div class="organization-avatar">
              {{ organizationInitial(organization) }}
            </div>
            <div class="organization-copy">
              <div class="organization-name-row">
                <h2>{{ organizationLabel(organization) }}</h2>
                <span v-if="organization.current" class="status-pill current-pill">
                  {{ $t('organizationSelect.current') }}
                </span>
              </div>
              <p class="organization-slug">
                {{ organization.slug || organization.organization_id }}
              </p>
            </div>
          </div>

          <div class="organization-section">
            <span class="section-label">{{ $t('organizationSelect.status') }}</span>
            <span class="status-pill">{{ organization.status || 'active' }}</span>
          </div>

          <div v-if="organization.roles?.length" class="organization-section">
            <span class="section-label">{{ $t('organizationSelect.roles') }}</span>
            <div class="tag-list">
              <span v-for="role in organization.roles" :key="role" class="tag">
                {{ role }}
              </span>
            </div>
          </div>

          <div v-if="organization.groups?.length" class="organization-section">
            <span class="section-label">{{ $t('organizationSelect.groups') }}</span>
            <div class="tag-list">
              <span v-for="group in organization.groups" :key="group" class="tag tag-muted">
                {{ group }}
              </span>
            </div>
          </div>

          <div class="organization-card-footer">
            <span v-if="selectingOrganizationId === organization.organization_id">
              {{ $t('organizationSelect.redirecting') }}
            </span>
            <span v-else>{{ $t('organizationSelect.continue') }}</span>
          </div>
        </button>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { context } from '@/context'
import { getApiErrorMessage, serverApi } from '@/api/serverApi'
import type { CurrentUserOrganization } from '@/api/serverApi'

const router = useRouter()
const { t } = useI18n()

const loading = ref(true)
const error = ref('')
const organizations = ref<CurrentUserOrganization[]>([])
const selectingOrganizationId = ref('')

const hasBusinessConnection = computed(() => serverApi.hasBusinessConnection())

const authQuery = computed(() => ({
  ...(serverApi.clientId ? { client_id: serverApi.clientId } : {}),
  ...(serverApi.redirectUri ? { redirect_uri: serverApi.redirectUri } : {}),
  ...(serverApi.loginHint ? { login_hint: serverApi.loginHint } : {}),
  ...(serverApi.domainHint ? { domain_hint: serverApi.domainHint } : {}),
  ...(serverApi.orgHint ? { org_hint: serverApi.orgHint } : {}),
}))

const organizationLabel = (organization: CurrentUserOrganization) => {
  return organization.display_name || organization.name || organization.slug || organization.organization_id
}

const organizationInitial = (organization: CurrentUserOrganization) => {
  return organizationLabel(organization).slice(0, 1).toUpperCase()
}

const goToLogin = async () => {
  await router.replace({
    path: '/login',
    query: authQuery.value,
  })
}

const selectOrganization = (organization: CurrentUserOrganization) => {
  const nextOrgHint = organization.slug || organization.organization_id
  if (!nextOrgHint) {
    error.value = t('errors.organizationSelectionFailed')
    return
  }

  selectingOrganizationId.value = organization.organization_id
  error.value = ''
  serverApi.continueOIDCWithOrganization(nextOrgHint)
}

const loadOrganizations = async () => {
  if (!hasBusinessConnection.value) {
    await router.replace('/profile')
    return
  }

  try {
    loading.value = true
    error.value = ''

    const session = await serverApi.fetchBrowserSession()
    if (!session?.authenticated) {
      context.setAuthenticated(false)
      await goToLogin()
      return
    }

    context.setAuthenticated(true)

    const response = await serverApi.fetchCurrentUserOrganizations()
    organizations.value = response.organizations || []

    if (organizations.value.length === 1) {
      selectOrganization(organizations.value[0])
      return
    }
  } catch (err: any) {
    if (err?.response?.status === 401) {
      context.setAuthenticated(false)
      await goToLogin()
      return
    }

    error.value = getApiErrorMessage(err, t('errors.organizationSelectionLoadFailed'))
  } finally {
    loading.value = false
  }
}

const refreshOrganizations = async () => {
  selectingOrganizationId.value = ''
  await loadOrganizations()
}

onMounted(async () => {
  await loadOrganizations()
})
</script>

<style scoped>
.organization-select-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 32px 16px;
}

.organization-select-shell {
  width: min(100%, 1040px);
  border-radius: 28px;
  padding: 32px;
  background:
    radial-gradient(circle at top left, rgba(27, 94, 118, 0.16), transparent 34%),
    radial-gradient(circle at bottom right, rgba(238, 186, 94, 0.18), transparent 28%),
    linear-gradient(180deg, #fdfefe 0%, #f4fafb 100%);
  box-shadow: 0 28px 80px rgba(17, 63, 84, 0.14);
}

.organization-select-state {
  max-width: 560px;
  text-align: center;
}

.organization-select-error {
  color: #b42318;
}

.hero-panel {
  display: flex;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 28px;
  align-items: flex-start;
}

.hero-copy {
  max-width: 620px;
}

.eyebrow {
  margin: 0 0 10px;
  color: #6a8590;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.14em;
}

.hero-copy h1 {
  margin: 0 0 12px;
  color: #103e4f;
  font-size: 36px;
  line-height: 1.1;
}

.hero-description {
  margin: 0;
  color: #4e6873;
  line-height: 1.7;
  font-size: 16px;
}

.hero-meta {
  display: grid;
  gap: 12px;
  min-width: 220px;
}

.meta-chip {
  padding: 16px 18px;
  border-radius: 18px;
  background: rgba(255, 255, 255, 0.84);
  border: 1px solid rgba(16, 62, 79, 0.08);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.9);
}

.meta-label,
.section-label {
  display: block;
  margin-bottom: 8px;
  color: #6a8590;
  font-size: 12px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}

.meta-chip strong {
  color: #103e4f;
  word-break: break-word;
}

.organization-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 18px;
}

.organization-card {
  text-align: left;
  padding: 22px;
  border-radius: 22px;
  border: 1px solid rgba(16, 62, 79, 0.08);
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.96) 0%, rgba(246, 251, 252, 0.94) 100%);
  box-shadow: 0 16px 36px rgba(17, 63, 84, 0.08);
  cursor: pointer;
  transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease;
}

.organization-card:hover:not(:disabled) {
  transform: translateY(-2px);
  border-color: rgba(16, 62, 79, 0.2);
  box-shadow: 0 22px 40px rgba(17, 63, 84, 0.12);
}

.organization-card:disabled {
  cursor: wait;
  opacity: 0.82;
}

.organization-card-top {
  display: flex;
  gap: 14px;
  align-items: flex-start;
  margin-bottom: 16px;
}

.organization-avatar {
  width: 54px;
  height: 54px;
  border-radius: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  color: #fff;
  font-weight: 700;
  font-size: 22px;
  background: linear-gradient(135deg, #103e4f 0%, #1f6c76 100%);
  box-shadow: 0 12px 24px rgba(16, 62, 79, 0.2);
}

.organization-copy {
  min-width: 0;
  flex: 1;
}

.organization-name-row {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

.organization-name-row h2 {
  margin: 0;
  color: #153b48;
  font-size: 24px;
  line-height: 1.2;
}

.organization-slug {
  margin: 8px 0 0;
  color: #65808b;
  word-break: break-word;
}

.organization-section {
  margin-top: 16px;
}

.tag-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.tag,
.status-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 6px 10px;
  border-radius: 999px;
  background: rgba(16, 62, 79, 0.08);
  color: #103e4f;
  font-size: 13px;
}

.tag-muted {
  background: rgba(238, 186, 94, 0.18);
}

.current-pill {
  background: rgba(23, 148, 96, 0.16);
  color: #0f6b48;
}

.organization-card-footer {
  margin-top: 20px;
  padding-top: 16px;
  border-top: 1px solid rgba(16, 62, 79, 0.08);
  color: #0f5667;
  font-weight: 600;
}

.organization-select-actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-top: 24px;
}

.empty-state {
  padding: 28px;
  border-radius: 22px;
  background: rgba(255, 255, 255, 0.74);
  border: 1px dashed rgba(16, 62, 79, 0.14);
}

.empty-state h2 {
  margin: 0 0 10px;
  color: #103e4f;
  font-size: 28px;
}

.empty-state p {
  margin: 0;
  color: #4e6873;
  line-height: 1.7;
}

.secondary-btn,
.ghost-btn {
  padding: 12px 18px;
  border-radius: 14px;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.secondary-btn {
  border: none;
  color: #fff;
  background: linear-gradient(135deg, #103e4f 0%, #1f6c76 100%);
}

.secondary-btn:hover {
  transform: translateY(-1px);
  box-shadow: 0 10px 24px rgba(16, 62, 79, 0.22);
}

.ghost-btn {
  border: 1px solid rgba(16, 62, 79, 0.16);
  color: #103e4f;
  background: rgba(255, 255, 255, 0.86);
}

.ghost-btn:hover {
  border-color: rgba(16, 62, 79, 0.3);
}

.spinner {
  width: 42px;
  height: 42px;
  margin: 0 auto 16px;
  border-radius: 50%;
  border: 4px solid rgba(16, 62, 79, 0.12);
  border-top-color: #1f6c76;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

@media (max-width: 900px) {
  .hero-panel {
    flex-direction: column;
  }

  .hero-meta {
    width: 100%;
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .organization-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 640px) {
  .organization-select-shell {
    padding: 24px;
  }

  .hero-copy h1 {
    font-size: 30px;
  }

  .hero-meta {
    grid-template-columns: 1fr;
  }

  .organization-name-row h2 {
    font-size: 22px;
  }
}
</style>
