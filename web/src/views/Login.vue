/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

<template>
  <!-- 登录表单容器 -->
  <div v-if="shouldShowLoginForm" class="login-container">
    <div class="brand-header">
      <img src="/minki-logo.svg" alt="minki-auth logo" class="brand-logo" />
      <div class="brand-copy">
        <p class="brand-kicker">Minki Technology</p>
        <h1 class="brand-title">minki-auth</h1>
      </div>
    </div>

    <!-- 登录/注册标签页 -->
    <div class="auth-tabs">
      <button 
        :class="['tab-btn', { active: activeTab === 'login' }]" 
        @click="activeTab = 'login'"
      >
        {{ $t('auth.login') }}
      </button>
      <button 
        :class="['tab-btn', { active: activeTab === 'register' }]" 
        @click="activeTab = 'register'"
      >
        {{ $t('auth.register') }}
      </button>
    </div>

    <!-- 登录表单 -->
    <div v-if="activeTab === 'login'">
      <!-- 登录方式选择器 -->
      <div v-if="hasMultipleLoginMethods" class="login-type-selector">
        <button 
          v-if="hasAccountLogin"
          :class="['login-type-btn', { active: loginType === 'account' }]" 
          @click="loginType = 'account'"
        >
          {{ $t('auth.accountLogin') }}
        </button>
        <button 
          v-if="hasEmailLogin"
          :class="['login-type-btn', { active: loginType === 'email' }]" 
          @click="loginType = 'email'"
        >
          {{ $t('auth.emailLogin') }}
        </button>
        <button 
          v-if="hasPhoneLogin"
          :class="['login-type-btn', { active: loginType === 'phone' }]" 
          @click="loginType = 'phone'"
        >
          {{ $t('auth.phoneLogin') }}
        </button>
      </div>
    
      <!-- 登录组件 -->
      <AccountLogin
        v-if="(loginType === 'account' || (!hasEmailLogin && !hasPhoneLogin)) && hasAccountLogin"
        @login-success="handleLoginSuccess"
        @login-error="handleLoginError"
      />
      <EmailLogin
        v-if="(loginType === 'email' || (!hasAccountLogin && !hasPhoneLogin)) && hasEmailLogin"
        @login-success="handleLoginSuccess"
        @login-error="handleLoginError"
      />
      <PhoneLogin
        v-if="(loginType === 'phone' || (!hasAccountLogin && !hasEmailLogin)) && hasPhoneLogin"
        @login-success="handleLoginSuccess"
        @login-error="handleLoginError"
      />
    </div>

    <!-- 注册表单 -->
    <div v-if="activeTab === 'register'">
      <!-- 注册方式选择器 -->
      <div v-if="hasMultipleRegisterMethods" class="register-type-selector">
        <button 
          v-if="hasAccountLogin"
          :class="['register-type-btn', { active: registerType === 'account' }]" 
          @click="registerType = 'account'"
        >
          {{ $t('auth.accountRegister') }}
        </button>
        <button 
          v-if="hasEmailLogin"
          :class="['register-type-btn', { active: registerType === 'email' }]" 
          @click="registerType = 'email'"
        >
          {{ $t('auth.emailRegister') }}
        </button>
        <button 
          v-if="hasPhoneLogin"
          :class="['register-type-btn', { active: registerType === 'phone' }]" 
          @click="registerType = 'phone'"
        >
          {{ $t('auth.phoneRegister') }}
        </button>
      </div>
      
      <!-- 注册组件 -->
      <AccountRegister
        v-if="(registerType === 'account' || (!hasEmailLogin && !hasPhoneLogin)) && hasAccountLogin"
        :invitation-code="invitationCode"
        @register-success="handleRegisterSuccess"
        @register-error="handleLoginError"
      />
      <EmailRegister
        v-if="(registerType === 'email' || (!hasAccountLogin && !hasPhoneLogin)) && hasEmailLogin"
        :invitation-code="invitationCode"
        @register-success="handleRegisterSuccess"
        @register-error="handleLoginError"
      />
      <PhoneRegister
        v-if="(registerType === 'phone' || (!hasAccountLogin && !hasEmailLogin)) && hasPhoneLogin"
        :invitation-code="invitationCode"
        @register-success="handleRegisterSuccess"
        @register-error="handleLoginError"
      />
    </div>
    
    <!-- 社交登录 -->
    <div v-if="hasSocialLogin && hasPrimaryLogin"
         class="divider"
    >
      {{ $t('common.or') }}
    </div>
    
    <div v-if="hasSocialLogin" class="social-login">
      <div class="social-buttons">
        <GoogleLogin 
          v-if="hasGoogleLogin" 
          :invitation-code="invitationCode"
          @login-error="handleLoginError"
          @login-success="handleLoginSuccess"
        />
        <WeixinLogin 
          v-if="hasWeixinLogin" 
          :invitation-code="invitationCode"
          @login-error="handleLoginError"
        />
        <div v-if="hasEnterpriseOIDCLogin" class="enterprise-sso-panel">
          <div class="enterprise-discovery-card">
            <p class="enterprise-discovery-title">{{ $t('auth.enterpriseEmailLogin') }}</p>
            <p class="enterprise-discovery-subtitle">{{ $t('auth.enterpriseEmailLoginHint') }}</p>
            <div class="enterprise-discovery-form">
              <input
                v-model="enterpriseEmail"
                class="enterprise-discovery-input"
                type="email"
                :placeholder="$t('auth.enterpriseEmailPlaceholder')"
                @input="resetEnterpriseOIDCDiscovery"
                @keyup.enter="handleEnterpriseOIDCDiscovery"
              />
              <button
                class="enterprise-discovery-submit"
                type="button"
                :disabled="enterpriseDiscoveryLoading"
                @click="handleEnterpriseOIDCDiscovery"
              >
                {{ enterpriseDiscoveryLoading ? $t('common.loading') : $t('common.next') }}
              </button>
            </div>
            <p v-if="enterpriseDiscoveryMessage" class="enterprise-discovery-message">
              {{ enterpriseDiscoveryMessage }}
            </p>
          </div>

          <div v-if="visibleEnterpriseOIDCProviders.length > 0" class="enterprise-login-list">
            <button
              v-for="provider in visibleEnterpriseOIDCProviders"
              :key="provider.slug"
              class="enterprise-login-btn"
              type="button"
              @click="handleEnterpriseOIDCLogin(provider)"
            >
              <span class="enterprise-login-mark">SSO</span>
              <span class="enterprise-login-text">
                {{ $t('auth.loginWithEnterprise', { name: provider.name }) }}
              </span>
            </button>
          </div>

          <div v-if="selectedEnterpriseLDAPProvider" class="enterprise-directory-card">
            <p class="enterprise-directory-title">
              {{ $t('auth.loginWithEnterprise', { name: selectedEnterpriseLDAPProvider.name }) }}
            </p>
            <p class="enterprise-directory-subtitle">{{ $t('auth.enterpriseDirectoryLoginHint') }}</p>
            <div class="enterprise-directory-form">
              <input
                v-model="enterpriseDirectoryUsername"
                class="enterprise-discovery-input"
                type="text"
                :placeholder="$t('auth.enterpriseDirectoryUsernamePlaceholder')"
              />
              <input
                v-model="enterpriseDirectoryPassword"
                class="enterprise-discovery-input"
                type="password"
                :placeholder="$t('auth.enterpriseDirectoryPasswordPlaceholder')"
                @keyup.enter="handleEnterpriseLDAPLogin"
              />
              <button
                class="enterprise-discovery-submit"
                type="button"
                :disabled="enterpriseDirectoryLoading"
                @click="handleEnterpriseLDAPLogin"
              >
                {{ enterpriseDirectoryLoading ? $t('common.loading') : $t('auth.enterpriseDirectoryLogin') }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 错误信息 -->
    <div v-if="errorMessage" class="error-message">
      {{ errorMessage }}
    </div>
  </div>

  <!-- 仅社交登录容器 -->
  <div v-if="hasSocialLogin && !shouldShowLoginForm" class="social-buttons2">
    <GoogleLogin 
      v-if="hasGoogleLogin" 
      :invitation-code="invitationCode"
      @login-error="handleLoginError"
      @login-success="handleLoginSuccess"
    />
    <WeixinLogin 
      v-if="hasWeixinLogin" 
      :invitation-code="invitationCode"
      @login-error="handleLoginError"
    />
    <div v-if="hasEnterpriseOIDCLogin" class="enterprise-sso-panel">
      <div class="enterprise-discovery-card">
        <p class="enterprise-discovery-title">{{ $t('auth.enterpriseEmailLogin') }}</p>
        <p class="enterprise-discovery-subtitle">{{ $t('auth.enterpriseEmailLoginHint') }}</p>
        <div class="enterprise-discovery-form">
          <input
            v-model="enterpriseEmail"
            class="enterprise-discovery-input"
            type="email"
            :placeholder="$t('auth.enterpriseEmailPlaceholder')"
            @input="resetEnterpriseOIDCDiscovery"
            @keyup.enter="handleEnterpriseOIDCDiscovery"
          />
          <button
            class="enterprise-discovery-submit"
            type="button"
            :disabled="enterpriseDiscoveryLoading"
            @click="handleEnterpriseOIDCDiscovery"
          >
            {{ enterpriseDiscoveryLoading ? $t('common.loading') : $t('common.next') }}
          </button>
        </div>
        <p v-if="enterpriseDiscoveryMessage" class="enterprise-discovery-message">
          {{ enterpriseDiscoveryMessage }}
        </p>
      </div>

      <div v-if="visibleEnterpriseOIDCProviders.length > 0" class="enterprise-login-list">
        <button
          v-for="provider in visibleEnterpriseOIDCProviders"
          :key="provider.slug"
          class="enterprise-login-btn"
          type="button"
          @click="handleEnterpriseOIDCLogin(provider)"
        >
          <span class="enterprise-login-mark">SSO</span>
          <span class="enterprise-login-text">
            {{ $t('auth.loginWithEnterprise', { name: provider.name }) }}
          </span>
        </button>
      </div>

      <div v-if="selectedEnterpriseLDAPProvider" class="enterprise-directory-card">
        <p class="enterprise-directory-title">
          {{ $t('auth.loginWithEnterprise', { name: selectedEnterpriseLDAPProvider.name }) }}
        </p>
        <p class="enterprise-directory-subtitle">{{ $t('auth.enterpriseDirectoryLoginHint') }}</p>
        <div class="enterprise-directory-form">
          <input
            v-model="enterpriseDirectoryUsername"
            class="enterprise-discovery-input"
            type="text"
            :placeholder="$t('auth.enterpriseDirectoryUsernamePlaceholder')"
          />
          <input
            v-model="enterpriseDirectoryPassword"
            class="enterprise-discovery-input"
            type="password"
            :placeholder="$t('auth.enterpriseDirectoryPasswordPlaceholder')"
            @keyup.enter="handleEnterpriseLDAPLogin"
          />
          <button
            class="enterprise-discovery-submit"
            type="button"
            :disabled="enterpriseDirectoryLoading"
            @click="handleEnterpriseLDAPLogin"
          >
            {{ enterpriseDirectoryLoading ? $t('common.loading') : $t('auth.enterpriseDirectoryLogin') }}
          </button>
        </div>
      </div>
    </div>
    <div v-if="errorMessage" class="error-message">
      {{ errorMessage }}
    </div>
  </div>
</template>

<script lang="ts" setup>
import { ref, onMounted, computed } from 'vue'
import { context } from '@/context'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'


// 组件导入
import AccountLogin from '@/components/auth/AccountLogin.vue'
import EmailLogin from '@/components/auth/EmailLogin.vue'
import PhoneLogin from '@/components/auth/PhoneLogin.vue'
import GoogleLogin from '@/components/auth/GoogleLogin.vue'
import WeixinLogin from '@/components/auth/WeixinLogin.vue'
import AccountRegister from '@/components/auth/AccountRegister.vue'
import EmailRegister from '@/components/auth/EmailRegister.vue'
import PhoneRegister from '@/components/auth/PhoneRegister.vue'
import { getApiErrorMessage, serverApi } from '@/api/serverApi'
import type { AuthProvider, EnterpriseOIDCDiscoveryResponse, EnterpriseOIDCProvider } from '@/api/serverApi'


const { t } = useI18n()
const route = useRoute()


// 响应式状态
const activeTab = ref<'login' | 'register'>('login')
const loginType = ref<'account' | 'email' | 'phone'>('account')
const registerType = ref<'account' | 'email' | 'phone'>('account')
const errorMessage = ref('')
const shouldShowLoginForm = ref(false)
const enterpriseOIDCProviders = ref<EnterpriseOIDCProvider[]>([])
const enterpriseEmail = ref('')
const enterpriseDiscoveryLoading = ref(false)
const enterpriseDiscoveryMessage = ref('')
const discoveredEnterpriseOIDCProviders = ref<EnterpriseOIDCProvider[]>([])
const selectedEnterpriseLDAPProvider = ref<EnterpriseOIDCProvider | null>(null)
const enterpriseDirectoryUsername = ref('')
const enterpriseDirectoryPassword = ref('')
const enterpriseDirectoryLoading = ref(false)

// 登录方式检查
const hasProvider = (provider: AuthProvider) => context.hasProvider(provider)
const hasAccountLogin = hasProvider('account')
const hasEmailLogin = hasProvider('email')
const hasPhoneLogin = hasProvider('phone')
const hasGoogleLogin = hasProvider('google')
const hasWeixinLogin = hasProvider('weixin')
const hasEnterpriseOIDCLogin = hasProvider('enterprise_oidc')
const invitationCode = computed(() => {
  const raw = route.query.invitation_code || route.query.invite_code
  return Array.isArray(raw) ? (raw[0] || '') : (raw || '')
})


// 计算属性
const hasPrimaryLogin = computed(() => hasAccountLogin || hasEmailLogin || hasPhoneLogin)
const hasSocialLogin = computed(() => hasGoogleLogin || hasWeixinLogin || hasEnterpriseOIDCLogin)
const visibleEnterpriseOIDCProviders = computed(() => {
  return discoveredEnterpriseOIDCProviders.value.length > 0
    ? discoveredEnterpriseOIDCProviders.value
    : enterpriseOIDCProviders.value
})

const hasMultipleLoginMethods = computed(() => {
  let count = 0
  if (hasProvider('account')) count++
  if (hasProvider('email')) count++
  if (hasProvider('phone')) count++
  return count > 1
})

const hasMultipleRegisterMethods = computed(() => {
  let count = 0
  if (hasProvider('account')) count++
  if (hasProvider('email')) count++
  if (hasProvider('phone')) count++
  return count > 1
})

const handleWechatLogin = async () => {
  try {
    // 获取微信登录的URL
    const url = await serverApi.getWechatAuthUrl(invitationCode.value)

    // 获取url中的state
    const cleanUrl = url.split('#')[0]
    const state = cleanUrl.split('state=')[1]
    if (!state) {
      throw new Error(t('errors.wechatLoginFailed'))
    }
    // 使用state存储client_id
    sessionStorage.setItem(state, serverApi.clientId)
    // 重定向到微信登录页面
    // https://open.weixin.qq.com/connect/qrconnect?appid=xxxxx&redirect_uri=https://auth.example.com/wechat/callback&response_type=code&scope=snsapi_login&state=123#wechat_redirect
    // 上述地址授权完成后，会跳转到 https://auth.example.com/wechat/callback?code=xxx&state=123
    window.location.href = url
  } catch (error: any) {
    console.error(t('errors.wechatLoginFailed'), error)
  }
}

const loadEnterpriseOIDCProviders = async () => {
  if (!hasEnterpriseOIDCLogin) {
    enterpriseOIDCProviders.value = []
    discoveredEnterpriseOIDCProviders.value = []
    return
  }
  try {
    enterpriseOIDCProviders.value = await serverApi.fetchEnterpriseOIDCProviders()
  } catch (error) {
    console.error(t('errors.enterpriseOIDCProvidersFailed'), error)
    throw error
  }
}

const resetEnterpriseOIDCDiscovery = () => {
  discoveredEnterpriseOIDCProviders.value = []
  enterpriseDiscoveryMessage.value = ''
  errorMessage.value = ''
  selectedEnterpriseLDAPProvider.value = null
  enterpriseDirectoryPassword.value = ''
}

const enterpriseDiscoveryOrganizationName = (response: EnterpriseOIDCDiscoveryResponse) => {
  return response.organization_display_name || response.organization_name || response.organization_slug || response.domain || 'SSO'
}

const canUseEnterpriseLoginHint = (value: string) => {
  const trimmed = value.trim()
  return trimmed.includes('@') && !trimmed.startsWith('@') && !trimmed.endsWith('@')
}

const canUseEnterpriseDomainHint = (value: string) => {
  const trimmed = value.trim().toLowerCase()
  return trimmed.includes('.') && !trimmed.includes('@') && !trimmed.startsWith('.') && !trimmed.endsWith('.')
}

const applyEnterpriseOIDCDiscoveryResponse = (response: EnterpriseOIDCDiscoveryResponse) => {
  switch (response.status) {
    case 'matched':
      if (response.auto_redirect && response.preferred_provider_slug) {
        const preferredProvider = response.providers.find(provider => provider.slug === response.preferred_provider_slug)
        enterpriseDiscoveryMessage.value = t('auth.enterpriseDiscoveryMatched', {
          name: enterpriseDiscoveryOrganizationName(response)
        })
        if (preferredProvider) {
          handleEnterpriseOIDCLogin(preferredProvider)
        } else {
          handleEnterpriseOIDCLogin(response.preferred_provider_slug)
        }
        return
      }
      if (response.providers.length === 1) {
        enterpriseDiscoveryMessage.value = t('auth.enterpriseDiscoveryMatched', {
          name: enterpriseDiscoveryOrganizationName(response)
        })
        handleEnterpriseOIDCLogin(response.providers[0])
        return
      }
      discoveredEnterpriseOIDCProviders.value = response.providers
      enterpriseDiscoveryMessage.value = t('auth.enterpriseDiscoveryMultiple', {
        name: enterpriseDiscoveryOrganizationName(response)
      })
      return
    case 'domain_not_found':
      errorMessage.value = t('errors.enterpriseDomainNotFound')
      return
    case 'organization_inactive':
      errorMessage.value = t('errors.enterpriseOrganizationInactive')
      return
    case 'no_provider':
      errorMessage.value = t('errors.enterpriseOIDCNotConfigured')
      return
    default:
      errorMessage.value = t('errors.enterpriseOIDCDiscoveryFailed')
      return
  }
}

const handleEnterpriseOIDCDiscovery = async () => {
  const email = enterpriseEmail.value.trim()
  if (!email) {
    errorMessage.value = t('errors.enterpriseEmailRequired')
    return
  }

  enterpriseDiscoveryLoading.value = true
  errorMessage.value = ''
  enterpriseDiscoveryMessage.value = ''
  discoveredEnterpriseOIDCProviders.value = []

  try {
    const response = await serverApi.discoverEnterpriseOIDCByEmail(email)
    applyEnterpriseOIDCDiscoveryResponse(response)
  } catch (error) {
    errorMessage.value = getApiErrorMessage(error, t('errors.enterpriseOIDCDiscoveryFailed'))
  } finally {
    enterpriseDiscoveryLoading.value = false
  }
}

const handleEnterpriseOIDCDomainDiscovery = async (domain: string) => {
  enterpriseDiscoveryLoading.value = true
  errorMessage.value = ''
  enterpriseDiscoveryMessage.value = ''
  discoveredEnterpriseOIDCProviders.value = []

  try {
    const response = await serverApi.discoverEnterpriseOIDCByDomain(domain)
    applyEnterpriseOIDCDiscoveryResponse(response)
  } catch (error) {
    errorMessage.value = getApiErrorMessage(error, t('errors.enterpriseOIDCDiscoveryFailed'))
  } finally {
    enterpriseDiscoveryLoading.value = false
  }
}

const openEnterpriseLDAPProvider = (provider: EnterpriseOIDCProvider) => {
  selectedEnterpriseLDAPProvider.value = provider
  enterpriseDirectoryPassword.value = ''
  if (!enterpriseDirectoryUsername.value.trim()) {
    enterpriseDirectoryUsername.value = enterpriseEmail.value.trim() || serverApi.loginHint.trim()
  }
  enterpriseDiscoveryMessage.value = t('auth.enterpriseDirectorySelected', {
    name: provider.name,
  })
}

const handleEnterpriseOIDCLogin = (provider: EnterpriseOIDCProvider | string) => {
  try {
    errorMessage.value = ''
    const resolvedProvider = typeof provider === 'string'
      ? visibleEnterpriseOIDCProviders.value.find(item => item.slug === provider)
      : provider
    if (resolvedProvider?.provider_type === 'ldap') {
      openEnterpriseLDAPProvider(resolvedProvider)
      return
    }
    selectedEnterpriseLDAPProvider.value = null
    serverApi.startEnterpriseOIDCLogin(provider)
  } catch (error) {
    console.error(t('errors.enterpriseOIDCLoginFailed'), error)
    errorMessage.value = t('errors.enterpriseOIDCLoginFailed')
  }
}

const handleEnterpriseLDAPLogin = async () => {
  if (!selectedEnterpriseLDAPProvider.value) {
    errorMessage.value = t('errors.enterpriseLDAPLoginFailed')
    return
  }

  const username = enterpriseDirectoryUsername.value.trim()
  const password = enterpriseDirectoryPassword.value
  if (!username || !password) {
    errorMessage.value = t('errors.enterpriseDirectoryCredentialsRequired')
    return
  }

  enterpriseDirectoryLoading.value = true
  errorMessage.value = ''

  try {
    await serverApi.enterpriseLDAPLogin(selectedEnterpriseLDAPProvider.value, username, password)
  } catch (error) {
    errorMessage.value = getApiErrorMessage(error, t('errors.enterpriseLDAPLoginFailed'))
  } finally {
    enterpriseDirectoryLoading.value = false
  }
}


// 生命周期钩子
onMounted(async () => {

  try {
    if (context.isAuthenticated) {
      try {
        await serverApi.fetchBrowserSession()
        await serverApi.handleLoginRedirect()
        return
      } catch {
        context.setAuthenticated(false)
      }
    }

    if (route.query.tab === 'register') {
      activeTab.value = 'register'
    }

    await loadEnterpriseOIDCProviders()

    const loginHint = serverApi.loginHint.trim()
    if (hasEnterpriseOIDCLogin && canUseEnterpriseLoginHint(loginHint)) {
      enterpriseEmail.value = loginHint
      await handleEnterpriseOIDCDiscovery()
    } else {
      const domainHint = serverApi.domainHint.trim()
      if (hasEnterpriseOIDCLogin && canUseEnterpriseDomainHint(domainHint)) {
        await handleEnterpriseOIDCDomainDiscovery(domainHint)
      }
    }

    // 如果只有微信登录
    if (!hasAccountLogin && !hasEmailLogin && !hasPhoneLogin && !hasGoogleLogin && !hasEnterpriseOIDCLogin && hasWeixinLogin) {
      handleWechatLogin()
      return
    }
    
    // 如果只有社交/企业 SSO 登录
    if (!hasPrimaryLogin.value) {
      return
    }
    
    shouldShowLoginForm.value = true
    // 设置默认登录和注册类型
    if (hasProvider('account')) {
      loginType.value = 'account'
      registerType.value = 'account'
    } else if (hasProvider('email')) {
      loginType.value = 'email'
      registerType.value = 'email'
    } else if (hasProvider('phone')) {
      loginType.value = 'phone'
      registerType.value = 'phone'
    }
  } catch (error) {
    console.error(t('errors.initLoginPageFailed'), error)
    errorMessage.value = t('errors.loadLoginOptionsFailed')
  }
})

// 事件处理
const handleLoginSuccess = () => {
  errorMessage.value = ''

}

const handleLoginError = (message: string) => {
  errorMessage.value = message
}

const handleRegisterSuccess = () => {
  errorMessage.value = t('auth.registerSuccess')
  handleLoginSuccess()
}
</script>

<style scoped>
/* 容器样式 */
.login-container,
.social-buttons2 {
  max-width: 400px;
  margin: 40px auto;
  padding: 30px;
  border-radius: 12px;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.1);
  background: white;
}

.brand-header {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 24px;
}

.brand-logo {
  width: 44px;
  height: 44px;
  border-radius: 12px;
  box-shadow: 0 10px 24px rgba(17, 63, 84, 0.18);
  flex-shrink: 0;
}

.brand-copy {
  min-width: 0;
}

.brand-kicker {
  margin: 0 0 2px;
  color: #5b7280;
  font-size: 12px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.brand-title {
  margin: 0;
  color: #113f54;
  font-size: 26px;
  line-height: 1.1;
  font-weight: 700;
}

/* 标签页样式 */
.auth-tabs {
  display: flex;
  margin-bottom: 24px;
  border-bottom: 1px solid #eee;
}

.tab-btn {
  flex: 1;
  padding: 12px;
  background: none;
  border: none;
  color: #666;
  font-size: 16px;
  cursor: pointer;
  transition: all 0.3s;
}

.tab-btn.active {
  color: #1890ff;
  border-bottom: 2px solid #1890ff;
}

/* 登录方式选择器 */
.login-type-selector,
.register-type-selector {
  display: flex;
  margin-bottom: 20px;
  background: #f5f5f5;
  border-radius: 8px;
  overflow: hidden;
}

.login-type-btn,
.register-type-btn {
  flex: 1;
  padding: 10px;
  background: none;
  border: none;
  color: #666;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.3s;
}

.login-type-btn.active,
.register-type-btn.active {
  background: #1890ff;
  color: white;
}

/* 表单样式 */
.auth-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.form-item {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

input {
  padding: 12px;
  border: 1px solid #ddd;
  border-radius: 8px;
  font-size: 14px;
  transition: all 0.3s;
}

input:focus {
  outline: none;
  border-color: #1890ff;
  box-shadow: 0 0 0 2px rgba(24,144,255,0.1);
}

input.error {
  border-color: #ff4d4f;
}

.error-text {
  color: #ff4d4f;
  font-size: 12px;
}

/* 按钮样式 */
.submit-btn {
  padding: 12px;
  border: none;
  border-radius: 8px;
  background: #1890ff;
  color: white;
  font-size: 16px;
  cursor: pointer;
  transition: all 0.3s;
}

.submit-btn:hover {
  background: #40a9ff;
}

.submit-btn:disabled {
  background: #bfbfbf;
  cursor: not-allowed;
}

/* 分隔线样式 */
.divider {
  margin: 24px 0;
  text-align: center;
  color: #999;
  position: relative;
}

.divider::before,
.divider::after {
  content: '';
  position: absolute;
  top: 50%;
  width: 45%;
  height: 1px;
  background: #eee;
}

.divider::before {
  left: 0;
}

.divider::after {
  right: 0;
}

/* 社交登录样式 */
.social-login {
  margin-bottom: 16px;
  width: 100%;
}

.social-buttons,
.social-buttons2 {
  display: flex;
  flex-direction: column;
  gap: 16px;
  width: 100%;
}

.enterprise-sso-panel {
  display: flex;
  flex-direction: column;
  gap: 12px;
  width: 100%;
}

.enterprise-discovery-card {
  padding: 14px;
  border: 1px solid #d8e6ed;
  border-radius: 12px;
  background: linear-gradient(180deg, #fbfdfe 0%, #f3f8fb 100%);
}

.enterprise-discovery-title {
  margin: 0 0 4px;
  color: #113f54;
  font-size: 14px;
  font-weight: 700;
}

.enterprise-discovery-subtitle {
  margin: 0 0 12px;
  color: #627b88;
  font-size: 13px;
  line-height: 1.5;
}

.enterprise-discovery-form {
  display: flex;
  gap: 10px;
}

.enterprise-discovery-input {
  flex: 1;
  min-width: 0;
  padding: 12px 14px;
  border: 1px solid #c9d7df;
  border-radius: 10px;
  font-size: 14px;
  color: #113f54;
  background: #ffffff;
  outline: none;
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.enterprise-discovery-input:focus {
  border-color: #1890ff;
  box-shadow: 0 0 0 3px rgba(24, 144, 255, 0.12);
}

.enterprise-discovery-submit {
  padding: 0 16px;
  border: none;
  border-radius: 10px;
  background: #113f54;
  color: #ffffff;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.2s ease, transform 0.2s ease;
}

.enterprise-discovery-submit:hover:not(:disabled) {
  opacity: 0.92;
  transform: translateY(-1px);
}

.enterprise-discovery-submit:disabled {
  cursor: not-allowed;
  opacity: 0.6;
}

.enterprise-discovery-message {
  margin: 10px 0 0;
  color: #3a5a68;
  font-size: 13px;
  line-height: 1.5;
}

.enterprise-login-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
  width: 100%;
}

.enterprise-directory-card {
  padding: 14px;
  border: 1px solid #d8e6ed;
  border-radius: 12px;
  background: linear-gradient(180deg, #ffffff 0%, #f7fbfd 100%);
}

.enterprise-directory-title {
  margin: 0 0 4px;
  color: #113f54;
  font-size: 14px;
  font-weight: 700;
}

.enterprise-directory-subtitle {
  margin: 0 0 12px;
  color: #627b88;
  font-size: 13px;
  line-height: 1.5;
}

.enterprise-directory-form {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.enterprise-login-btn {
  display: flex;
  align-items: center;
  gap: 12px;
  width: 100%;
  padding: 12px 14px;
  border: 1px solid #c9d7df;
  border-radius: 10px;
  background: linear-gradient(135deg, #f7fbfd 0%, #eef6fa 100%);
  color: #113f54;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;
}

.enterprise-login-btn:hover {
  border-color: #1890ff;
  box-shadow: 0 8px 18px rgba(17, 63, 84, 0.12);
  transform: translateY(-1px);
}

.enterprise-login-mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 42px;
  height: 28px;
  border-radius: 8px;
  background: #113f54;
  color: #ffffff;
  font-size: 12px;
  letter-spacing: 0.08em;
  flex-shrink: 0;
}

.enterprise-login-text {
  min-width: 0;
  text-align: left;
}

/* 错误信息样式 */
.error-message {
  margin-top: 16px;
  padding: 12px;
  background: #fff2f0;
  border: 1px solid #ffccc7;
  border-radius: 8px;
  color: #ff4d4f;
  font-size: 14px;
}

/* 加载动画样式 */
.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 4px solid rgba(0, 0, 0, 0.1);
  border-top: 4px solid #1890ff;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

@media (max-width: 520px) {
  .enterprise-discovery-form {
    flex-direction: column;
  }

  .enterprise-discovery-submit {
    min-height: 44px;
  }
}
</style>
