/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

<template>
  <div class="email-verify-container">
    <div v-if="loading" class="verify-loading">
      <div class="spinner"></div>
      <p>{{ statusMessage }}</p>
    </div>
    
    <div v-else-if="error" class="verify-error">
      <h1>{{ $t('emailVerify.verifyFailed') }}</h1>
      <p>{{ error }}</p>
      <div class="actions">
        <button @click="resendVerification" :disabled="resending">
          {{ resending ? $t('emailVerify.sending') : $t('emailVerify.resendVerification') }}
        </button>
        <button @click="goToRegister">{{ $t('emailVerify.register') }}</button>
        <button @click="goToLogin">{{ $t('emailVerify.backToLogin') }}</button>
      </div>
      
      <div v-if="resendSuccess" class="resend-success">
        <div class="success-icon-small">✓</div>
        {{ $t('emailVerify.resendSuccess') }}
      </div>
    </div>
    
    <div v-else-if="success" class="verify-success">
      <h1>{{ $t('emailVerify.verifySuccess') }}</h1>
      <p>{{ $t('emailVerify.redirecting') }}</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import axios from 'axios'
import { serverApi } from '@/api/serverApi'
import { buildVerificationEmailTpl } from './emailtpl'

const route = useRoute()
const router = useRouter()
const { t } = useI18n()

const loading = ref(true)
const error = ref('')
const success = ref(false)
const resending = ref(false)
const verifiedEmail = ref('')
const resendSuccess = ref(false)

const statusMessage = computed(() => {
  if (success.value) {
    return t('emailVerify.redirecting')
  }
  return t('emailVerify.loading')
})

const verifyEmail = async (token: string) => {
  try {
    loading.value = true
    
    const response = await axios.get('/email/verify', {
      params: { token },
      headers: {
        'Content-Type': 'application/json',
      },
    })

    if (response.status !== 200) {
      throw new Error(response.data.error || t('emailVerify.verifyFailed'))
    }
    
    success.value = true
    serverApi.updateUserInfo(response.data)
  } catch (err: any) {
    console.error('验证邮箱失败:', err)
    error.value = err.response?.data?.error || err.message || t('emailVerify.verifyFailed')
  } finally {
    loading.value = false
  }
}

const resendVerification = async () => {
  if (!verifiedEmail.value) {
    error.value = t('emailVerify.cannotResend')
    return
  }
  
  try {
    const verificationEmailTpl = buildVerificationEmailTpl({
      clientId: serverApi.clientId,
      redirectUri: serverApi.redirectUri,
    })

    resending.value = true
    resendSuccess.value = false
    
    await axios.post('/email/resend-verification', {
      email: verifiedEmail.value,
      title: t('email.verificationTitle'),
      content: verificationEmailTpl
    })
    
    resendSuccess.value = true
    
    setTimeout(() => {
      resendSuccess.value = false
    }, 5000)
    
  } catch (err: any) {
    console.error('重新发送验证邮件失败:', err)
    error.value = err.response?.data?.error || err.response?.data?.message || t('emailVerify.verifyFailed')
  } finally {
    resending.value = false
  }
}

const goToRegister = () => {
  router.push({
    path: '/login',
    query: {
      tab: 'register',
      ...(serverApi.clientId ? { client_id: serverApi.clientId } : {}),
      ...(serverApi.redirectUri ? { redirect_uri: serverApi.redirectUri } : {}),
      ...(serverApi.loginHint ? { login_hint: serverApi.loginHint } : {}),
      ...(serverApi.domainHint ? { domain_hint: serverApi.domainHint } : {}),
      ...(serverApi.orgHint ? { org_hint: serverApi.orgHint } : {}),
    },
  })
}

const goToLogin = () => {
  router.push({
    path: '/login',
    query: {
      ...(serverApi.clientId ? { client_id: serverApi.clientId } : {}),
      ...(serverApi.redirectUri ? { redirect_uri: serverApi.redirectUri } : {}),
      ...(serverApi.loginHint ? { login_hint: serverApi.loginHint } : {}),
      ...(serverApi.domainHint ? { domain_hint: serverApi.domainHint } : {}),
      ...(serverApi.orgHint ? { org_hint: serverApi.orgHint } : {}),
    },
  })
}

onMounted(() => {
  const token = route.query.token as string
  const clientId = typeof route.query.client_id === 'string' ? route.query.client_id : ''
  const redirectUri = typeof route.query.redirect_uri === 'string'
    ? route.query.redirect_uri
    : typeof route.query.redirect_url === 'string'
      ? route.query.redirect_url
      : undefined
  const loginHint = typeof route.query.login_hint === 'string' ? route.query.login_hint : undefined
  const domainHint = typeof route.query.domain_hint === 'string' ? route.query.domain_hint : undefined
  const orgHint = typeof route.query.org_hint === 'string' ? route.query.org_hint : undefined

  serverApi.updateAuthData(clientId, redirectUri, loginHint, domainHint, orgHint)
  
  if (!token) {
    loading.value = false
    error.value = t('emailVerify.invalidLink')
    return
  }
  
  verifiedEmail.value = route.query.email as string || ''
  
  verifyEmail(token)
})
</script>

<style scoped>
.email-verify-container {
  max-width: 500px;
  margin: 0 auto;
  padding: 40px 20px;
  text-align: center;
}

h1 {
  margin-bottom: 20px;
  color: #333;
}

.verify-loading, .verify-error, .verify-success {
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.verify-loading {
  display: flex;
  flex-direction: column;
  align-items: center;
}

.spinner {
  width: 40px;
  height: 40px;
  border: 4px solid #f3f3f3;
  border-top: 4px solid #3498db;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 15px;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.verify-error {
  background-color: #fff0f0;
  border: 1px solid #ffcccc;
  color: #cc0000;
}

.verify-success {
  background-color: #f0fff0;
  border: 1px solid #ccffcc;
  color: #007700;
}

.user-info {
  margin: 20px 0;
  padding: 15px;
  background-color: #f9f9f9;
  border-radius: 4px;
  text-align: left;
}

.actions {
  margin-top: 20px;
  display: flex;
  gap: 10px;
  justify-content: center;
}

button {
  padding: 10px 15px;
  border: none;
  border-radius: 4px;
  background-color: #3498db;
  color: white;
  cursor: pointer;
  font-size: 14px;
  transition: background-color 0.3s;
}

button:hover {
  background-color: #2980b9;
}

button:disabled {
  background-color: #95a5a6;
  cursor: not-allowed;
}

/* 重发成功提示样式 */
.resend-success {
  display: flex;
  align-items: center;
  margin-top: 12px;
  padding: 8px 12px;
  background-color: #f6ffed;
  border: 1px solid #b7eb8f;
  border-radius: 4px;
  color: #52c41a;
  font-size: 14px;
  animation: fadeIn 0.3s ease-in-out;
}

.success-icon-small {
  width: 20px;
  height: 20px;
  margin-right: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background-color: #52c41a;
  color: white;
  font-size: 12px;
  font-weight: bold;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(-10px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>
