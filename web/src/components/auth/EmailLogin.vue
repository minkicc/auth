/*
 * Copyright (c) 2025 Open Source Contributors (https://example.com)
 * Licensed under the MIT License.
 */

<template>
  <div>
    <!-- 邮箱验证码登录表单 -->
    <form @submit.prevent="handleEmailLogin" class="auth-form">
      <div class="form-item">
        <input
          v-model="formData.email"
          type="email"
          :placeholder="$t('common.email')"
          :class="{ 'error': formErrors.email }"
        >
        <span v-if="formErrors.email" class="error-text">{{ formErrors.email }}</span>
      </div>

      <div class="form-item verification-code">
        <input
          v-model="formData.code"
          type="text"
          :placeholder="$t('common.verificationCode')"
          :class="{ 'error': formErrors.code }"
        >
        <button
          type="button"
          class="code-btn"
          :disabled="cooldown > 0 || !formData.email || isLoading || isSendingCode"
          @click="sendVerificationCode"
        >
          <span v-if="isSendingCode">{{ $t('common.sending') }}</span>
          <span v-else>{{ cooldown > 0 ? $t('common.secondsRemaining', { seconds: cooldown }) : $t('auth.getVerificationCode') }}</span>
        </button>
        <span v-if="formErrors.code" class="error-text">{{ formErrors.code }}</span>
      </div>

      <button type="submit" :disabled="isLoading" class="submit-btn">
        {{ isLoading ? $t('common.loading') : $t('auth.emailLogin') }}
      </button>
    </form>
  </div>
</template>

<script lang="ts" setup>
import { onUnmounted, reactive, ref, defineEmits } from 'vue'
import { useI18n } from 'vue-i18n'
import { serverApi } from '@/api/serverApi';

const emit = defineEmits<{
  (e: 'login-success'): void
  (e: 'login-error', message: string): void
}>()

interface FormData {
  email: string
  code: string
}

interface FormErrors {
  email?: string
  code?: string
}

const { t } = useI18n()
const isLoading = ref(false)
const isSendingCode = ref(false)
const cooldown = ref(0)
let cooldownTimer: number | null = null
const formData = reactive<FormData>({
  email: '',
  code: ''
})
const formErrors = reactive<FormErrors>({})

const validateForm = () => {
  let isValid = true

  // 清除之前的错误
  Object.keys(formErrors).forEach(key => delete formErrors[key as keyof FormErrors])

  if (!formData.email) {
    formErrors.email = t('validation.required', { field: t('common.email') })
    isValid = false
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
    formErrors.email = t('validation.invalidEmail')
    isValid = false
  }

  if (!formData.code) {
    formErrors.code = t('validation.required', { field: t('common.verificationCode') })
    isValid = false
  } else if (!/^\d{6}$/.test(formData.code)) {
    formErrors.code = t('validation.verificationCodeFormat')
    isValid = false
  }

  return isValid
}

const validateEmailOnly = () => {
  delete formErrors.email

  if (!formData.email) {
    formErrors.email = t('validation.required', { field: t('common.email') })
    return false
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
    formErrors.email = t('validation.invalidEmail')
    return false
  }
  return true
}

const startCooldown = () => {
  cooldown.value = 60
  if (cooldownTimer) {
    clearInterval(cooldownTimer)
  }
  cooldownTimer = window.setInterval(() => {
    cooldown.value--
    if (cooldown.value <= 0 && cooldownTimer) {
      clearInterval(cooldownTimer)
      cooldownTimer = null
    }
  }, 1000)
}

const sendVerificationCode = async () => {
  if (!validateEmailOnly()) return

  try {
    isSendingCode.value = true
    await serverApi.sendEmailLoginCode(formData.email)
    startCooldown()
  } catch (error: any) {
    emit('login-error', error.response?.data?.error || error.message || t('errors.emailLoginFailed'))
  } finally {
    isSendingCode.value = false
  }
}

const handleEmailLogin = async () => {
  try {
    // 表单验证
    if (!validateForm()) return

    isLoading.value = true

    await serverApi.emailCodeLogin(formData.email, formData.code)
    emit('login-success')

  } catch (error: any) {
    // 登录失败，通知父组件
    emit('login-error', error.response?.data?.error || error.message || t('errors.emailLoginFailed'))
  } finally {
    isLoading.value = false
  }
}

onUnmounted(() => {
  if (cooldownTimer) {
    clearInterval(cooldownTimer)
  }
})
</script>

<style scoped>
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

.verification-code {
  position: relative;
}

.verification-code input {
  padding-right: 132px;
}

.code-btn {
  position: absolute;
  right: 6px;
  top: 6px;
  border: none;
  border-radius: 6px;
  padding: 7px 10px;
  background: #eef6f9;
  color: #155266;
  cursor: pointer;
}

.code-btn:disabled {
  color: #8aa1aa;
  cursor: not-allowed;
}
</style>
