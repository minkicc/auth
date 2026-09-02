/*
 * Licensed under the MIT License.
 */

<template>
  <div class="weixin-login-container">
    <button @click="startWechatLogin" :disabled="isLoading" class="social-btn wechat-btn" type="button">
      <img src="@/assets/wechat-icon.svg" alt="" />
      {{ isLoading ? $t('common.loading') : $t('auth.loginWithWechat') }}
    </button>
  </div>
</template>

<script lang="ts" setup>
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { getApiErrorMessage, serverApi } from '@/api/serverApi'

const emit = defineEmits<{
  (e: 'login-error', message: string): void
}>()
const props = defineProps<{
  invitationCode?: string
}>()

const { t } = useI18n()
const isLoading = ref(false)

const startWechatLogin = async () => {
  isLoading.value = true
  try {
    const url = await serverApi.getWechatAuthURL(props.invitationCode || '')
    window.location.assign(url)
  } catch (error) {
    emit('login-error', getApiErrorMessage(error, t('errors.wechatLoginFailed')))
    isLoading.value = false
  } finally {
    if (document.visibilityState === 'visible') isLoading.value = false
  }
}
</script>

<style scoped>
.weixin-login-container {
  width: 100%;
  display: grid;
  gap: 12px;
}

.wechat-btn {
  width: 100%;
  height: 44px;
  background: #07C160;
  color: white;
  border: none;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 16px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  text-align: center;
  gap: 8px;
  transition: all 0.3s;
}

.wechat-btn img {
  width: 20px;
  height: 20px;
  margin-right: 4px;
  object-fit: contain;
}

.wechat-btn:hover {
  background: #06ae56;
}

.wechat-btn:disabled {
  background: #92ddb5;
  cursor: not-allowed;
  opacity: 0.8;
}

/* 社交按钮通用样式 */
.social-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 16px;
  font-size: 14px;
  transition: all 0.3s;
  outline: none;
  cursor: pointer;
}
</style>
