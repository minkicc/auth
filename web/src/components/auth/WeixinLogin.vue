/*
 * Licensed under the MIT License.
 */

<template>
  <div class="weixin-login-container">
    <div v-if="qrDataURL" class="wechat-qr-panel">
      <img :src="qrDataURL" alt="微信登录二维码" class="wechat-qr-code" />
      <strong>使用微信扫一扫登录</strong>
      <span>{{ statusText }}</span>
    </div>
    <div v-else class="wechat-qr-placeholder">{{ statusText }}</div>
    <button v-if="loadError" @click="startWechatLogin" :disabled="isLoading" class="social-btn wechat-btn" type="button">
      重新获取二维码
    </button>
  </div>
</template>

<script lang="ts" setup>
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import QRCode from 'qrcode'
import { getApiErrorMessage, serverApi } from '@/api/serverApi'

const emit = defineEmits<{
  (e: 'login-error', message: string): void
}>()
const props = defineProps<{
  invitationCode?: string
}>()

const { t } = useI18n()
const isLoading = ref(false)
const loadError = ref('')
const qrDataURL = ref('')
const statusText = ref('正在生成微信二维码...')
let pollTimer: ReturnType<typeof setTimeout> | undefined
let stopped = false

const clearPollTimer = () => {
  if (pollTimer) clearTimeout(pollTimer)
  pollTimer = undefined
}

const pollWechatLogin = async (transactionId: string) => {
  if (stopped) return
  try {
    const result = await serverApi.pollWechatQRSession(transactionId)
    if ('authenticated' in result && result.authenticated) {
      statusText.value = '登录成功，正在进入...'
      await serverApi.handleLoginRedirect()
      return
    }
    pollTimer = setTimeout(() => pollWechatLogin(transactionId), 1800)
  } catch (error) {
    loadError.value = getApiErrorMessage(error, t('errors.wechatLoginFailed'))
    statusText.value = loadError.value
    qrDataURL.value = ''
  }
}

const startWechatLogin = async () => {
  clearPollTimer()
  loadError.value = ''
  qrDataURL.value = ''
  statusText.value = '正在生成微信二维码...'
  isLoading.value = true
  try {
    const session = await serverApi.createWechatQRSession(props.invitationCode || '')
    qrDataURL.value = await QRCode.toDataURL(session.url, {
      width: 220,
      margin: 1,
      errorCorrectionLevel: 'M',
    })
    statusText.value = '二维码有效期 10 分钟'
    pollWechatLogin(session.transaction_id)
  } catch (error) {
    loadError.value = getApiErrorMessage(error, t('errors.wechatLoginFailed'))
    statusText.value = loadError.value
    emit('login-error', loadError.value)
  } finally {
    isLoading.value = false
  }
}

onMounted(startWechatLogin)
onBeforeUnmount(() => {
  stopped = true
  clearPollTimer()
})
</script>

<style scoped>
.weixin-login-container {
  width: 100%;
  display: grid;
  gap: 12px;
}

.wechat-qr-panel {
  display: grid;
  justify-items: center;
  gap: 7px;
  color: #173a57;
}

.wechat-qr-code {
  width: 190px;
  height: 190px;
  border: 1px solid #dce8e2;
  border-radius: 8px;
}

.wechat-qr-panel strong {
  font-size: 15px;
}

.wechat-qr-panel span,
.wechat-qr-placeholder {
  color: #718698;
  font-size: 13px;
}

.wechat-qr-placeholder {
  min-height: 92px;
  display: grid;
  place-items: center;
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
