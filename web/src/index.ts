/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import axios from 'axios'
import i18n, { getPreferredLanguage, setLanguage } from './locales'
import { context } from './context'
import { serverApi } from './api/serverApi'

// 设置 axios 默认值
axios.defaults.baseURL = import.meta.env.VITE_API_URL

const app = createApp(App)
const pinia = createPinia()
app.use(pinia)
app.use(router)
app.use(i18n)

// 设置语言
const preferredLanguage = getPreferredLanguage()
setLanguage(preferredLanguage)
document.documentElement.setAttribute('lang', preferredLanguage)

// 初始化认证状态
const initAuth = async () => {
  const urlParams = new URLSearchParams(window.location.search)
  const clientId = urlParams.get('client_id') || ''
  const redirectUri = urlParams.get('redirect_uri') || urlParams.get('redirect_url') || undefined
  serverApi.updateAuthData(clientId, redirectUri)
  serverApi.clearStoredAuth()

  try {
    const session = await serverApi.fetchBrowserSession()
    context.setAuthenticated(!!session?.authenticated)
    if (session?.authenticated && serverApi.isEntryRoute()) {
      await serverApi.handleLoginRedirect()
      return
    }
  } catch (error) {
    context.setAuthenticated(false)
    console.error('获取浏览器会话失败:', error)
  }

  // 获取支持的登录方式
  try {
    await context.fetchSupportedProviders()
  } catch (error) {
    console.error('获取支持的登录方式失败:', error)
  }

}

// 挂载应用前初始化认证
initAuth().finally(() => {
  app.mount('#app')
}) 
