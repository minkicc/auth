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

// 从本地存储中获取 token 并设置 axios 默认 headers
const token = localStorage.getItem('token')
if (token) {
  axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
}

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

  if (serverApi.isOIDCFlow()) {
    serverApi.clearStoredAuth()
    try {
      const session = await serverApi.fetchBrowserSession()
      if (session?.authenticated) {
        await serverApi.handleLoginRedirect()
      }
    } catch (error) {
      console.error('获取浏览器会话失败:', error)
    }
  } else if (token) {
    // 如果有token，尝试获取当前用户信息
    try {
      const user = await serverApi.fetchCurrentUser()
      // 当前已经登陆，直接回调
      if (user) await serverApi.handleLoginRedirect()
    } catch (error) {
      console.error('获取用户信息失败:', error)
      serverApi.clearStoredAuth()
    }
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
