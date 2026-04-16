/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

import axios from 'axios'

// API响应类型定义
interface AuthResponse {
    user_id: string
    nickname?: string
    avatar?: string
    authenticated?: boolean
    expires_at?: string
    message?: string
}

interface NestedAuthResponse {
    user?: {
        user_id: string
        nickname?: string
        avatar?: string
    }
    user_id?: string
    nickname?: string
    avatar?: string
}

export type AuthProvider = 'account' | 'email' | 'google' | 'weixin' | 'phone' | 'weixin_mini'

type ApiErrorPayload = {
    error?: string | {
        message?: string
        details?: string
    }
    message?: string
    details?: string
}

function formatApiErrorValue(value: unknown): string | undefined {
    if (typeof value === 'string' && value) {
        return value
    }

    if (!value || typeof value !== 'object') {
        return undefined
    }

    const payload = value as { message?: unknown; details?: unknown }
    const message = typeof payload.message === 'string' ? payload.message : ''
    const details = typeof payload.details === 'string' ? payload.details : ''

    if (message && details && !message.includes(details)) {
        return `${message}: ${details}`
    }

    return message || details || undefined
}

export function getApiErrorMessage(error: unknown, fallback: string): string {
    if (axios.isAxiosError<ApiErrorPayload>(error)) {
        const data = error.response?.data
        const responseMessage = formatApiErrorValue(data?.error) || formatApiErrorValue(data)
        if (responseMessage) {
            return responseMessage
        }
    }

    if (error instanceof Error && error.message) {
        return error.message
    }

    return fallback
}


// 响应拦截器：处理重定向响应
// axios.interceptors.response.use(
//     (response) => {
//         return response
//     },
//     (error) => {
//         // 处理307重定向或其他重定向状态码
//         if (error.response && [301, 302, 307, 308].includes(error.response.status)) {
//             const redirectUrl = error.response.headers.location
//             if (redirectUrl) {
//                 // 如果是登录重定向，直接跳转到新地址
//                 window.location.href = redirectUrl
//                 return Promise.resolve({ redirected: true, url: redirectUrl })
//             }
//         }
//         return Promise.reject(error)
//     }
// )

class ServerApi {

    clientId: string = ''
    redirectUri: string = ''

    clearStoredAuth() {
        localStorage.removeItem('token')
        localStorage.removeItem('user')
        localStorage.removeItem('avatar')
        localStorage.removeItem('nickname')
        localStorage.removeItem('userId')
        delete axios.defaults.headers.common['Authorization']
    }

    isOIDCFlow(): boolean {
        if (!this.redirectUri) {
            return false
        }

        try {
            const url = new URL(this.redirectUri, window.location.origin)
            return url.pathname === '/oauth2/authorize' || url.pathname.endsWith('/oauth2/authorize')
        } catch {
            return false
        }
    }

    private normalizeAuthResponse(response: AuthResponse | NestedAuthResponse): AuthResponse {
        if ('user' in response && response.user) {
            return {
                user_id: response.user.user_id,
                nickname: response.user.nickname || '',
                avatar: response.user.avatar || '',
            }
        }

        return {
            user_id: response.user_id || '',
            nickname: response.nickname || '',
            avatar: response.avatar || '',
        }
    }

    updateUserInfo(response: AuthResponse | NestedAuthResponse) {
        this.normalizeAuthResponse(response)
        this.clearStoredAuth()

        this.handleLoginRedirect() // 重定向到应用
    }

    updateAuthData(clientId: string, redirectUri?: string) {
        serverApi.clientId = clientId
        if (redirectUri) {
            serverApi.redirectUri = redirectUri
            sessionStorage.setItem(clientId, redirectUri)
        } else {
            serverApi.redirectUri = sessionStorage.getItem(clientId) || ''
        }
    }

    // 获取支持的登录方式
    async fetchSupportedProviders(): Promise<{ providers: AuthProvider[] }> {
        const response = await axios.get('/providers')
        return response.data
    }

    // 账号密码登录
    async login(username: string, password: string): Promise<AuthResponse> {
        const response = await axios.post('/account/login', { username, password, client_id: this.clientId, redirect_uri: this.redirectUri })
        this.updateUserInfo(response.data)
        return response.data
    }

    // 账号注册
    async registerAccount(username: string, password: string): Promise<AuthResponse> {
        const response = await axios.post('/account/register', { username, password, client_id: this.clientId, redirect_uri: this.redirectUri })
        this.updateUserInfo(response.data)
        return response.data
    }

    // 获取当前用户信息
    async fetchCurrentUser() {
        const response = await axios.get('/user')
        return response.data
    }

    async fetchBrowserSession() {
        const response = await axios.get('/browser-session')
        return response.data
    }

    // 登出
    async logout() {
        this.clearStoredAuth()
        return axios.post('/logout')
    }

    // Google相关
    async getGoogleClientId() {
        const response = await axios.get('/google/client_id')
        return response.data.client_id
    }

    async handleGoogleCallback(credential: string): Promise<AuthResponse> {
        const response = await axios.post('/google/callback', { credential, client_id: this.clientId, redirect_uri: this.redirectUri })
        this.updateUserInfo(response.data)
        return response.data
    }

    // 微信相关
    async getWechatAuthUrl(): Promise<string> {
        const response = await axios.get('/weixin/url')
        return response.data.url
    }

    async handleWeixinCallback(code: string, state: string): Promise<AuthResponse> {
        const response = await axios.get('/weixin/callback', { params: { code, state, client_id: this.clientId, redirect_uri: this.redirectUri } })
        this.updateUserInfo(response.data)
        return response.data
    }

    // 当前已经登陆，直接回调
    async handleLoginRedirect(): Promise<void> {
        if (!this.redirectUri) {
            return
        }

        window.location.href = this.redirectUri
    }

    // 手机相关
    async sendPhoneLoginCode(phone: string) {
        const response = await axios.post('/phone/send-login-code', { phone })
        return response.data
    }

    async phoneLogin(phone: string, password: string): Promise<AuthResponse> {
        const response = await axios.post('/phone/login', { phone, password, client_id: this.clientId, redirect_uri: this.redirectUri })
        const authResponse = this.normalizeAuthResponse(response.data)
        this.updateUserInfo(authResponse)
        return authResponse
    }

    async phoneCodeLogin(phone: string, code: string): Promise<AuthResponse> {
        const response = await axios.post('/phone/code-login', { phone, code, client_id: this.clientId, redirect_uri: this.redirectUri })
        const authResponse = this.normalizeAuthResponse(response.data)
        this.updateUserInfo(authResponse)
        return authResponse
    }

    async startPhoneRegistration(phone: string, password: string, nickname: string) {
        const response = await axios.post('/phone/preregister', { phone, password, nickname })
        return response.data
    }

    async resendPhoneRegistrationCode(phone: string) {
        const response = await axios.post('/phone/resend-verification', { phone })
        return response.data
    }

    async completePhoneRegistration(phone: string, code: string): Promise<AuthResponse> {
        const response = await axios.post('/phone/verify-register', { phone, code })
        const authResponse = this.normalizeAuthResponse(response.data)
        this.updateUserInfo(authResponse)
        return authResponse
    }

    async initiatePhonePasswordReset(phone: string) {
        const response = await axios.post('/phone/reset-password/init', { phone })
        return response.data
    }

    async completePhonePasswordReset(phone: string, code: string, newPassword: string) {
        const response = await axios.post('/phone/reset-password/complete', {
            phone,
            code,
            new_password: newPassword
        })
        return response.data
    }

    // 邮箱相关
    async emailLogin(email: string, password: string): Promise<AuthResponse> {
        const response = await axios.post('/email/login', { email, password, client_id: this.clientId, redirect_uri: this.redirectUri })
        const authResponse = this.normalizeAuthResponse(response.data)
        this.updateUserInfo(authResponse)
        return authResponse
    }
}

export const serverApi = new ServerApi()
