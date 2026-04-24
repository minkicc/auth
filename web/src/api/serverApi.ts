/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

import axios from 'axios'

// API响应类型定义
interface AuthResponse {
    user_id: string
    username?: string
    nickname?: string
    avatar?: string
    authenticated?: boolean
    expires_at?: string
    message?: string
}

interface NestedAuthResponse {
    user?: {
        user_id: string
        username?: string
        nickname?: string
        avatar?: string
    }
    user_id?: string
    username?: string
    nickname?: string
    avatar?: string
}

export type AuthProvider = 'account' | 'email' | 'google' | 'weixin' | 'phone' | 'weixin_mini' | 'enterprise_oidc'

export interface EnterpriseOIDCProvider {
    slug: string
    name: string
    organization_id?: string
}

export type EnterpriseOIDCDiscoveryStatus =
    | 'matched'
    | 'domain_not_found'
    | 'organization_not_found'
    | 'organization_inactive'
    | 'no_provider'

export interface EnterpriseOIDCDiscoveryResponse {
    status: EnterpriseOIDCDiscoveryStatus
    email?: string
    domain?: string
    organization_id?: string
    organization_slug?: string
    organization_name?: string
    organization_display_name?: string
    providers: EnterpriseOIDCProvider[]
}

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
    loginHint: string = ''
    domainHint: string = ''

    private redirectStorageKey(clientId: string): string {
        return `mkauth:redirect:${clientId}`
    }

    private loginHintStorageKey(clientId: string): string {
        return `mkauth:login_hint:${clientId}`
    }

    private domainHintStorageKey(clientId: string): string {
        return `mkauth:domain_hint:${clientId}`
    }

    private appBaseURL(): URL {
        const base = import.meta.env.VITE_BASE_URL || import.meta.env.BASE_URL || '/'
        return new URL(base, window.location.origin)
    }

    private normalizePath(path: string): string {
        const normalized = path.replace(/\/+$/, '')
        return normalized || '/'
    }

    private buildAppURL(path: string): string {
        const normalizedPath = path.replace(/^\/+/, '')
        return new URL(normalizedPath, this.appBaseURL()).toString()
    }

    private buildApiURL(path: string, params?: URLSearchParams): string {
        const baseURL = axios.defaults.baseURL || ''
        const normalizedBase = baseURL.replace(/\/+$/, '')
        const normalizedPath = path.startsWith('/') ? path : `/${path}`
        const url = new URL(`${normalizedBase}${normalizedPath}`, window.location.origin)
        if (params) {
            params.forEach((value, key) => url.searchParams.set(key, value))
        }
        return url.toString()
    }

    private sanitizeRedirectUri(redirectUri?: string | null): string {
        const rawRedirectUri = typeof redirectUri === 'string' ? redirectUri.trim() : ''
        if (!rawRedirectUri) {
            return ''
        }

        try {
            const url = new URL(rawRedirectUri, window.location.origin)
            const normalizedPath = this.normalizePath(url.pathname)
            const isAuthorizePath = normalizedPath === '/oauth2/authorize' || normalizedPath.endsWith('/oauth2/authorize')
            if (url.origin !== window.location.origin || !isAuthorizePath) {
                return ''
            }
            return url.toString()
        } catch {
            return ''
        }
    }

    private routePath(path: string): string {
        return this.normalizePath(new URL(path.replace(/^\/+/, ''), this.appBaseURL()).pathname)
    }

    private sanitizeLoginHint(loginHint?: string | null): string {
        return typeof loginHint === 'string' ? loginHint.trim() : ''
    }

    private sanitizeDomainHint(domainHint?: string | null): string {
        return typeof domainHint === 'string' ? domainHint.trim().toLowerCase() : ''
    }

    private extractLoginHintFromRedirectUri(redirectUri?: string | null): string {
        const sanitizedRedirectUri = this.sanitizeRedirectUri(redirectUri)
        if (!sanitizedRedirectUri) {
            return ''
        }

        try {
            const url = new URL(sanitizedRedirectUri)
            const normalizedPath = this.normalizePath(url.pathname)
            const isAuthorizePath = normalizedPath === '/oauth2/authorize' || normalizedPath.endsWith('/oauth2/authorize')
            if (!isAuthorizePath) {
                return ''
            }
            return this.sanitizeLoginHint(url.searchParams.get('login_hint'))
        } catch {
            return ''
        }
    }

    private extractDomainHintFromRedirectUri(redirectUri?: string | null): string {
        const sanitizedRedirectUri = this.sanitizeRedirectUri(redirectUri)
        if (!sanitizedRedirectUri) {
            return ''
        }

        try {
            const url = new URL(sanitizedRedirectUri)
            const normalizedPath = this.normalizePath(url.pathname)
            const isAuthorizePath = normalizedPath === '/oauth2/authorize' || normalizedPath.endsWith('/oauth2/authorize')
            if (!isAuthorizePath) {
                return ''
            }
            return this.sanitizeDomainHint(url.searchParams.get('domain_hint'))
        } catch {
            return ''
        }
    }

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
        return this.redirectUri === this.sanitizeRedirectUri(this.redirectUri)
    }

    private normalizeAuthResponse(response: AuthResponse | NestedAuthResponse): AuthResponse {
        if ('user' in response && response.user) {
            return {
                user_id: response.user.user_id,
                username: response.user.username || '',
                nickname: response.user.nickname || '',
                avatar: response.user.avatar || '',
            }
        }

        return {
            user_id: response.user_id || '',
            username: response.username || '',
            nickname: response.nickname || '',
            avatar: response.avatar || '',
        }
    }

    updateUserInfo(response: AuthResponse | NestedAuthResponse) {
        this.normalizeAuthResponse(response)
        this.clearStoredAuth()

        this.handleLoginRedirect() // 重定向到应用
    }

    updateAuthData(clientId: string, redirectUri?: string, loginHint?: string, domainHint?: string) {
        serverApi.clientId = clientId
        if (redirectUri !== undefined || loginHint !== undefined || domainHint !== undefined) {
            const sanitizedRedirectUri = this.sanitizeRedirectUri(redirectUri)
            const sanitizedLoginHint = this.sanitizeLoginHint(loginHint) || this.extractLoginHintFromRedirectUri(sanitizedRedirectUri)
            const sanitizedDomainHint = this.sanitizeDomainHint(domainHint) || this.extractDomainHintFromRedirectUri(sanitizedRedirectUri)
            serverApi.redirectUri = sanitizedRedirectUri
            serverApi.loginHint = sanitizedLoginHint
            serverApi.domainHint = sanitizedDomainHint
            if (clientId) {
                if (sanitizedRedirectUri) {
                    sessionStorage.setItem(this.redirectStorageKey(clientId), sanitizedRedirectUri)
                } else {
                    sessionStorage.removeItem(this.redirectStorageKey(clientId))
                }
                if (sanitizedLoginHint) {
                    sessionStorage.setItem(this.loginHintStorageKey(clientId), sanitizedLoginHint)
                } else {
                    sessionStorage.removeItem(this.loginHintStorageKey(clientId))
                }
                if (sanitizedDomainHint) {
                    sessionStorage.setItem(this.domainHintStorageKey(clientId), sanitizedDomainHint)
                } else {
                    sessionStorage.removeItem(this.domainHintStorageKey(clientId))
                }
            }
            return
        }

        if (clientId) {
            const storedRedirectUri = sessionStorage.getItem(this.redirectStorageKey(clientId)) || ''
            const storedLoginHint = sessionStorage.getItem(this.loginHintStorageKey(clientId)) || ''
            const storedDomainHint = sessionStorage.getItem(this.domainHintStorageKey(clientId)) || ''
            const sanitizedRedirectUri = this.sanitizeRedirectUri(storedRedirectUri)
            const sanitizedLoginHint = this.sanitizeLoginHint(storedLoginHint) || this.extractLoginHintFromRedirectUri(sanitizedRedirectUri)
            const sanitizedDomainHint = this.sanitizeDomainHint(storedDomainHint) || this.extractDomainHintFromRedirectUri(sanitizedRedirectUri)
            serverApi.redirectUri = sanitizedRedirectUri
            serverApi.loginHint = sanitizedLoginHint
            serverApi.domainHint = sanitizedDomainHint
            if (!sanitizedRedirectUri) {
                sessionStorage.removeItem(this.redirectStorageKey(clientId))
            }
            if (!sanitizedLoginHint) {
                sessionStorage.removeItem(this.loginHintStorageKey(clientId))
            }
            if (!sanitizedDomainHint) {
                sessionStorage.removeItem(this.domainHintStorageKey(clientId))
            }
            return
        }

        serverApi.redirectUri = ''
        serverApi.loginHint = ''
        serverApi.domainHint = ''
    }

    hasBusinessConnection(): boolean {
        return this.isOIDCFlow()
    }

    getDefaultAuthenticatedURL(): string {
        return this.buildAppURL('/profile')
    }

    isEntryRoute(pathname: string = window.location.pathname): boolean {
        const currentPath = this.normalizePath(pathname)
        const rootPath = this.normalizePath(this.appBaseURL().pathname)
        return currentPath === rootPath || currentPath === this.routePath('/login')
    }

    // 获取支持的登录方式
    async fetchSupportedProviders(): Promise<{ providers: AuthProvider[] }> {
        const response = await axios.get('/providers')
        return response.data
    }

    async fetchEnterpriseOIDCProviders(): Promise<EnterpriseOIDCProvider[]> {
        const response = await axios.get('/enterprise/oidc/providers')
        return response.data.providers || []
    }

    async discoverEnterpriseOIDCByEmail(email: string): Promise<EnterpriseOIDCDiscoveryResponse> {
        const response = await axios.get('/enterprise/oidc/discover', {
            params: { email }
        })
        const data = response.data || {}
        return {
            ...data,
            providers: data.providers || []
        }
    }

    async discoverEnterpriseOIDCByDomain(domain: string): Promise<EnterpriseOIDCDiscoveryResponse> {
        const response = await axios.get('/enterprise/oidc/discover', {
            params: { domain }
        })
        const data = response.data || {}
        return {
            ...data,
            providers: data.providers || []
        }
    }

    startEnterpriseOIDCLogin(slug: string): void {
        const params = new URLSearchParams()
        params.set('return_uri', this.isOIDCFlow() ? this.redirectUri : this.routePath('/profile'))
        window.location.href = this.buildApiURL(`/enterprise/oidc/${encodeURIComponent(slug)}/login`, params)
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
        window.location.href = this.isOIDCFlow() ? this.redirectUri : this.getDefaultAuthenticatedURL()
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
