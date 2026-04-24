/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

import axios from 'axios'

// Vite环境变量类型声明
declare interface ImportMeta {
  readonly env: {
    readonly VITE_API_URL: string
  }
}

// 创建 axios 实例
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
  timeout: 10000,
  withCredentials: true
})

// 请求拦截器
api.interceptors.request.use(
  config => {
    // 可以在这里添加认证头等逻辑
    return config
  },
  error => {
    return Promise.reject(error)
  }
)

// 响应拦截器
api.interceptors.response.use(
  response => {
    // 调试日志，可以在生产环境中移除
    console.debug(`API响应 [${response.config.url}]:`, response.data)
    return response
  },
  error => {
    // 处理 401 未授权错误
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('admin_session')
      window.location.href = '/login'
    }

    // 调试日志，记录请求错误
    console.error(`API错误 [${error.config?.url}]:`, error.response?.data || error.message)

    return Promise.reject(error)
  }
)

// ===================== 认证相关接口定义 =====================
export interface LoginCredentials {
  username: string
  password: string
}

export interface UserInfo {
  username: string
  roles: string[]
}

// ===================== 其他接口定义 =====================
export interface StatsData {
  total_users: number
  active_users: number
  inactive_users: number
  locked_users: number
  banned_users: number
  new_today: number
  new_this_week: number
  new_this_month: number
  login_today: number
  login_this_week: number
  login_this_month: number
  email_users: number
  phone_users: number
  social_users: number
  local_users: number
}

export interface User {
  user_id: string
  username?: string
  status: string
  nickname: string
  avatar: string

  last_login: string | null
  login_attempts: number
  last_attempt: string | null
  created_at: string
  updated_at: string
  [key: string]: any
}

export interface UserListResponse {
  users?: User[]
  data?: User[]
  list?: User[]
  total?: number
  total_count?: number
  count?: number
  page?: number
  page_size?: number
  size?: number
  total_page?: number
  pages?: number
  [key: string]: any // 添加索引签名以支持其他可能存在的字段
}

export interface ActivityData {
  date: string
  new_users: number
  active_users: number
  login_attempts: number
  successful_auth: number
  failed_auth: number
}

export interface SessionData {
  id: string
  user_id: string
  ip: string
  user_agent: string
  expires_at: string
  created_at: string
  updated_at: string
}

export interface JWTSessionData {
  key_id: string
  token_type: string
  issued_at: string
  expires_at: string
  ip?: string
  user_agent?: string
}

export interface UserSessionsResponse {
  sessions: SessionData[]
  jwt_sessions: JWTSessionData[]
}

export interface Organization {
  organization_id: string
  slug: string
  name: string
  display_name?: string
  status: 'active' | 'inactive' | string
  metadata_json?: string
  created_at: string
  updated_at: string
}

export interface OrganizationDomain {
  domain: string
  organization_id: string
  verified: boolean
  created_at: string
  updated_at: string
}

export interface OrganizationMembership {
  organization_id: string
  user_id: string
  status: 'active' | 'invited' | 'disabled' | string
  roles: string[]
  username?: string
  nickname?: string
  avatar?: string
  user_status?: string
  created_at: string
  updated_at: string
}

export interface OrganizationGroupMember {
  user_id: string
  username?: string
  nickname?: string
  avatar?: string
  user_status?: string
}

export interface OrganizationGroup {
  group_id: string
  organization_id: string
  provider_type: string
  provider_id?: string
  external_id?: string
  display_name: string
  role_name: string
  editable: boolean
  member_count: number
  members?: OrganizationGroupMember[]
  created_at: string
  updated_at: string
}

export interface OrganizationIdentityProviderConfig {
  issuer?: string
  client_id?: string
  redirect_uri?: string
  scopes?: string[]
  client_secret_configured?: boolean
  idp_metadata_url?: string
  idp_metadata_xml_configured?: boolean
  entity_id?: string
  acs_url?: string
  name_id_format?: string
  email_attribute?: string
  username_attribute?: string
  display_name_attribute?: string
  allow_idp_initiated?: boolean
  default_redirect_uri?: string
  url?: string
  base_dn?: string
  bind_dn?: string
  bind_password_configured?: boolean
  user_filter?: string
  group_base_dn?: string
  group_filter?: string
  group_member_attribute?: string
  group_identifier_attribute?: string
  group_name_attribute?: string
  start_tls?: boolean
  insecure_skip_verify?: boolean
  subject_attribute?: string
}

export interface OrganizationIdentityProvider {
  identity_provider_id: string
  organization_id: string
  provider_type: 'oidc' | 'saml' | string
  name: string
  slug: string
  enabled: boolean
  priority: number
  is_default: boolean
  auto_redirect: boolean
  config: OrganizationIdentityProviderConfig
  created_at: string
  updated_at: string
}

export interface OrganizationListResponse {
  organizations: Organization[]
  total: number
  page: number
  page_size: number
}

export interface PluginInfo {
  id: string
  name: string
  version?: string
  type: string
  source: 'builtin' | 'local' | 'http_action' | string
  entry?: string
  description?: string
  events?: string[]
  permissions?: string[]
  config_schema?: PluginConfigField[]
  config_configured?: boolean
  enabled: boolean
  signature_verified: boolean
  signer_key_id?: string
  package_sha256?: string
  path?: string
}

export interface PluginConfigField {
  key: string
  label?: string
  type?: 'string' | 'text' | 'url' | 'secret' | 'integer' | 'boolean' | 'select' | string
  description?: string
  required?: boolean
  default?: string
  options?: string[]
  sensitive?: boolean
}

export interface PluginConfigView {
  plugin_id: string
  schema: PluginConfigField[]
  values: Record<string, string>
  configured: Record<string, boolean>
}

export interface PluginInstallPreview {
  id: string
  name: string
  version?: string
  type: string
  entry?: string
  description?: string
  events?: string[]
  permissions?: string[]
  config_schema?: PluginConfigField[]
  package_sha256: string
  signature_verified: boolean
  signer_key_id?: string
  exists: boolean
  existing?: PluginInfo
  requires_replace?: boolean
  will_backup?: boolean
  enabled_after_install: boolean
  preserved_config_keys?: string[]
  dropped_config_keys?: string[]
  warnings?: string[]
  requested_replace: boolean
  effective_replace: boolean
  existing_package_sha256?: string
}

export interface CatalogPluginInfo {
  catalog_id: string
  catalog_name?: string
  id: string
  name: string
  version?: string
  type: string
  description?: string
  permissions?: string[]
  download_url: string
  homepage?: string
  package_sha256?: string
  signature_required: boolean
  installed: boolean
  installed_version?: string
  installed_source?: string
  installed_package_sha256?: string
  update_available?: boolean
  update_reason?: string
}

export interface PluginAuditActor {
  id?: string
  ip?: string
  user_agent?: string
}

export interface PluginAuditEntry {
  id: string
  time: string
  action: string
  plugin_id?: string
  plugin_name?: string
  version?: string
  source?: string
  actor?: PluginAuditActor
  success: boolean
  error?: string
  details?: Record<string, string>
}

export interface PluginBackupInfo {
  id: string
  plugin_id: string
  plugin_name?: string
  version?: string
  package_sha256?: string
  source?: string
  reason?: string
  created_at: string
}

// ===================== 其他 API 方法 =====================
class ServerApi {
  /**
 * 登录
 */
  async login(credentials: LoginCredentials): Promise<UserInfo> {
    const response = await api.post<UserInfo>('/login', credentials)
    // save the response to localStorage
    localStorage.setItem('admin_session', JSON.stringify(response.data))
    return response.data
  }

  /**
   * 注销
   */
  async logout(): Promise<void> {
    await api.post('/logout')
  }

  /**
   * 验证会话
   */
  async verifySession(): Promise<UserInfo> {
    const response = await api.get<UserInfo>('/verify')
    localStorage.setItem('admin_session', JSON.stringify(response.data))
    return response.data
  }

  // 获取统计数据
  getStats(): Promise<StatsData> {
    return api.get('/stats').then(res => res.data)
  }

  // 获取用户列表
  getUsers(params: { page?: number, size?: number, status?: string, provider?: string, verified?: string, search?: string }): Promise<UserListResponse> {
    return api.get('/users', { params }).then(res => res.data)
  }

  // 获取活跃情况
  getActivity(days: number): Promise<ActivityData[]> {
    return api.get('/activity', { params: { days } }).then(res => res.data)
  }

  // 获取用户会话列表
  getUserSessions(userId: string): Promise<UserSessionsResponse> {
    return api.get(`/user/${userId}/sessions`).then(res => res.data)
  }

  // 终止用户特定会话
  terminateUserSession(userId: string, sessionId: string): Promise<{ message: string }> {
    return api.delete(`/user/${userId}/sessions/${sessionId}`).then(res => res.data)
  }

  // 终止用户所有会话
  terminateAllUserSessions(userId: string): Promise<{ message: string }> {
    return api.delete(`/user/${userId}/sessions`).then(res => res.data)
  }

  // 获取组织列表
  getOrganizations(params: { page?: number, size?: number, status?: string, search?: string }): Promise<OrganizationListResponse> {
    return api.get('/organizations', { params }).then(res => res.data)
  }

  // 创建组织
  createOrganization(payload: { slug: string, name: string, display_name?: string, status?: string, metadata?: Record<string, any> }): Promise<{ organization: Organization }> {
    return api.post('/organizations', payload).then(res => res.data)
  }

  // 更新组织
  updateOrganization(id: string, payload: { slug: string, name: string, display_name?: string, status?: string, metadata?: Record<string, any> }): Promise<{ organization: Organization }> {
    return api.patch(`/organizations/${id}`, payload).then(res => res.data)
  }

  // 获取组织域名
  getOrganizationDomains(id: string): Promise<{ domains: OrganizationDomain[] }> {
    return api.get(`/organizations/${id}/domains`).then(res => res.data)
  }

  // 添加组织域名
  createOrganizationDomain(id: string, payload: { domain: string, verified?: boolean }): Promise<{ domain: OrganizationDomain }> {
    return api.post(`/organizations/${id}/domains`, payload).then(res => res.data)
  }

  // 更新组织域名
  updateOrganizationDomain(id: string, domain: string, payload: { verified: boolean }): Promise<{ domain: OrganizationDomain }> {
    return api.patch(`/organizations/${id}/domains/${encodeURIComponent(domain)}`, payload).then(res => res.data)
  }

  // 删除组织域名
  deleteOrganizationDomain(id: string, domain: string): Promise<{ message: string }> {
    return api.delete(`/organizations/${id}/domains/${encodeURIComponent(domain)}`).then(res => res.data)
  }

  // 获取组织成员
  getOrganizationMemberships(id: string): Promise<{ memberships: OrganizationMembership[] }> {
    return api.get(`/organizations/${id}/memberships`).then(res => res.data)
  }

  // 添加/更新组织成员
  upsertOrganizationMembership(id: string, payload: { user_id: string, status?: string, roles?: string[] }): Promise<{ membership: OrganizationMembership }> {
    return api.post(`/organizations/${id}/memberships`, payload).then(res => res.data)
  }

  // 更新组织成员
  updateOrganizationMembership(id: string, userId: string, payload: { status?: string, roles?: string[] }): Promise<{ membership: OrganizationMembership }> {
    return api.patch(`/organizations/${id}/memberships/${encodeURIComponent(userId)}`, payload).then(res => res.data)
  }

  // 删除组织成员
  deleteOrganizationMembership(id: string, userId: string): Promise<{ message: string }> {
    return api.delete(`/organizations/${id}/memberships/${encodeURIComponent(userId)}`).then(res => res.data)
  }

  // 获取组织组列表
  getOrganizationGroups(id: string): Promise<{ groups: OrganizationGroup[] }> {
    return api.get(`/organizations/${id}/groups`).then(res => res.data)
  }

  // 获取组织组详情
  getOrganizationGroup(id: string, groupId: string): Promise<{ group: OrganizationGroup }> {
    return api.get(`/organizations/${id}/groups/${encodeURIComponent(groupId)}`).then(res => res.data)
  }

  // 创建组织组
  createOrganizationGroup(id: string, payload: {
    display_name: string
    role_name?: string
    user_ids?: string[]
  }): Promise<{ group: OrganizationGroup }> {
    return api.post(`/organizations/${id}/groups`, payload).then(res => res.data)
  }

  // 更新组织组
  updateOrganizationGroup(id: string, groupId: string, payload: {
    display_name: string
    role_name?: string
    user_ids?: string[]
  }): Promise<{ group: OrganizationGroup }> {
    return api.patch(`/organizations/${id}/groups/${encodeURIComponent(groupId)}`, payload).then(res => res.data)
  }

  // 删除组织组
  deleteOrganizationGroup(id: string, groupId: string): Promise<{ message: string }> {
    return api.delete(`/organizations/${id}/groups/${encodeURIComponent(groupId)}`).then(res => res.data)
  }

  // 获取组织身份提供方
  getOrganizationIdentityProviders(id: string): Promise<{ identity_providers: OrganizationIdentityProvider[] }> {
    return api.get(`/organizations/${id}/identity-providers`).then(res => res.data)
  }

  // 创建组织身份提供方
  createOrganizationIdentityProvider(id: string, payload: {
    provider_type?: string
    name: string
    slug: string
    enabled?: boolean
    priority?: number
    is_default?: boolean
    auto_redirect?: boolean
    issuer?: string
    client_id?: string
    client_secret?: string
    redirect_uri?: string
    scopes?: string[]
    idp_metadata_url?: string
    idp_metadata_xml?: string
    entity_id?: string
    acs_url?: string
    name_id_format?: string
    url?: string
    base_dn?: string
    bind_dn?: string
    bind_password?: string
    user_filter?: string
    start_tls?: boolean
    insecure_skip_verify?: boolean
    subject_attribute?: string
    email_attribute?: string
    username_attribute?: string
    display_name_attribute?: string
    allow_idp_initiated?: boolean
    default_redirect_uri?: string
  }): Promise<{ identity_provider: OrganizationIdentityProvider }> {
    return api.post(`/organizations/${id}/identity-providers`, payload).then(res => res.data)
  }

  // 更新组织身份提供方
  updateOrganizationIdentityProvider(id: string, providerId: string, payload: {
    provider_type?: string
    name: string
    slug: string
    enabled?: boolean
    priority?: number
    is_default?: boolean
    auto_redirect?: boolean
    issuer?: string
    client_id?: string
    client_secret?: string
    redirect_uri?: string
    scopes?: string[]
    idp_metadata_url?: string
    idp_metadata_xml?: string
    entity_id?: string
    acs_url?: string
    name_id_format?: string
    url?: string
    base_dn?: string
    bind_dn?: string
    bind_password?: string
    user_filter?: string
    start_tls?: boolean
    insecure_skip_verify?: boolean
    subject_attribute?: string
    email_attribute?: string
    username_attribute?: string
    display_name_attribute?: string
    allow_idp_initiated?: boolean
    default_redirect_uri?: string
  }): Promise<{ identity_provider: OrganizationIdentityProvider }> {
    return api.patch(`/organizations/${id}/identity-providers/${encodeURIComponent(providerId)}`, payload).then(res => res.data)
  }

  // 删除组织身份提供方
  deleteOrganizationIdentityProvider(id: string, providerId: string): Promise<{ message: string }> {
    return api.delete(`/organizations/${id}/identity-providers/${encodeURIComponent(providerId)}`).then(res => res.data)
  }

  // 获取插件列表
  getPlugins(): Promise<{ plugins: PluginInfo[] }> {
    return api.get('/plugins').then(res => res.data)
  }

  // 获取远程插件目录
  getPluginCatalog(): Promise<{ plugins: CatalogPluginInfo[] }> {
    return api.get('/plugins/catalog').then(res => res.data)
  }

  // 获取插件操作审计
  getPluginAudit(limit = 100): Promise<{ audit: PluginAuditEntry[] }> {
    return api.get('/plugins/audit', { params: { limit } }).then(res => res.data)
  }

  // 获取插件回滚快照
  getPluginBackups(limit = 100): Promise<{ backups: PluginBackupInfo[] }> {
    return api.get('/plugins/backups', { params: { limit } }).then(res => res.data)
  }

  // 从回滚快照恢复插件
  restorePluginBackup(backupId: string): Promise<{ message: string, plugin: PluginInfo }> {
    return api.post('/plugins/restore', { backup_id: backupId }).then(res => res.data)
  }

  // 获取插件配置
  getPluginConfig(id: string): Promise<PluginConfigView> {
    return api.get(`/plugins/${id}/config`).then(res => res.data)
  }

  // 更新插件配置
  updatePluginConfig(id: string, config: Record<string, string>): Promise<{ message: string, config: PluginConfigView }> {
    return api.patch(`/plugins/${id}/config`, { config }).then(res => res.data)
  }

  // 预览上传插件
  previewPlugin(file: File, replace = false): Promise<{ preview: PluginInstallPreview }> {
    const form = new FormData()
    form.append('package', file)
    form.append('replace', String(replace))
    return api.post('/plugins/preview', form, {
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    }).then(res => res.data)
  }

  // 上传安装插件
  installPlugin(file: File, replace = false): Promise<{ message: string, plugin: PluginInfo }> {
    const form = new FormData()
    form.append('package', file)
    form.append('replace', String(replace))
    return api.post('/plugins/install', form, {
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    }).then(res => res.data)
  }

  // 通过 URL 安装插件
  installPluginFromURL(payload: { url: string, replace?: boolean, package_sha256?: string, source?: string }): Promise<{ message: string, plugin: PluginInfo }> {
    return api.post('/plugins/install-url', payload).then(res => res.data)
  }

  // 通过 catalog 安装插件
  installPluginFromCatalog(payload: { catalog_id: string, plugin_id: string, replace?: boolean }): Promise<{ message: string, plugin: PluginInfo }> {
    return api.post('/plugins/install-catalog', payload).then(res => res.data)
  }

  // 启用/禁用插件
  updatePlugin(id: string, enabled: boolean): Promise<{ message: string, plugin: PluginInfo }> {
    return api.patch(`/plugins/${id}`, { enabled }).then(res => res.data)
  }

  // 删除插件
  deletePlugin(id: string): Promise<{ message: string }> {
    return api.delete(`/plugins/${id}`).then(res => res.data)
  }
}

export const serverApi = new ServerApi()
