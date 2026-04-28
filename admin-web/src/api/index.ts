/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

import axios from 'axios'

function normalizeBasePath(path: string | undefined): string {
  const trimmed = (path || '').trim()
  if (!trimmed) return '/'
  const withLeadingSlash = trimmed.startsWith('/') ? trimmed : `/${trimmed}`
  return withLeadingSlash.endsWith('/') ? withLeadingSlash : `${withLeadingSlash}/`
}

function buildAdminLoginPath(): string {
  return new URL('login', window.location.origin + normalizeBasePath(import.meta.env.VITE_BASE_URL)).pathname
}

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
      const loginPath = buildAdminLoginPath()
      if (typeof window !== 'undefined' && window.location.pathname !== loginPath) {
        window.location.href = loginPath
      }
    }

    // 调试日志，记录请求错误
    console.error(`API错误 [${error.config?.url}]:`, error.response?.data || error.message)

    return Promise.reject(error)
  }
)

// ===================== 认证相关接口定义 =====================
export interface UserInfo {
  user_id: string
  username: string
  nickname?: string
  roles: string[]
  sources?: string[]
  global_admin?: boolean
  organization_admin_ids?: string[]
  profile_url?: string
}

export interface AdminPrincipal {
  user_id: string
  username?: string
  nickname?: string
  status?: string
  sources: string[]
  editable: boolean
  created_at?: string
  updated_at?: string
}

export interface AdminPrincipalListResponse {
  admins: AdminPrincipal[]
  total: number
}

export interface OrganizationAdminPrincipal {
  organization_id: string
  user_id: string
  username?: string
  nickname?: string
  status?: string
  created_at?: string
  updated_at?: string
}

export interface OrganizationAdminPrincipalListResponse {
  admins: OrganizationAdminPrincipal[]
  total: number
}

export interface AdminInvitation {
  invitation_id: string
  name: string
  status: string
  scope: string
  organization_id?: string
  client_id?: string
  max_uses: number
  used_count: number
  expires_at?: string
  allowed_email?: string
  allowed_domain?: string
  default_roles_json?: string
  default_groups_json?: string
  created_by?: string
  created_at?: string
  updated_at?: string
}

export interface AdminInvitationListResponse {
  invitations: AdminInvitation[]
  total: number
}

export interface AdminInvitationCreatePayload {
  name: string
  code?: string
  scope?: string
  organization_id?: string
  client_id?: string
  max_uses?: number
  expires_at?: string
  allowed_email?: string
  allowed_domain?: string
  default_roles?: string[]
  default_groups?: string[]
}

export interface AdminInvitationCreateResponse {
  invitation: AdminInvitation
  code: string
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

export interface OrganizationRoleBinding {
  binding_id: string
  organization_id: string
  role_id: string
  subject_type: 'membership' | 'group' | string
  subject_id: string
  subject_label?: string
  subject_secondary?: string
  created_at: string
  updated_at: string
}

export interface OrganizationRole {
  role_id: string
  organization_id: string
  name: string
  slug: string
  description?: string
  enabled: boolean
  permissions: string[]
  binding_count: number
  bindings?: OrganizationRoleBinding[]
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

export interface OIDCClient {
  name?: string
  client_id: string
  grant_types?: string[]
  service_account_enabled?: boolean
  service_account_subject?: string
  redirect_uris: string[]
  scopes?: string[]
  public: boolean
  require_pkce: boolean
  require_organization: boolean
  allowed_organizations?: string[]
  required_org_roles?: string[]
  required_org_roles_all?: string[]
  required_org_groups?: string[]
  required_org_groups_all?: string[]
  scope_policies?: Record<string, OIDCOrganizationPolicy>
  enabled: boolean
  editable: boolean
  source: 'config' | 'database' | string
  client_secret_configured: boolean
  created_at?: string
  updated_at?: string
}

export interface OIDCOrganizationPolicy {
  require_organization?: boolean
  allowed_organizations?: string[]
  required_org_roles?: string[]
  required_org_roles_all?: string[]
  required_org_groups?: string[]
  required_org_groups_all?: string[]
}

export interface AdminClaimMapper {
  mapper_id: string
  name: string
  description?: string
  enabled: boolean
  claim: string
  value?: string
  value_from?: string
  events: string[]
  clients?: string[]
  organizations?: string[]
  created_at: string
  updated_at: string
}

export interface SecuritySecretsStatus {
  enabled: boolean
  fallback_key_count: number
  managed_oidc_client_count: number
  managed_identity_provider_count: number
}

export interface SecuritySecretsResealResult {
  oidc_clients: number
  identity_providers: number
  oidc_providers: number
  saml_providers: number
  ldap_providers: number
}

export interface SecurityAuditActor {
  id?: string
  ip?: string
  user_agent?: string
}

export interface SecurityAuditEntry {
  id: string
  time: string
  action: string
  actor?: SecurityAuditActor
  success: boolean
  error?: string
  details?: Record<string, string>
}

export interface SecurityAuditQuery {
  page?: number
  size?: number
  action?: string
  resource_type?: string
  client_id?: string
  provider_id?: string
  organization_id?: string
  actor_id?: string
  query?: string
  time_from?: string
  time_to?: string
  success?: boolean
}

export interface SecurityAuditListResponse {
  audit: SecurityAuditEntry[]
  total: number
  page: number
  size: number
}

export interface SecurityAuditExportJob {
  job_id: string
  status: 'pending' | 'running' | 'completed' | 'failed' | string
  filename: string
  content_type: string
  row_count: number
  total_count: number
  truncated: boolean
  error?: string
  created_at: string
  updated_at: string
  completed_at?: string
  download_ready: boolean
  query?: SecurityAuditQuery
  actor?: SecurityAuditActor
}

export interface SecurityAuditExportJobQuery {
  page?: number
  size?: number
  status?: string
  organization_id?: string
}

export interface SecurityAuditExportJobListResponse {
  jobs: SecurityAuditExportJob[]
  total: number
  page: number
  size: number
}

export interface SecurityAuditExportJobCleanupRequest {
  organization_id?: string
  older_than_days?: number
  status?: string
}

export interface SecurityAuditExportJobCleanupResult {
  deleted: number
  older_than_days: number
  status: string
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
  claim_mappings?: PluginClaimMapping[]
  config_configured?: boolean
  enabled: boolean
  signature_verified: boolean
  signer_key_id?: string
  package_sha256?: string
  path?: string
}

export interface PluginClaimMapping {
  claim: string
  value?: string
  value_from?: string
  clients?: string[]
  organizations?: string[]
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
  claim_mappings?: PluginClaimMapping[]
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
 * 使用当前主站登录会话引导后台会话
 */
  async bootstrapSession(): Promise<UserInfo> {
    const response = await api.post<UserInfo>('/session/bootstrap')
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

  listAdmins(): Promise<AdminPrincipalListResponse> {
    return api.get('/admins').then(res => res.data)
  }

  createAdmin(payload: { user_id?: string; username?: string; user_ref?: string }): Promise<{ admin: AdminPrincipal }> {
    return api.post('/admins', payload).then(res => res.data)
  }

  deleteAdmin(userId: string): Promise<{ message: string }> {
    return api.delete(`/admins/${encodeURIComponent(userId)}`).then(res => res.data)
  }

  listInvitations(): Promise<AdminInvitationListResponse> {
    return api.get('/invitations').then(res => res.data)
  }

  createInvitation(payload: AdminInvitationCreatePayload): Promise<AdminInvitationCreateResponse> {
    return api.post('/invitations', payload).then(res => res.data)
  }

  disableInvitation(invitationId: string): Promise<{ message: string }> {
    return api.delete(`/invitations/${encodeURIComponent(invitationId)}`).then(res => res.data)
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

  // 获取单个组织
  getOrganization(id: string): Promise<{ organization: Organization }> {
    return api.get(`/organizations/${id}`).then(res => res.data)
  }

  // 更新组织
  updateOrganization(id: string, payload: { slug: string, name: string, display_name?: string, status?: string, metadata?: Record<string, any> }): Promise<{ organization: Organization }> {
    return api.patch(`/organizations/${id}`, payload).then(res => res.data)
  }

  // 获取组织域名
  getOrganizationDomains(id: string): Promise<{ domains: OrganizationDomain[] }> {
    return api.get(`/organizations/${id}/domains`).then(res => res.data)
  }

  // 获取组织管理员
  getOrganizationAdmins(id: string): Promise<OrganizationAdminPrincipalListResponse> {
    return api.get(`/organizations/${id}/admins`).then(res => res.data)
  }

  // 添加组织管理员
  createOrganizationAdmin(id: string, payload: { user_id?: string; username?: string; user_ref?: string }): Promise<{ admin: OrganizationAdminPrincipal }> {
    return api.post(`/organizations/${id}/admins`, payload).then(res => res.data)
  }

  // 删除组织管理员
  deleteOrganizationAdmin(id: string, userId: string): Promise<{ message: string }> {
    return api.delete(`/organizations/${id}/admins/${encodeURIComponent(userId)}`).then(res => res.data)
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

  // 获取组织角色列表
  getOrganizationRoles(id: string): Promise<{ roles: OrganizationRole[] }> {
    return api.get(`/organizations/${id}/roles`).then(res => res.data)
  }

  // 创建组织角色
  createOrganizationRole(id: string, payload: {
    name: string
    slug?: string
    description?: string
    enabled?: boolean
    permissions?: string[]
  }): Promise<{ role: OrganizationRole }> {
    return api.post(`/organizations/${id}/roles`, payload).then(res => res.data)
  }

  // 更新组织角色
  updateOrganizationRole(id: string, roleId: string, payload: {
    name: string
    slug?: string
    description?: string
    enabled?: boolean
    permissions?: string[]
  }): Promise<{ role: OrganizationRole }> {
    return api.patch(`/organizations/${id}/roles/${encodeURIComponent(roleId)}`, payload).then(res => res.data)
  }

  // 删除组织角色
  deleteOrganizationRole(id: string, roleId: string): Promise<{ message: string }> {
    return api.delete(`/organizations/${id}/roles/${encodeURIComponent(roleId)}`).then(res => res.data)
  }

  // 创建组织角色绑定
  createOrganizationRoleBinding(id: string, roleId: string, payload: {
    subject_type: string
    subject_id: string
  }): Promise<{ binding: OrganizationRoleBinding }> {
    return api.post(`/organizations/${id}/roles/${encodeURIComponent(roleId)}/bindings`, payload).then(res => res.data)
  }

  // 删除组织角色绑定
  deleteOrganizationRoleBinding(id: string, roleId: string, bindingId: string): Promise<{ message: string }> {
    return api.delete(`/organizations/${id}/roles/${encodeURIComponent(roleId)}/bindings/${encodeURIComponent(bindingId)}`).then(res => res.data)
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

  // 获取 OIDC clients
  getOIDCClients(): Promise<{ clients: OIDCClient[] }> {
    return api.get('/oidc/clients').then(res => res.data)
  }

  // 创建 OIDC client
  createOIDCClient(payload: {
    name?: string
    client_id: string
    client_secret?: string
    grant_types?: string[]
    service_account_subject?: string
    redirect_uris: string[]
    scopes?: string[]
    public?: boolean
    require_pkce?: boolean
    require_organization?: boolean
    allowed_organizations?: string[]
    required_org_roles?: string[]
    required_org_roles_all?: string[]
    required_org_groups?: string[]
    required_org_groups_all?: string[]
    scope_policies?: Record<string, OIDCOrganizationPolicy>
    enabled?: boolean
  }): Promise<{ client: OIDCClient }> {
    return api.post('/oidc/clients', payload).then(res => res.data)
  }

  // 更新 OIDC client
  updateOIDCClient(clientId: string, payload: {
    name?: string
    client_id?: string
    client_secret?: string
    grant_types?: string[]
    service_account_subject?: string
    redirect_uris?: string[]
    scopes?: string[]
    public?: boolean
    require_pkce?: boolean
    require_organization?: boolean
    allowed_organizations?: string[]
    required_org_roles?: string[]
    required_org_roles_all?: string[]
    required_org_groups?: string[]
    required_org_groups_all?: string[]
    scope_policies?: Record<string, OIDCOrganizationPolicy>
    enabled?: boolean
  }): Promise<{ client: OIDCClient }> {
    return api.patch(`/oidc/clients/${encodeURIComponent(clientId)}`, payload).then(res => res.data)
  }

  // 删除 OIDC client
  deleteOIDCClient(clientId: string): Promise<{ message: string }> {
    return api.delete(`/oidc/clients/${encodeURIComponent(clientId)}`).then(res => res.data)
  }

  // 获取后台可配置 Claim Mapper
  getClaimMappers(): Promise<{ claim_mappers: AdminClaimMapper[] }> {
    return api.get('/claim-mappers').then(res => res.data)
  }

  // 创建后台可配置 Claim Mapper
  createClaimMapper(payload: Partial<AdminClaimMapper>): Promise<{ claim_mapper: AdminClaimMapper }> {
    return api.post('/claim-mappers', payload).then(res => res.data)
  }

  // 更新后台可配置 Claim Mapper
  updateClaimMapper(mapperId: string, payload: Partial<AdminClaimMapper>): Promise<{ claim_mapper: AdminClaimMapper }> {
    return api.patch(`/claim-mappers/${encodeURIComponent(mapperId)}`, payload).then(res => res.data)
  }

  // 删除后台可配置 Claim Mapper
  deleteClaimMapper(mapperId: string): Promise<{ message: string }> {
    return api.delete(`/claim-mappers/${encodeURIComponent(mapperId)}`).then(res => res.data)
  }

  // 查询 secrets 加密状态
  getSecuritySecretsStatus(): Promise<{ status: SecuritySecretsStatus }> {
    return api.get('/security/secrets/status').then(res => res.data)
  }

  // 重写后台托管 secrets
  resealManagedSecrets(): Promise<{ message: string, result: SecuritySecretsResealResult }> {
    return api.post('/security/secrets/reseal').then(res => res.data)
  }

  // 查询安全审计
  getSecurityAudit(params: SecurityAuditQuery = {}): Promise<SecurityAuditListResponse> {
    return api.get('/security/audit', { params }).then(res => res.data)
  }

  // 导出安全审计 CSV
  exportSecurityAuditCSV(params: SecurityAuditQuery = {}): Promise<Blob> {
    return api.get('/security/audit/export', {
      params,
      responseType: 'blob'
    }).then(res => res.data)
  }

  createSecurityAuditExportJob(payload: SecurityAuditQuery = {}): Promise<{ message: string, job: SecurityAuditExportJob }> {
    return api.post('/security/audit/export-jobs', payload).then(res => res.data)
  }

  listSecurityAuditExportJobs(params: SecurityAuditExportJobQuery = {}): Promise<SecurityAuditExportJobListResponse> {
    return api.get('/security/audit/export-jobs', { params }).then(res => res.data)
  }

  cleanupSecurityAuditExportJobs(payload: SecurityAuditExportJobCleanupRequest = {}): Promise<{ message: string, result: SecurityAuditExportJobCleanupResult }> {
    return api.post('/security/audit/export-jobs/cleanup', payload).then(res => res.data)
  }

  getSecurityAuditExportJob(jobId: string): Promise<{ job: SecurityAuditExportJob }> {
    return api.get(`/security/audit/export-jobs/${jobId}`).then(res => res.data)
  }

  deleteSecurityAuditExportJob(jobId: string): Promise<{ message: string }> {
    return api.delete(`/security/audit/export-jobs/${jobId}`).then(res => res.data)
  }

  downloadSecurityAuditExportJob(jobId: string): Promise<Blob> {
    return api.get(`/security/audit/export-jobs/${jobId}/download`, {
      responseType: 'blob'
    }).then(res => res.data)
  }

  // 兼容旧的 secrets 审计接口
  getSecuritySecretsAudit(limit = 50): Promise<SecurityAuditListResponse> {
    return this.getSecurityAudit({ page: 1, size: limit })
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
