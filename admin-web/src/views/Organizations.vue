<template>
  <div class="organizations-page">
    <el-card class="page-card">
      <template #header>
        <div class="card-header">
          <div>
            <h2>组织管理</h2>
            <p>管理 B2B CIAM 的租户、企业域名、组织成员、组织组，以及 Enterprise OIDC / SAML 登录源。</p>
          </div>
          <el-button type="primary" @click="openOrgDialog()">新建组织</el-button>
        </div>
      </template>

      <div class="toolbar">
        <el-input
          v-model="filters.search"
          placeholder="搜索 slug / 名称"
          clearable
          @keyup.enter="loadOrganizations"
          @clear="loadOrganizations"
        />
        <el-select v-model="filters.status" clearable placeholder="状态" @change="loadOrganizations">
          <el-option label="Active" value="active" />
          <el-option label="Inactive" value="inactive" />
        </el-select>
        <el-button :loading="loading" @click="loadOrganizations">刷新</el-button>
      </div>

      <el-table v-loading="loading" :data="organizations" row-key="organization_id" empty-text="暂无组织">
        <el-table-column prop="name" label="名称" min-width="180" />
        <el-table-column prop="slug" label="Slug" min-width="150" />
        <el-table-column label="显示名" min-width="160">
          <template #default="{ row }">{{ row.display_name || '-' }}</template>
        </el-table-column>
        <el-table-column label="状态" width="120">
          <template #default="{ row }">
            <el-tag :type="row.status === 'active' ? 'success' : 'info'" effect="plain">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="创建时间" min-width="170">
          <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="180" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openManageDialog(row)">管理</el-button>
            <el-button link type="primary" @click="openOrgDialog(row)">编辑</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination-wrap">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :total="total"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @size-change="loadOrganizations"
          @current-change="loadOrganizations"
        />
      </div>
    </el-card>

    <el-dialog
      v-model="orgDialogVisible"
      :title="editingOrg ? '编辑组织' : '新建组织'"
      width="560px"
    >
      <el-form label-position="top">
        <el-form-item label="Slug">
          <el-input v-model="orgForm.slug" placeholder="acme" :disabled="!!editingOrg" />
        </el-form-item>
        <el-form-item label="名称">
          <el-input v-model="orgForm.name" placeholder="Acme Inc" />
        </el-form-item>
        <el-form-item label="显示名">
          <el-input v-model="orgForm.display_name" placeholder="Acme" />
        </el-form-item>
        <el-form-item label="状态">
          <el-select v-model="orgForm.status" class="full-width">
            <el-option label="Active" value="active" />
            <el-option label="Inactive" value="inactive" />
          </el-select>
        </el-form-item>
        <el-form-item label="Metadata JSON">
          <el-input v-model="orgForm.metadata_text" type="textarea" :rows="4" placeholder='{"plan":"enterprise"}' />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="orgDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="orgSaving" @click="saveOrganization">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="manageDialogVisible"
      :title="`管理组织 ${activeOrg?.name || activeOrg?.slug || ''}`"
      width="960px"
    >
      <el-tabs v-model="activeTab">
        <el-tab-pane label="域名" name="domains">
          <div class="inline-form">
            <el-input v-model="domainForm.domain" placeholder="example.com" />
            <el-switch v-model="domainForm.verified" active-text="已验证" inactive-text="未验证" />
            <el-button type="primary" :loading="detailSaving === 'domain'" @click="addDomain">添加域名</el-button>
          </div>
          <el-table v-loading="detailLoading" :data="domains" row-key="domain" empty-text="暂无域名">
            <el-table-column prop="domain" label="域名" min-width="220" />
            <el-table-column label="验证状态" width="140">
              <template #default="{ row }">
                <el-tag :type="row.verified ? 'success' : 'warning'" effect="plain">
                  {{ row.verified ? '已验证' : '未验证' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="更新时间" min-width="170">
              <template #default="{ row }">{{ formatDate(row.updated_at) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="190" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" @click="toggleDomain(row)">
                  {{ row.verified ? '标记未验证' : '标记已验证' }}
                </el-button>
                <el-button link type="danger" @click="deleteDomain(row.domain)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="成员" name="members">
          <div class="inline-form member-form">
            <el-input v-model="memberForm.user_id" placeholder="usr_xxx" />
            <el-select v-model="memberForm.status" placeholder="状态">
              <el-option label="Active" value="active" />
              <el-option label="Invited" value="invited" />
              <el-option label="Disabled" value="disabled" />
            </el-select>
            <el-input v-model="memberForm.roles_text" placeholder="admin,developer" />
            <el-button type="primary" :loading="detailSaving === 'member'" @click="saveMembership">保存成员</el-button>
          </div>
          <el-table v-loading="detailLoading" :data="memberships" row-key="user_id" empty-text="暂无成员">
            <el-table-column label="用户" min-width="220">
              <template #default="{ row }">
                <strong>{{ row.nickname || row.username || row.user_id }}</strong>
                <p class="muted">{{ row.user_id }}</p>
              </template>
            </el-table-column>
            <el-table-column label="状态" width="120">
              <template #default="{ row }">
                <el-tag :type="row.status === 'active' ? 'success' : row.status === 'invited' ? 'warning' : 'info'" effect="plain">
                  {{ row.status }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="角色" min-width="220">
              <template #default="{ row }">{{ row.roles?.join(', ') || '-' }}</template>
            </el-table-column>
            <el-table-column label="操作" width="150" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" @click="editMembership(row)">编辑</el-button>
                <el-button link type="danger" @click="deleteMembership(row.user_id)">移除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="组" name="groups">
          <div class="identity-provider-header">
            <div>
              <h3>组织组</h3>
              <p>手工维护组织组成员和角色映射；SCIM 同步进来的组也会展示在这里，并进入 OIDC 的 `org_groups` claim。</p>
            </div>
            <el-button type="primary" :disabled="!activeOrg" @click="openGroupDialog()">新建组织组</el-button>
          </div>

          <el-table v-loading="detailLoading" :data="groups" row-key="group_id" empty-text="暂无组织组">
            <el-table-column prop="display_name" label="组名" min-width="180" />
            <el-table-column prop="role_name" label="角色映射" min-width="160">
              <template #default="{ row }">
                <span class="mono">{{ row.role_name }}</span>
              </template>
            </el-table-column>
            <el-table-column label="来源" min-width="150">
              <template #default="{ row }">
                <el-tag :type="row.provider_type === 'manual' ? 'success' : 'info'" effect="plain">
                  {{ row.provider_type === 'manual' ? '手工维护' : row.provider_type?.toUpperCase() }}
                </el-tag>
                <p v-if="row.provider_type !== 'manual' && row.provider_id" class="muted">{{ row.provider_id }}</p>
              </template>
            </el-table-column>
            <el-table-column label="成员数" width="100">
              <template #default="{ row }">{{ row.member_count ?? 0 }}</template>
            </el-table-column>
            <el-table-column label="可编辑" width="120">
              <template #default="{ row }">
                <el-tag :type="row.editable ? 'success' : 'info'" effect="plain">
                  {{ row.editable ? '可编辑' : '只读' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="更新时间" min-width="170">
              <template #default="{ row }">{{ formatDate(row.updated_at) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="170" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" @click="openGroupDialog(row)">
                  {{ row.editable ? '编辑' : '查看' }}
                </el-button>
                <el-button v-if="row.editable" link type="danger" @click="deleteGroup(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="企业登录" name="identity-providers">
          <div class="identity-provider-header">
            <div>
              <h3>企业登录源</h3>
              <p>为组织配置上游企业 IdP，支持 Enterprise OIDC 和 Enterprise SAML，保存后会立即刷新运行时。</p>
            </div>
            <el-button type="primary" :disabled="!activeOrg" @click="openIdentityProviderDialog()">新建企业登录源</el-button>
          </div>

          <el-table
            v-loading="detailLoading"
            :data="identityProviders"
            row-key="identity_provider_id"
            empty-text="暂无企业登录源"
          >
            <el-table-column prop="name" label="名称" min-width="180" />
            <el-table-column prop="slug" label="Slug" min-width="150" />
            <el-table-column label="类型" width="120">
              <template #default="{ row }">
                <el-tag effect="plain">{{ row.provider_type?.toUpperCase() || 'OIDC' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="状态" width="120">
              <template #default="{ row }">
                <el-tag :type="row.enabled ? 'success' : 'info'" effect="plain">
                  {{ row.enabled ? '启用中' : '已禁用' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="策略" min-width="180">
              <template #default="{ row }">
                <div class="tag-group">
                  <el-tag v-if="row.is_default" type="success" effect="plain">默认</el-tag>
                  <el-tag v-if="row.auto_redirect" type="warning" effect="plain">自动跳转</el-tag>
                  <span v-if="!row.is_default && !row.auto_redirect" class="muted">手动选择</span>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="优先级" width="110">
              <template #default="{ row }">{{ row.priority ?? 100 }}</template>
            </el-table-column>
            <el-table-column label="Issuer / Metadata" min-width="220">
              <template #default="{ row }">
                <span class="mono">{{ row.provider_type === 'saml' ? (row.config?.idp_metadata_url || '-') : (row.config?.issuer || '-') }}</span>
              </template>
            </el-table-column>
            <el-table-column label="Redirect / ACS" min-width="280">
              <template #default="{ row }">
                <span class="mono">{{ row.provider_type === 'saml' ? (row.config?.acs_url || '-') : (row.config?.redirect_uri || '-') }}</span>
              </template>
            </el-table-column>
            <el-table-column label="配置摘要" min-width="200">
              <template #default="{ row }">
                <span v-if="row.provider_type === 'saml'">
                  {{ row.config?.entity_id || row.config?.name_id_format || '-' }}
                </span>
                <span v-else>{{ row.config?.scopes?.join(', ') || '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="配置" width="120">
              <template #default="{ row }">
                <el-tag
                  :type="row.provider_type === 'saml'
                    ? (row.config?.idp_metadata_xml_configured ? 'success' : 'info')
                    : (row.config?.client_secret_configured ? 'success' : 'warning')"
                  effect="plain"
                >
                  {{ row.provider_type === 'saml'
                    ? (row.config?.idp_metadata_xml_configured ? '内置元数据' : 'URL 元数据')
                    : (row.config?.client_secret_configured ? '已配置' : '未配置') }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="更新时间" min-width="170">
              <template #default="{ row }">{{ formatDate(row.updated_at) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="170" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" @click="openIdentityProviderDialog(row)">编辑</el-button>
                <el-button link type="danger" @click="deleteIdentityProvider(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </el-dialog>

    <el-dialog
      v-model="groupDialogVisible"
      :title="editingGroup ? (editingGroup.editable ? '编辑组织组' : '查看组织组') : '新建组织组'"
      width="640px"
      append-to-body
    >
      <el-form label-position="top">
        <el-form-item label="组名">
          <el-input v-model="groupForm.display_name" placeholder="Platform Team" :disabled="!!editingGroup && !editingGroup.editable" />
        </el-form-item>
        <el-form-item label="角色映射">
          <el-input v-model="groupForm.role_name" placeholder="留空则自动从组名生成，例如 platform-team" :disabled="!!editingGroup && !editingGroup.editable" />
          <p class="form-hint">组成员会自动把这里的角色映射同步到组织成员的 `org_roles`。</p>
        </el-form-item>
        <el-form-item label="成员 User ID">
          <el-input
            v-model="groupForm.user_ids_text"
            type="textarea"
            :rows="5"
            placeholder="usr_xxx,usr_yyy"
            :disabled="!!editingGroup && !editingGroup.editable"
          />
          <p class="form-hint">支持逗号、空格或换行分隔。没有组织成员关系的用户会自动创建为 active 成员。</p>
        </el-form-item>
        <template v-if="editingGroup && editingGroup.members?.length">
          <el-form-item label="当前成员">
            <div class="tag-group">
              <el-tag v-for="member in editingGroup.members" :key="member.user_id" effect="plain">
                {{ member.nickname || member.username || member.user_id }}
              </el-tag>
            </div>
          </el-form-item>
        </template>
      </el-form>
      <template #footer>
        <el-button @click="groupDialogVisible = false">关闭</el-button>
        <el-button
          v-if="!editingGroup || editingGroup.editable"
          type="primary"
          :loading="detailSaving === 'group'"
          @click="saveGroup"
        >
          保存
        </el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="identityProviderDialogVisible"
      :title="editingIdentityProvider ? '编辑企业登录源' : '新建企业登录源'"
      width="640px"
      append-to-body
    >
      <el-form label-position="top">
        <el-form-item label="类型">
          <el-select v-model="identityProviderForm.provider_type" class="full-width">
            <el-option label="Enterprise OIDC" value="oidc" />
            <el-option label="Enterprise SAML" value="saml" />
          </el-select>
        </el-form-item>
        <el-form-item label="名称">
          <el-input v-model="identityProviderForm.name" placeholder="Acme Workforce" />
        </el-form-item>
        <el-form-item label="Slug">
          <el-input v-model="identityProviderForm.slug" placeholder="acme-workforce" />
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="identityProviderForm.enabled" active-text="启用中" inactive-text="已禁用" />
        </el-form-item>
        <el-form-item label="优先级">
          <el-input-number v-model="identityProviderForm.priority" :min="0" :step="10" class="full-width" />
          <p class="form-hint">数值越小越靠前。多个企业登录源同时命中时，会按默认标记和优先级排序。</p>
        </el-form-item>
        <el-form-item label="默认登录源">
          <el-switch v-model="identityProviderForm.is_default" active-text="默认" inactive-text="普通" />
          <p class="form-hint">多企业登录源并存时，默认登录源会优先展示，并作为优先推荐对象。</p>
        </el-form-item>
        <el-form-item label="自动跳转">
          <el-switch v-model="identityProviderForm.auto_redirect" active-text="自动跳转" inactive-text="手动选择" />
          <p class="form-hint">命中该组织且存在多个登录源时，会优先直跳当前优先提供方。建议同一组织只启用一个自动跳转源。</p>
        </el-form-item>
        <template v-if="identityProviderForm.provider_type === 'oidc'">
          <el-form-item label="Issuer">
            <el-input v-model="identityProviderForm.issuer" placeholder="https://login.acme.com" />
          </el-form-item>
          <el-form-item label="Client ID">
            <el-input v-model="identityProviderForm.client_id" placeholder="acme-client-id" />
          </el-form-item>
          <el-form-item label="Client Secret">
            <el-input
              v-model="identityProviderForm.client_secret"
              type="password"
              show-password
              :placeholder="editingIdentityProvider ? '留空则保留现有 secret' : '请输入 client secret'"
            />
            <p v-if="editingIdentityProvider?.provider_type === 'oidc' && editingIdentityProvider?.config?.client_secret_configured" class="form-hint">
              当前已配置 secret，留空会继续沿用原值。
            </p>
          </el-form-item>
          <el-form-item label="Redirect URI">
            <el-input
              v-model="identityProviderForm.redirect_uri"
              placeholder="https://auth.example.com/api/enterprise/oidc/acme-workforce/callback"
            />
          </el-form-item>
          <el-form-item label="Scopes">
            <el-input
              v-model="identityProviderForm.scopes_text"
              type="textarea"
              :rows="3"
              placeholder="openid,profile,email"
            />
            <p class="form-hint">支持逗号或换行分隔，默认会补齐 `openid, profile, email`。</p>
          </el-form-item>
        </template>
        <template v-else>
          <el-form-item label="IdP Metadata URL">
            <el-input v-model="identityProviderForm.idp_metadata_url" placeholder="https://login.acme.com/metadata" />
          </el-form-item>
          <el-form-item label="IdP Metadata XML">
            <el-input
              v-model="identityProviderForm.idp_metadata_xml"
              type="textarea"
              :rows="4"
              placeholder="<EntityDescriptor ...>"
            />
            <p class="form-hint">可选。留空时会继续使用已有 XML；如果同时配置 URL，则优先使用 XML。</p>
          </el-form-item>
          <el-form-item label="Entity ID">
            <el-input v-model="identityProviderForm.entity_id" placeholder="留空则默认使用 metadata 地址" />
          </el-form-item>
          <el-form-item label="ACS URL">
            <el-input v-model="identityProviderForm.acs_url" placeholder="留空则默认生成 /api/enterprise/saml/:slug/acs" />
          </el-form-item>
          <el-form-item label="NameID Format">
            <el-input v-model="identityProviderForm.name_id_format" placeholder="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" />
          </el-form-item>
          <el-form-item label="Email Attribute">
            <el-input v-model="identityProviderForm.email_attribute" placeholder="email 或 urn:oid:0.9.2342.19200300.100.1.3" />
          </el-form-item>
          <el-form-item label="Username Attribute">
            <el-input v-model="identityProviderForm.username_attribute" placeholder="uid" />
          </el-form-item>
          <el-form-item label="Display Name Attribute">
            <el-input v-model="identityProviderForm.display_name_attribute" placeholder="displayName" />
          </el-form-item>
          <el-form-item label="允许 IdP 发起">
            <el-switch v-model="identityProviderForm.allow_idp_initiated" active-text="允许" inactive-text="仅 SP 发起" />
          </el-form-item>
          <el-form-item label="默认回跳地址">
            <el-input v-model="identityProviderForm.default_redirect_uri" placeholder="/profile" />
          </el-form-item>
        </template>
      </el-form>
      <template #footer>
        <el-button @click="identityProviderDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="detailSaving === 'identity-provider'" @click="saveIdentityProvider">
          保存
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index'
import { ElMessageBox } from 'element-plus/es/components/message-box/index'
import {
  serverApi,
  type Organization,
  type OrganizationDomain,
  type OrganizationGroup,
  type OrganizationIdentityProvider,
  type OrganizationMembership
} from '@/api'

const loading = ref(false)
const organizations = ref<Organization[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)
const filters = ref({ search: '', status: '' })

const orgDialogVisible = ref(false)
const orgSaving = ref(false)
const editingOrg = ref<Organization | null>(null)
const orgForm = ref({
  slug: '',
  name: '',
  display_name: '',
  status: 'active',
  metadata_text: ''
})

const manageDialogVisible = ref(false)
const activeOrg = ref<Organization | null>(null)
const activeTab = ref('domains')
const detailLoading = ref(false)
const detailSaving = ref('')
const domains = ref<OrganizationDomain[]>([])
const memberships = ref<OrganizationMembership[]>([])
const groups = ref<OrganizationGroup[]>([])
const identityProviders = ref<OrganizationIdentityProvider[]>([])
const domainForm = ref({ domain: '', verified: true })
const memberForm = ref({ user_id: '', status: 'active', roles_text: '' })

const groupDialogVisible = ref(false)
const editingGroup = ref<OrganizationGroup | null>(null)
const groupForm = ref(defaultGroupForm())

const identityProviderDialogVisible = ref(false)
const editingIdentityProvider = ref<OrganizationIdentityProvider | null>(null)
const identityProviderForm = ref(defaultIdentityProviderForm())

function defaultGroupForm() {
  return {
    display_name: '',
    role_name: '',
    user_ids_text: ''
  }
}

function defaultIdentityProviderForm() {
  return {
    provider_type: 'oidc',
    name: '',
    slug: '',
    enabled: true,
    priority: 100,
    is_default: false,
    auto_redirect: false,
    issuer: '',
    client_id: '',
    client_secret: '',
    redirect_uri: '',
    scopes_text: 'openid,profile,email',
    idp_metadata_url: '',
    idp_metadata_xml: '',
    entity_id: '',
    acs_url: '',
    name_id_format: '',
    email_attribute: '',
    username_attribute: '',
    display_name_attribute: '',
    allow_idp_initiated: false,
    default_redirect_uri: '/profile'
  }
}

const loadOrganizations = async () => {
  loading.value = true
  try {
    const response = await serverApi.getOrganizations({
      page: page.value,
      size: pageSize.value,
      search: filters.value.search || undefined,
      status: filters.value.status || undefined
    })
    organizations.value = response.organizations || []
    total.value = response.total || 0
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载组织失败')
  } finally {
    loading.value = false
  }
}

const openOrgDialog = (org?: Organization) => {
  editingOrg.value = org || null
  orgForm.value = {
    slug: org?.slug || '',
    name: org?.name || '',
    display_name: org?.display_name || '',
    status: org?.status || 'active',
    metadata_text: formatMetadata(org?.metadata_json)
  }
  orgDialogVisible.value = true
}

const saveOrganization = async () => {
  let metadata: Record<string, any> = {}
  try {
    metadata = parseMetadata(orgForm.value.metadata_text)
  } catch (error: any) {
    ElMessage.error(error.message || 'Metadata JSON 格式不正确')
    return
  }
  orgSaving.value = true
  try {
    const payload = {
      slug: orgForm.value.slug,
      name: orgForm.value.name,
      display_name: orgForm.value.display_name,
      status: orgForm.value.status,
      metadata
    }
    if (editingOrg.value) {
      await serverApi.updateOrganization(editingOrg.value.organization_id, payload)
    } else {
      await serverApi.createOrganization(payload)
    }
    ElMessage.success('组织已保存')
    orgDialogVisible.value = false
    await loadOrganizations()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '保存组织失败')
  } finally {
    orgSaving.value = false
  }
}

const openManageDialog = async (org: Organization) => {
  activeOrg.value = org
  activeTab.value = 'domains'
  manageDialogVisible.value = true
  groupDialogVisible.value = false
  identityProviderDialogVisible.value = false
  await loadOrganizationDetails()
}

const loadOrganizationDetails = async () => {
  if (!activeOrg.value) return
  detailLoading.value = true
  try {
    const [domainResponse, memberResponse, groupResponse, identityProviderResponse] = await Promise.all([
      serverApi.getOrganizationDomains(activeOrg.value.organization_id),
      serverApi.getOrganizationMemberships(activeOrg.value.organization_id),
      serverApi.getOrganizationGroups(activeOrg.value.organization_id),
      serverApi.getOrganizationIdentityProviders(activeOrg.value.organization_id)
    ])
    domains.value = domainResponse.domains || []
    memberships.value = memberResponse.memberships || []
    groups.value = groupResponse.groups || []
    identityProviders.value = identityProviderResponse.identity_providers || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载组织详情失败')
  } finally {
    detailLoading.value = false
  }
}

const addDomain = async () => {
  if (!activeOrg.value) return
  detailSaving.value = 'domain'
  try {
    await serverApi.createOrganizationDomain(activeOrg.value.organization_id, domainForm.value)
    ElMessage.success('域名已保存')
    domainForm.value = { domain: '', verified: true }
    await loadOrganizationDetails()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '保存域名失败')
  } finally {
    detailSaving.value = ''
  }
}

const toggleDomain = async (domain: OrganizationDomain) => {
  if (!activeOrg.value) return
  try {
    await serverApi.updateOrganizationDomain(activeOrg.value.organization_id, domain.domain, { verified: !domain.verified })
    await loadOrganizationDetails()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '更新域名失败')
  }
}

const deleteDomain = async (domain: string) => {
  if (!activeOrg.value) return
  try {
    await ElMessageBox.confirm(`确定删除域名 ${domain} 吗？`, '删除域名', { type: 'warning' })
  } catch {
    return
  }
  try {
    await serverApi.deleteOrganizationDomain(activeOrg.value.organization_id, domain)
    ElMessage.success('域名已删除')
    await loadOrganizationDetails()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '删除域名失败')
  }
}

const saveMembership = async () => {
  if (!activeOrg.value) return
  detailSaving.value = 'member'
  try {
    await serverApi.upsertOrganizationMembership(activeOrg.value.organization_id, {
      user_id: memberForm.value.user_id,
      status: memberForm.value.status,
      roles: parseRoles(memberForm.value.roles_text)
    })
    ElMessage.success('成员已保存')
    memberForm.value = { user_id: '', status: 'active', roles_text: '' }
    await loadOrganizationDetails()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '保存成员失败')
  } finally {
    detailSaving.value = ''
  }
}

const editMembership = (membership: OrganizationMembership) => {
  memberForm.value = {
    user_id: membership.user_id,
    status: membership.status || 'active',
    roles_text: membership.roles?.join(',') || ''
  }
}

const deleteMembership = async (userId: string) => {
  if (!activeOrg.value) return
  try {
    await ElMessageBox.confirm(`确定移除成员 ${userId} 吗？`, '移除成员', { type: 'warning' })
  } catch {
    return
  }
  try {
    await serverApi.deleteOrganizationMembership(activeOrg.value.organization_id, userId)
    ElMessage.success('成员已移除')
    await loadOrganizationDetails()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '移除成员失败')
  }
}

const openGroupDialog = async (group?: OrganizationGroup) => {
  if (!activeOrg.value) return
  if (!group) {
    editingGroup.value = null
    groupForm.value = defaultGroupForm()
    groupDialogVisible.value = true
    return
  }
  try {
    detailLoading.value = true
    const response = await serverApi.getOrganizationGroup(activeOrg.value.organization_id, group.group_id)
    editingGroup.value = response.group
    groupForm.value = {
      display_name: response.group.display_name || '',
      role_name: response.group.role_name || '',
      user_ids_text: (response.group.members || []).map(member => member.user_id).join('\n')
    }
    groupDialogVisible.value = true
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载组织组失败')
  } finally {
    detailLoading.value = false
  }
}

const saveGroup = async () => {
  if (!activeOrg.value) return
  detailSaving.value = 'group'
  try {
    const payload = {
      display_name: groupForm.value.display_name,
      role_name: groupForm.value.role_name || undefined,
      user_ids: parseUserIds(groupForm.value.user_ids_text)
    }
    if (editingGroup.value) {
      await serverApi.updateOrganizationGroup(activeOrg.value.organization_id, editingGroup.value.group_id, payload)
    } else {
      await serverApi.createOrganizationGroup(activeOrg.value.organization_id, payload)
    }
    ElMessage.success('组织组已保存')
    groupDialogVisible.value = false
    editingGroup.value = null
    groupForm.value = defaultGroupForm()
    await loadOrganizationDetails()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '保存组织组失败')
  } finally {
    detailSaving.value = ''
  }
}

const deleteGroup = async (group: OrganizationGroup) => {
  if (!activeOrg.value) return
  try {
    await ElMessageBox.confirm(`确定删除组织组 ${group.display_name} 吗？`, '删除组织组', { type: 'warning' })
  } catch {
    return
  }
  try {
    await serverApi.deleteOrganizationGroup(activeOrg.value.organization_id, group.group_id)
    ElMessage.success('组织组已删除')
    await loadOrganizationDetails()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '删除组织组失败')
  }
}

const openIdentityProviderDialog = (provider?: OrganizationIdentityProvider) => {
  editingIdentityProvider.value = provider || null
  identityProviderForm.value = {
    provider_type: provider?.provider_type || 'oidc',
    name: provider?.name || '',
    slug: provider?.slug || '',
    enabled: provider?.enabled ?? true,
    priority: provider?.priority ?? 100,
    is_default: provider?.is_default ?? false,
    auto_redirect: provider?.auto_redirect ?? false,
    issuer: provider?.config?.issuer || '',
    client_id: provider?.config?.client_id || '',
    client_secret: '',
    redirect_uri: provider?.config?.redirect_uri || '',
    scopes_text: provider?.config?.scopes?.join(',') || 'openid,profile,email',
    idp_metadata_url: provider?.config?.idp_metadata_url || '',
    idp_metadata_xml: '',
    entity_id: provider?.config?.entity_id || '',
    acs_url: provider?.config?.acs_url || '',
    name_id_format: provider?.config?.name_id_format || '',
    email_attribute: provider?.config?.email_attribute || '',
    username_attribute: provider?.config?.username_attribute || '',
    display_name_attribute: provider?.config?.display_name_attribute || '',
    allow_idp_initiated: provider?.config?.allow_idp_initiated ?? false,
    default_redirect_uri: provider?.config?.default_redirect_uri || '/profile'
  }
  identityProviderDialogVisible.value = true
}

const saveIdentityProvider = async () => {
  if (!activeOrg.value) return
  detailSaving.value = 'identity-provider'
  try {
    const payload = {
      provider_type: identityProviderForm.value.provider_type,
      name: identityProviderForm.value.name,
      slug: identityProviderForm.value.slug,
      enabled: identityProviderForm.value.enabled,
      priority: identityProviderForm.value.priority,
      is_default: identityProviderForm.value.is_default,
      auto_redirect: identityProviderForm.value.auto_redirect,
      issuer: identityProviderForm.value.issuer,
      client_id: identityProviderForm.value.client_id,
      client_secret: identityProviderForm.value.client_secret || undefined,
      redirect_uri: identityProviderForm.value.redirect_uri,
      scopes: parseScopes(identityProviderForm.value.scopes_text),
      idp_metadata_url: identityProviderForm.value.idp_metadata_url || undefined,
      idp_metadata_xml: identityProviderForm.value.idp_metadata_xml || undefined,
      entity_id: identityProviderForm.value.entity_id || undefined,
      acs_url: identityProviderForm.value.acs_url || undefined,
      name_id_format: identityProviderForm.value.name_id_format || undefined,
      email_attribute: identityProviderForm.value.email_attribute || undefined,
      username_attribute: identityProviderForm.value.username_attribute || undefined,
      display_name_attribute: identityProviderForm.value.display_name_attribute || undefined,
      allow_idp_initiated: identityProviderForm.value.allow_idp_initiated,
      default_redirect_uri: identityProviderForm.value.default_redirect_uri || undefined
    }
    if (editingIdentityProvider.value) {
      await serverApi.updateOrganizationIdentityProvider(
        activeOrg.value.organization_id,
        editingIdentityProvider.value.identity_provider_id,
        payload
      )
    } else {
      await serverApi.createOrganizationIdentityProvider(activeOrg.value.organization_id, payload)
    }
    ElMessage.success('企业登录源已保存')
    identityProviderDialogVisible.value = false
    editingIdentityProvider.value = null
    identityProviderForm.value = defaultIdentityProviderForm()
    await loadOrganizationDetails()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '保存企业登录源失败')
  } finally {
    detailSaving.value = ''
  }
}

const deleteIdentityProvider = async (provider: OrganizationIdentityProvider) => {
  if (!activeOrg.value) return
  try {
    await ElMessageBox.confirm(`确定删除企业登录源 ${provider.name || provider.slug} 吗？`, '删除企业登录源', { type: 'warning' })
  } catch {
    return
  }
  try {
    await serverApi.deleteOrganizationIdentityProvider(activeOrg.value.organization_id, provider.identity_provider_id)
    ElMessage.success('企业登录源已删除')
    await loadOrganizationDetails()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '删除企业登录源失败')
  }
}

const parseMetadata = (raw: string) => {
  raw = raw.trim()
  if (!raw) return {}
  const parsed = JSON.parse(raw)
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error('Metadata 必须是 JSON 对象')
  }
  return parsed
}

const formatMetadata = (raw?: string) => {
  if (!raw) return ''
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}

const parseRoles = (raw: string) => raw.split(',').map(item => item.trim()).filter(Boolean)

const parseUserIds = (raw: string) =>
  raw
    .split(/[\s,]+/)
    .map(item => item.trim())
    .filter(Boolean)

const parseScopes = (raw: string) => {
  const values = raw
    .split(/[\n,]/)
    .map(item => item.trim())
    .filter(Boolean)
  return values.length > 0 ? values : ['openid', 'profile', 'email']
}

const formatDate = (value?: string) => {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString()
}

onMounted(() => {
  loadOrganizations()
})
</script>

<style lang="scss" scoped>
.organizations-page {
  .page-card {
    border-radius: 14px;
  }

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 16px;

    h2 {
      margin: 0 0 6px;
      font-size: 1.2rem;
      font-weight: 600;
    }

    p {
      margin: 0;
      color: #64748b;
      line-height: 1.5;
    }
  }

  .toolbar,
  .inline-form {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
  }

  .toolbar {
    max-width: 760px;
  }

  .member-form {
    align-items: stretch;
  }

  .identity-provider-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 16px;

    h3 {
      margin: 0 0 6px;
      font-size: 1rem;
      font-weight: 600;
    }

    p {
      margin: 0;
      color: #64748b;
      line-height: 1.5;
    }
  }

  .pagination-wrap {
    display: flex;
    justify-content: flex-end;
    margin-top: 18px;
  }

  .full-width {
    width: 100%;
  }

  .muted {
    margin: 4px 0 0;
    color: #64748b;
    font-size: 12px;
  }

  .tag-group {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
  }

  .form-hint {
    margin: 8px 0 0;
    color: #64748b;
    font-size: 12px;
    line-height: 1.5;
  }

  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    word-break: break-all;
  }
}

@media (max-width: 900px) {
  .organizations-page {
    .card-header,
    .toolbar,
    .inline-form,
    .identity-provider-header {
      flex-direction: column;
      align-items: stretch;
    }
  }
}
</style>
