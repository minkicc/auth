<template>
  <div class="organizations-page">
    <el-card class="page-card">
      <template #header>
        <div class="card-header">
          <div>
            <h2>组织管理</h2>
            <p>管理 B2B CIAM 的租户、企业域名和组织成员，为 Enterprise OIDC、HRD 和 SCIM 做准备。</p>
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
      width="900px"
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
      </el-tabs>
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
const domainForm = ref({ domain: '', verified: true })
const memberForm = ref({ user_id: '', status: 'active', roles_text: '' })

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
  await loadOrganizationDetails()
}

const loadOrganizationDetails = async () => {
  if (!activeOrg.value) return
  detailLoading.value = true
  try {
    const [domainResponse, memberResponse] = await Promise.all([
      serverApi.getOrganizationDomains(activeOrg.value.organization_id),
      serverApi.getOrganizationMemberships(activeOrg.value.organization_id)
    ])
    domains.value = domainResponse.domains || []
    memberships.value = memberResponse.memberships || []
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
}

@media (max-width: 900px) {
  .organizations-page {
    .card-header,
    .toolbar,
    .inline-form {
      flex-direction: column;
      align-items: stretch;
    }
  }
}
</style>
