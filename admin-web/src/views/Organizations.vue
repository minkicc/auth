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
            <el-table-column label="操作" width="220" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" @click="openGroupDialog(row)">
                  {{ row.editable ? '编辑' : '查看' }}
                </el-button>
                <el-button v-if="row.editable" link type="danger" @click="deleteGroup(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="角色" name="roles">
          <div class="identity-provider-header">
            <div>
              <h3>组织角色</h3>
              <p>管理正式组织角色、权限键和角色绑定。角色可以直接绑定到成员，也可以绑定到组织组。</p>
            </div>
            <el-button type="primary" :disabled="!activeOrg" @click="openRoleDialog()">新建角色</el-button>
          </div>

          <el-table v-loading="detailLoading" :data="roles" row-key="role_id" empty-text="暂无组织角色">
            <el-table-column prop="name" label="名称" min-width="160" />
            <el-table-column prop="slug" label="Slug" min-width="140">
              <template #default="{ row }">
                <span class="mono">{{ row.slug }}</span>
              </template>
            </el-table-column>
            <el-table-column label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="row.enabled ? 'success' : 'info'" effect="plain">
                  {{ row.enabled ? '启用' : '禁用' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="权限键" min-width="240">
              <template #default="{ row }">
                <span class="events">{{ row.permissions?.join(', ') || '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="绑定" min-width="220">
              <template #default="{ row }">
                <div class="tag-group">
                  <el-tag
                    v-for="binding in (row.bindings || []).slice(0, 3)"
                    :key="binding.binding_id"
                    effect="plain"
                    size="small"
                  >
                    {{ binding.subject_type === 'group' ? '组' : '成员' }} · {{ binding.subject_label || binding.subject_id }}
                  </el-tag>
                  <span v-if="(row.bindings || []).length === 0" class="muted">暂无绑定</span>
                  <span v-else-if="(row.bindings || []).length > 3" class="muted">+{{ (row.bindings || []).length - 3 }}</span>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="更新时间" min-width="170">
              <template #default="{ row }">{{ formatDate(row.updated_at) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="180" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" @click="openRoleDialog(row)">编辑</el-button>
                <el-button link type="danger" @click="deleteRole(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="企业登录" name="identity-providers">
          <div class="identity-provider-header">
            <div>
              <h3>企业登录源</h3>
              <p>为组织配置上游企业 IdP，支持 Enterprise OIDC、Enterprise SAML 和 Enterprise LDAP/AD，保存后会立即刷新运行时。</p>
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
                <span class="mono">{{ identityProviderEndpointLabel(row) }}</span>
              </template>
            </el-table-column>
            <el-table-column label="Redirect / ACS" min-width="280">
              <template #default="{ row }">
                <span class="mono">{{ identityProviderCallbackLabel(row) }}</span>
              </template>
            </el-table-column>
            <el-table-column label="配置摘要" min-width="200">
              <template #default="{ row }">
                <span>{{ identityProviderSummary(row) }}</span>
              </template>
            </el-table-column>
            <el-table-column label="配置" width="120">
              <template #default="{ row }">
                <el-tag :type="identityProviderConfigTagType(row)" effect="plain">
                  {{ identityProviderConfigTagText(row) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="更新时间" min-width="170">
              <template #default="{ row }">{{ formatDate(row.updated_at) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="220" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" @click="openIdentityProviderDialog(row)">编辑</el-button>
                <el-button link type="primary" @click="openIdentityProviderAudit(row)">审计</el-button>
                <el-button link type="warning" @click="openIdentityProviderFailureAudit(row)">失败记录</el-button>
                <el-button link type="danger" @click="deleteIdentityProvider(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="安全审计" name="security-audit">
          <div class="identity-provider-header">
            <div>
              <h3>组织安全审计</h3>
              <p>仅展示当前组织下企业身份源的创建、更新、删除安全审计，便于直接按组织上下文追踪配置变更。</p>
            </div>
          </div>

          <div class="audit-toolbar">
            <el-select
              v-model="organizationAuditFilters.action"
              clearable
              placeholder="全部动作"
              @change="handleOrganizationAuditFilterChange"
            >
              <el-option
                v-for="option in organizationAuditActionOptions"
                :key="option.value"
                :label="option.label"
                :value="option.value"
              />
            </el-select>
            <el-select
              v-model="organizationAuditFilters.success"
              placeholder="全部结果"
              @change="handleOrganizationAuditFilterChange"
            >
              <el-option label="全部结果" value="all" />
              <el-option label="仅成功" value="true" />
              <el-option label="仅失败" value="false" />
            </el-select>
            <el-input
              v-model="organizationAuditFilters.provider_id"
              clearable
              placeholder="精确 provider_id"
              @clear="handleOrganizationAuditFilterChange"
              @keyup.enter="handleOrganizationAuditFilterChange"
            />
            <el-input
              v-model="organizationAuditFilters.query"
              clearable
              placeholder="搜索 slug / 名称 / 错误"
              @clear="handleOrganizationAuditFilterChange"
              @keyup.enter="handleOrganizationAuditFilterChange"
            />
            <el-button :loading="organizationAuditLoading" @click="loadOrganizationSecurityAudit">刷新审计</el-button>
            <el-button @click="showOrganizationAuditFailures">只看失败</el-button>
            <el-button @click="resetOrganizationAuditFilters">重置筛选</el-button>
            <el-button :loading="organizationAuditExportLoading" @click="exportOrganizationSecurityAudit">导出 CSV</el-button>
            <el-button :loading="organizationAuditAsyncExportLoading" @click="createOrganizationAuditExportJob">后台导出</el-button>
            <el-button @click="copyOrganizationAuditFilterLink">复制筛选链接</el-button>
          </div>

          <el-alert
            v-if="organizationAuditExportJob"
            class="export-job-alert"
            :type="organizationAuditExportJobAlertType"
            :title="organizationAuditExportJobTitle"
            :closable="false"
            show-icon
          >
            <template #default>
              <div class="export-job-content">
                <span>{{ organizationAuditExportJobSummary }}</span>
                <div class="export-job-actions">
                  <el-button
                    v-if="organizationAuditExportJob.download_ready"
                    link
                    type="primary"
                    @click="downloadOrganizationAuditExportJob"
                  >
                    下载结果
                  </el-button>
                  <el-button
                    v-else-if="organizationAuditExportJob.status === 'pending' || organizationAuditExportJob.status === 'running'"
                    link
                    type="primary"
                    @click="refreshOrganizationAuditExportJob"
                  >
                    刷新状态
                  </el-button>
                  <el-button link @click="dismissOrganizationAuditExportJob">关闭</el-button>
                </div>
              </div>
            </template>
          </el-alert>

          <el-card class="audit-jobs-card" shadow="never">
            <template #header>
              <div class="catalog-header">
                <div>
                  <strong>最近后台导出任务</strong>
                  <p>仅展示当前组织的安全审计后台导出任务，刷新后也能继续下载已完成结果。</p>
                </div>
                <div class="table-actions">
                  <el-button :loading="organizationAuditCleanupLoading" text @click="cleanupOrganizationAuditExportJobs">清理旧任务</el-button>
                  <el-button :loading="organizationAuditExportJobsLoading" text @click="loadOrganizationAuditExportJobs">刷新任务</el-button>
                </div>
              </div>
            </template>

            <el-table
              v-loading="organizationAuditExportJobsLoading"
              :data="organizationAuditExportJobs"
              row-key="job_id"
              empty-text="暂无当前组织的后台导出任务"
            >
              <el-table-column label="创建时间" min-width="170">
                <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
              </el-table-column>
              <el-table-column label="状态" width="110">
                <template #default="{ row }">
                  <el-tag :type="organizationAuditExportJobTagType(row.status)" effect="plain">
                    {{ formatOrganizationAuditExportJobStatus(row.status) }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column label="范围" min-width="260">
                <template #default="{ row }">
                  <span class="events">{{ formatOrganizationAuditExportJobScope(row) }}</span>
                </template>
              </el-table-column>
              <el-table-column label="结果" min-width="160">
                <template #default="{ row }">
                  <span class="events">{{ formatOrganizationAuditExportJobResult(row) }}</span>
                </template>
              </el-table-column>
              <el-table-column label="操作人" min-width="130">
                <template #default="{ row }">{{ row.actor?.id || '-' }}</template>
              </el-table-column>
              <el-table-column label="操作" width="170" fixed="right">
                <template #default="{ row }">
                  <div class="table-actions">
                    <el-button link type="primary" @click="trackOrganizationAuditExportJob(row)">跟踪</el-button>
                    <el-button v-if="row.download_ready" link type="primary" @click="downloadListedOrganizationAuditExportJob(row)">下载</el-button>
                    <el-button
                      v-if="row.status === 'completed' || row.status === 'failed'"
                      link
                      type="danger"
                      :loading="organizationAuditExportJobActionId === `delete:${row.job_id}`"
                      @click="deleteOrganizationAuditExportJobEntry(row)"
                    >
                      删除
                    </el-button>
                  </div>
                </template>
              </el-table-column>
            </el-table>
          </el-card>

          <el-table
            v-loading="organizationAuditLoading"
            :data="organizationAuditEntries"
            row-key="id"
            empty-text="暂无当前组织的企业身份源安全审计"
          >
            <el-table-column label="时间" min-width="170">
              <template #default="{ row }">{{ formatDate(row.time) }}</template>
            </el-table-column>
            <el-table-column label="动作" width="140">
              <template #default="{ row }">
                <el-tag effect="plain">{{ formatSecurityAuditAction(row.action) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="操作人" min-width="150">
              <template #default="{ row }">{{ row.actor?.id || '-' }}</template>
            </el-table-column>
            <el-table-column label="结果" width="100">
              <template #default="{ row }">
                <el-tag :type="row.success ? 'success' : 'danger'" effect="plain">
                  {{ row.success ? '成功' : '失败' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="详情" min-width="320">
              <template #default="{ row }">
                <span class="events">{{ formatOrganizationSecurityAuditDetails(row) }}</span>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="100" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" @click="openOrganizationAuditDetail(row)">查看</el-button>
              </template>
            </el-table-column>
          </el-table>

          <div class="audit-pagination">
            <el-pagination
              background
              layout="total, sizes, prev, pager, next"
              :current-page="organizationAuditPage"
              :page-size="organizationAuditPageSize"
              :page-sizes="[10, 20, 50]"
              :total="organizationAuditTotal"
              @current-change="handleOrganizationAuditPageChange"
              @size-change="handleOrganizationAuditSizeChange"
            />
          </div>
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
      v-model="roleDialogVisible"
      :title="editingRole ? '编辑组织角色' : '新建组织角色'"
      width="720px"
      append-to-body
    >
      <el-form label-position="top">
        <el-form-item label="名称">
          <el-input v-model="roleForm.name" placeholder="Admin" />
        </el-form-item>
        <el-form-item label="Slug">
          <el-input v-model="roleForm.slug" placeholder="留空则自动从名称生成，例如 admin" />
        </el-form-item>
        <el-form-item label="说明">
          <el-input v-model="roleForm.description" type="textarea" :rows="3" placeholder="角色用途说明" />
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="roleForm.enabled" active-text="启用" inactive-text="禁用" />
        </el-form-item>
        <el-form-item label="权限键">
          <el-input
            v-model="roleForm.permissions_text"
            type="textarea"
            :rows="4"
            placeholder="settings.manage, billing.read"
          />
          <p class="form-hint">支持逗号、空格或换行分隔。第一阶段先作为规范化权限键存储，后续会接到更细粒度策略执行。</p>
        </el-form-item>

        <template v-if="editingRole">
          <el-divider content-position="left">角色绑定</el-divider>
          <div class="inline-form">
            <el-select v-model="roleBindingForm.subject_type" placeholder="绑定类型" class="role-binding-type">
              <el-option label="成员" value="membership" />
              <el-option label="组织组" value="group" />
            </el-select>
            <el-select v-model="roleBindingForm.subject_id" placeholder="选择绑定对象" class="full-width" filterable>
              <el-option
                v-for="option in roleBindingSubjectOptions"
                :key="option.value"
                :label="option.label"
                :value="option.value"
              />
            </el-select>
            <el-button type="primary" :loading="detailSaving === 'role-binding'" @click="addRoleBinding">添加绑定</el-button>
          </div>
          <p class="form-hint">成员绑定会直接授予角色；组绑定会让该组织组下的成员继承这个角色。</p>

          <el-table
            :data="editingRole.bindings || []"
            row-key="binding_id"
            empty-text="暂无角色绑定"
            class="role-bindings-table"
          >
            <el-table-column label="类型" width="110">
              <template #default="{ row }">
                <el-tag effect="plain">{{ row.subject_type === 'group' ? '组织组' : '成员' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="对象" min-width="240">
              <template #default="{ row }">
                <div>
                  <strong>{{ row.subject_label || row.subject_id }}</strong>
                  <p v-if="row.subject_secondary" class="muted">{{ row.subject_secondary }}</p>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="创建时间" min-width="170">
              <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="100" fixed="right">
              <template #default="{ row }">
                <el-button
                  link
                  type="danger"
                  :loading="detailSaving === 'role-binding-delete'"
                  @click="deleteRoleBinding(row.binding_id)"
                >
                  删除
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </template>
      </el-form>
      <template #footer>
        <el-button @click="roleDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="detailSaving === 'role'" @click="saveRole">保存</el-button>
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
            <el-option label="Enterprise LDAP / AD" value="ldap" />
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
        <template v-else-if="identityProviderForm.provider_type === 'saml'">
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
        <template v-else>
          <el-form-item label="LDAP URL">
            <el-input v-model="identityProviderForm.url" placeholder="ldaps://ldap.acme.com:636" />
          </el-form-item>
          <el-form-item label="Base DN">
            <el-input v-model="identityProviderForm.base_dn" placeholder="dc=acme,dc=com" />
          </el-form-item>
          <el-form-item label="Bind DN">
            <el-input v-model="identityProviderForm.bind_dn" placeholder="cn=svc-bind,ou=system,dc=acme,dc=com" />
          </el-form-item>
          <el-form-item label="Bind Password">
            <el-input
              v-model="identityProviderForm.bind_password"
              type="password"
              show-password
              :placeholder="editingIdentityProvider ? '留空则保留现有 bind password' : '可选，留空表示匿名搜索'"
            />
            <p v-if="editingIdentityProvider?.provider_type === 'ldap' && editingIdentityProvider?.config?.bind_password_configured" class="form-hint">
              当前已配置 bind password，留空会继续沿用原值。
            </p>
          </el-form-item>
          <el-form-item label="User Filter">
            <el-input
              v-model="identityProviderForm.user_filter"
              type="textarea"
              :rows="3"
              placeholder="(&(objectClass=person)(uid={username}))"
            />
            <p class="form-hint">支持使用 `{username}` 占位符，登录时会替换为用户输入并自动做 LDAP filter escaping。</p>
          </el-form-item>
          <el-form-item label="Group Membership Attribute">
            <el-input v-model="identityProviderForm.group_member_attribute" placeholder="memberOf" />
            <p class="form-hint">默认使用 `memberOf`。如果用户条目里带目录组 DN，登录成功后会自动同步这些组。</p>
          </el-form-item>
          <el-form-item label="Group Search Base DN">
            <el-input v-model="identityProviderForm.group_base_dn" placeholder="ou=groups,dc=acme,dc=com" />
          </el-form-item>
          <el-form-item label="Group Filter">
            <el-input
              v-model="identityProviderForm.group_filter"
              type="textarea"
              :rows="3"
              placeholder="(|(member={user_dn})(uniqueMember={user_dn})(memberUid={username}))"
            />
            <p class="form-hint">可选，支持 `{user_dn}` 和 `{username}` 占位符；适合没有 `memberOf` 的目录。</p>
          </el-form-item>
          <el-form-item label="Group Identifier Attribute">
            <el-input v-model="identityProviderForm.group_identifier_attribute" placeholder="entryUUID / objectGUID / gidNumber" />
          </el-form-item>
          <el-form-item label="Group Name Attribute">
            <el-input v-model="identityProviderForm.group_name_attribute" placeholder="displayName / cn" />
          </el-form-item>
          <el-form-item label="Subject Attribute">
            <el-input v-model="identityProviderForm.subject_attribute" placeholder="entryUUID / objectGUID / uid" />
          </el-form-item>
          <el-form-item label="Email Attribute">
            <el-input v-model="identityProviderForm.email_attribute" placeholder="mail" />
          </el-form-item>
          <el-form-item label="Username Attribute">
            <el-input v-model="identityProviderForm.username_attribute" placeholder="uid / sAMAccountName" />
          </el-form-item>
          <el-form-item label="Display Name Attribute">
            <el-input v-model="identityProviderForm.display_name_attribute" placeholder="displayName / cn" />
          </el-form-item>
          <el-form-item label="StartTLS">
            <el-switch v-model="identityProviderForm.start_tls" active-text="启用" inactive-text="关闭" />
          </el-form-item>
          <el-form-item label="跳过 TLS 校验">
            <el-switch v-model="identityProviderForm.insecure_skip_verify" active-text="跳过" inactive-text="严格校验" />
            <p class="form-hint">仅建议本地开发或明确受控环境使用。</p>
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

    <SecurityAuditDetailDrawer
      v-model="organizationAuditDetailVisible"
      :entry="selectedOrganizationAuditEntry"
      :action-label="selectedOrganizationAuditActionLabel"
      title="组织安全审计详情"
      @apply-filter="applyOrganizationAuditJumpFilter"
      @open-resource="openOrganizationAuditResource"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus/es/components/message/index'
import { ElMessageBox } from 'element-plus/es/components/message-box/index'
import SecurityAuditDetailDrawer from '@/components/SecurityAuditDetailDrawer.vue'
import {
  serverApi,
  type Organization,
  type OrganizationDomain,
  type OrganizationGroup,
  type OrganizationIdentityProvider,
  type OrganizationMembership,
  type OrganizationRole,
  type SecurityAuditEntry,
  type SecurityAuditExportJob,
  type SecurityAuditQuery
} from '@/api'

type OrganizationAuditSuccessFilter = 'all' | 'true' | 'false'

interface OrganizationAuditFilterState {
  action: string
  provider_id: string
  query: string
  success: OrganizationAuditSuccessFilter
}

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
const roles = ref<OrganizationRole[]>([])
const identityProviders = ref<OrganizationIdentityProvider[]>([])
const organizationAuditLoading = ref(false)
const organizationAuditExportLoading = ref(false)
const organizationAuditAsyncExportLoading = ref(false)
const organizationAuditCleanupLoading = ref(false)
const organizationAuditEntries = ref<SecurityAuditEntry[]>([])
const organizationAuditExportJobs = ref<SecurityAuditExportJob[]>([])
const organizationAuditTotal = ref(0)
const organizationAuditPage = ref(1)
const organizationAuditPageSize = ref(10)
const organizationAuditDetailVisible = ref(false)
const selectedOrganizationAuditEntry = ref<SecurityAuditEntry | null>(null)
const selectedOrganizationAuditActionLabel = ref('')
const organizationAuditExportJob = ref<SecurityAuditExportJob | null>(null)
const organizationAuditExportJobsLoading = ref(false)
const organizationAuditExportJobActionId = ref('')
const organizationAuditFilters = reactive<OrganizationAuditFilterState>({
  action: '',
  provider_id: '',
  query: '',
  success: 'all'
})
const domainForm = ref({ domain: '', verified: true })
const memberForm = ref({ user_id: '', status: 'active', roles_text: '' })

const groupDialogVisible = ref(false)
const editingGroup = ref<OrganizationGroup | null>(null)
const groupForm = ref(defaultGroupForm())
const roleDialogVisible = ref(false)
const editingRole = ref<OrganizationRole | null>(null)
const roleForm = ref(defaultRoleForm())
const roleBindingForm = ref(defaultRoleBindingForm())

const identityProviderDialogVisible = ref(false)
const editingIdentityProvider = ref<OrganizationIdentityProvider | null>(null)
const identityProviderForm = ref(defaultIdentityProviderForm())
const organizationAuditActionOptions = [
  { label: '创建企业身份源', value: 'identity_provider_create' },
  { label: '更新企业身份源', value: 'identity_provider_update' },
  { label: '删除企业身份源', value: 'identity_provider_delete' }
]

const route = useRoute()
const router = useRouter()
const handledOrganizationDeepLink = ref('')
let hydratingOrganizationRoute = false
let organizationAuditExportPollTimer: number | null = null
let lastSettledOrganizationAuditExportJob = ''
const organizationRouteQueryKeys = [
  'organization_id',
  'tab',
  'provider_id',
  'open',
  'audit_action',
  'audit_provider_id',
  'audit_query',
  'audit_success',
  'audit_page',
  'audit_size'
] as const
let syncingOrganizationRoute = false

function defaultGroupForm() {
  return {
    display_name: '',
    role_name: '',
    user_ids_text: ''
  }
}

function defaultRoleForm() {
  return {
    name: '',
    slug: '',
    description: '',
    enabled: true,
    permissions_text: ''
  }
}

function defaultRoleBindingForm() {
  return {
    subject_type: 'membership',
    subject_id: ''
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
    url: '',
    base_dn: '',
    bind_dn: '',
    bind_password: '',
    user_filter: '',
    group_member_attribute: '',
    group_base_dn: '',
    group_filter: '',
    group_identifier_attribute: '',
    group_name_attribute: '',
    start_tls: false,
    insecure_skip_verify: false,
    subject_attribute: '',
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

const roleBindingSubjectOptions = computed(() => {
  if (roleBindingForm.value.subject_type === 'group') {
    return groups.value.map(group => ({
      value: group.group_id,
      label: `${group.display_name || group.group_id}${group.role_name ? ` (${group.role_name})` : ''}`
    }))
  }
  return memberships.value.map(member => ({
    value: member.user_id,
    label: `${member.nickname || member.username || member.user_id} (${member.user_id})`
  }))
})

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

const openManageDialog = async (org: Organization, initialTab = 'domains') => {
  activeOrg.value = org
  activeTab.value = initialTab
  resetOrganizationSecurityAudit()
  manageDialogVisible.value = true
  groupDialogVisible.value = false
  roleDialogVisible.value = false
  identityProviderDialogVisible.value = false
  await loadOrganizationDetails()
}

const loadOrganizationDetails = async () => {
  if (!activeOrg.value) return
  detailLoading.value = true
  try {
    const [domainResponse, memberResponse, groupResponse, roleResponse, identityProviderResponse] = await Promise.all([
      serverApi.getOrganizationDomains(activeOrg.value.organization_id),
      serverApi.getOrganizationMemberships(activeOrg.value.organization_id),
      serverApi.getOrganizationGroups(activeOrg.value.organization_id),
      serverApi.getOrganizationRoles(activeOrg.value.organization_id),
      serverApi.getOrganizationIdentityProviders(activeOrg.value.organization_id)
    ])
    domains.value = domainResponse.domains || []
    memberships.value = memberResponse.memberships || []
    groups.value = groupResponse.groups || []
    roles.value = roleResponse.roles || []
    identityProviders.value = identityProviderResponse.identity_providers || []
    syncEditingRoleFromList()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载组织详情失败')
  } finally {
    detailLoading.value = false
  }
}

const resetOrganizationSecurityAudit = () => {
  organizationAuditEntries.value = []
  organizationAuditTotal.value = 0
  organizationAuditPage.value = 1
  organizationAuditPageSize.value = 10
  organizationAuditFilters.action = ''
  organizationAuditFilters.provider_id = ''
  organizationAuditFilters.query = ''
  organizationAuditFilters.success = 'all'
}

const buildOrganizationSecurityAuditQuery = (overrides: Partial<SecurityAuditQuery> = {}): SecurityAuditQuery => {
  return {
    organization_id: activeOrg.value?.organization_id,
    resource_type: 'identity_provider',
    action: organizationAuditFilters.action || undefined,
    provider_id: organizationAuditFilters.provider_id.trim() || undefined,
    query: organizationAuditFilters.query.trim() || undefined,
    success: organizationAuditFilters.success === 'all' ? undefined : organizationAuditFilters.success === 'true',
    ...overrides
  }
}

const applyOrganizationAuditRouteState = () => {
  const query = route.query
  organizationAuditFilters.action = typeof query.audit_action === 'string' ? query.audit_action : ''
  organizationAuditFilters.provider_id = typeof query.audit_provider_id === 'string' ? query.audit_provider_id : ''
  organizationAuditFilters.query = typeof query.audit_query === 'string' ? query.audit_query : ''
  organizationAuditFilters.success =
    query.audit_success === 'true' || query.audit_success === 'false'
      ? query.audit_success
      : 'all'

  const page = typeof query.audit_page === 'string' ? Number.parseInt(query.audit_page, 10) : NaN
  organizationAuditPage.value = Number.isFinite(page) && page > 0 ? page : 1
  const size = typeof query.audit_size === 'string' ? Number.parseInt(query.audit_size, 10) : NaN
  organizationAuditPageSize.value = Number.isFinite(size) && size > 0 ? size : 10
}

const buildOrganizationAuditRouteQuery = () => {
  const preservedQuery = Object.fromEntries(
    Object.entries(route.query).filter(([key]) => !organizationRouteQueryKeys.includes(key as (typeof organizationRouteQueryKeys)[number]))
  ) as Record<string, string>

  const nextQuery: Record<string, string> = {
    ...preservedQuery,
    organization_id: activeOrg.value?.organization_id || '',
    tab: 'security-audit'
  }
  if (organizationAuditFilters.action) nextQuery.audit_action = organizationAuditFilters.action
  if (organizationAuditFilters.provider_id.trim()) nextQuery.audit_provider_id = organizationAuditFilters.provider_id.trim()
  if (organizationAuditFilters.query.trim()) nextQuery.audit_query = organizationAuditFilters.query.trim()
  if (organizationAuditFilters.success !== 'all') nextQuery.audit_success = organizationAuditFilters.success
  if (organizationAuditPage.value > 1) nextQuery.audit_page = String(organizationAuditPage.value)
  if (organizationAuditPageSize.value !== 10) nextQuery.audit_size = String(organizationAuditPageSize.value)
  return nextQuery
}

const syncOrganizationAuditRoute = async () => {
  if (!activeOrg.value) return
  syncingOrganizationRoute = true
  try {
    await router.replace({
      name: 'Organizations',
      query: buildOrganizationAuditRouteQuery()
    })
  } finally {
    syncingOrganizationRoute = false
  }
}

const loadOrganizationSecurityAudit = async () => {
  if (!activeOrg.value) return
  organizationAuditLoading.value = true
  try {
    const response = await serverApi.getSecurityAudit(buildOrganizationSecurityAuditQuery({
      page: organizationAuditPage.value,
      size: organizationAuditPageSize.value
    }))
    organizationAuditEntries.value = response.audit || []
    organizationAuditTotal.value = response.total || 0
    organizationAuditPage.value = response.page || organizationAuditPage.value
    organizationAuditPageSize.value = response.size || organizationAuditPageSize.value
  } catch (error: any) {
    organizationAuditEntries.value = []
    organizationAuditTotal.value = 0
    ElMessage.error(error?.response?.data?.error || '加载组织安全审计失败')
  } finally {
    organizationAuditLoading.value = false
  }
}

const loadOrganizationAuditExportJobs = async () => {
  if (!activeOrg.value) return
  organizationAuditExportJobsLoading.value = true
  try {
    const response = await serverApi.listSecurityAuditExportJobs({
      page: 1,
      size: 8,
      organization_id: activeOrg.value.organization_id
    })
    organizationAuditExportJobs.value = response.jobs || []
  } catch {
    organizationAuditExportJobs.value = []
  } finally {
    organizationAuditExportJobsLoading.value = false
  }
}

const clearTrackedOrganizationAuditExportJobIfNeeded = (jobId: string) => {
  if (organizationAuditExportJob.value?.job_id === jobId) {
    dismissOrganizationAuditExportJob()
  }
}

const handleOrganizationAuditFilterChange = async () => {
  organizationAuditPage.value = 1
  await syncOrganizationAuditRoute()
  await loadOrganizationSecurityAudit()
}

const handleOrganizationAuditPageChange = async (page: number) => {
  organizationAuditPage.value = page
  await syncOrganizationAuditRoute()
  await loadOrganizationSecurityAudit()
}

const handleOrganizationAuditSizeChange = async (size: number) => {
  organizationAuditPageSize.value = size
  organizationAuditPage.value = 1
  await syncOrganizationAuditRoute()
  await loadOrganizationSecurityAudit()
}

const showOrganizationAuditFailures = async () => {
  organizationAuditFilters.success = 'false'
  organizationAuditPage.value = 1
  await syncOrganizationAuditRoute()
  await loadOrganizationSecurityAudit()
}

const resetOrganizationAuditFilters = async () => {
  organizationAuditFilters.action = ''
  organizationAuditFilters.provider_id = ''
  organizationAuditFilters.query = ''
  organizationAuditFilters.success = 'all'
  organizationAuditPage.value = 1
  organizationAuditPageSize.value = 10
  await syncOrganizationAuditRoute()
  await loadOrganizationSecurityAudit()
}

const writeClipboard = async (value: string) => {
  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value)
    return
  }
  const textarea = document.createElement('textarea')
  textarea.value = value
  textarea.setAttribute('readonly', 'readonly')
  textarea.style.position = 'absolute'
  textarea.style.left = '-9999px'
  document.body.appendChild(textarea)
  textarea.select()
  const succeeded = document.execCommand('copy')
  document.body.removeChild(textarea)
  if (!succeeded) throw new Error('copy failed')
}

const copyOrganizationAuditFilterLink = async () => {
  if (!activeOrg.value) return
  await syncOrganizationAuditRoute()
  const resolved = router.resolve({
    name: 'Organizations',
    query: buildOrganizationAuditRouteQuery()
  })
  const base = typeof window !== 'undefined' ? window.location.origin : ''
  const targetURL = `${base}${resolved.href}`
  try {
    await writeClipboard(targetURL)
    ElMessage.success('组织安全审计筛选链接已复制')
  } catch {
    ElMessage.error('复制组织安全审计筛选链接失败')
  }
}

const exportOrganizationSecurityAudit = async () => {
  if (!activeOrg.value) return
  organizationAuditExportLoading.value = true
  try {
    const blob = await serverApi.exportSecurityAuditCSV(buildOrganizationSecurityAuditQuery())
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    const timestamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19)
    link.href = url
    link.download = `organization-security-audit-${activeOrg.value.slug || activeOrg.value.organization_id}-${timestamp}.csv`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)
    ElMessage.success('组织安全审计 CSV 导出成功')
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '导出组织安全审计失败')
  } finally {
    organizationAuditExportLoading.value = false
  }
}

const clearOrganizationAuditExportPollTimer = () => {
  if (organizationAuditExportPollTimer !== null) {
    window.clearTimeout(organizationAuditExportPollTimer)
    organizationAuditExportPollTimer = null
  }
}

const dismissOrganizationAuditExportJob = () => {
  clearOrganizationAuditExportPollTimer()
  organizationAuditExportJob.value = null
  lastSettledOrganizationAuditExportJob = ''
}

const organizationAuditExportJobAlertType = computed(() => {
  const status = organizationAuditExportJob.value?.status
  if (status === 'completed') return 'success'
  if (status === 'failed') return 'error'
  return 'info'
})

const organizationAuditExportJobTitle = computed(() => {
  const job = organizationAuditExportJob.value
  if (!job) return ''
  if (job.status === 'completed') return `组织后台导出已完成 · ${job.job_id}`
  if (job.status === 'failed') return `组织后台导出失败 · ${job.job_id}`
  return `组织后台导出进行中 · ${job.job_id}`
})

const organizationAuditExportJobSummary = computed(() => {
  const job = organizationAuditExportJob.value
  if (!job) return ''
  if (job.status === 'completed') {
    const parts = [`共匹配 ${job.total_count} 条`, `已导出 ${job.row_count} 条`]
    if (job.truncated) parts.push('结果已按上限截断')
    return parts.join('，')
  }
  if (job.status === 'failed') {
    return job.error || '组织安全审计后台导出失败'
  }
  return '服务器正在后台准备当前组织的安全审计 CSV，完成后可直接下载。'
})

const scheduleOrganizationAuditExportPoll = (jobId: string) => {
  clearOrganizationAuditExportPollTimer()
  organizationAuditExportPollTimer = window.setTimeout(() => {
    refreshOrganizationAuditExportJob(jobId, true)
  }, 1500)
}

const applyOrganizationAuditExportJob = (job: SecurityAuditExportJob, silent = false) => {
  organizationAuditExportJob.value = job
  if (job.status === 'pending' || job.status === 'running') {
    scheduleOrganizationAuditExportPoll(job.job_id)
    return
  }
  clearOrganizationAuditExportPollTimer()
  void loadOrganizationAuditExportJobs()
  const settledKey = `${job.job_id}:${job.status}`
  if (silent || lastSettledOrganizationAuditExportJob === settledKey) return
  lastSettledOrganizationAuditExportJob = settledKey
  if (job.status === 'completed') {
    ElMessage.success('组织安全审计后台导出已完成')
  } else if (job.status === 'failed') {
    ElMessage.error(job.error || '组织安全审计后台导出失败')
  }
}

const refreshOrganizationAuditExportJob = async (jobId?: string, silent = false) => {
  const targetJobID = jobId || organizationAuditExportJob.value?.job_id
  if (!targetJobID) return
  try {
    const response = await serverApi.getSecurityAuditExportJob(targetJobID)
    applyOrganizationAuditExportJob(response.job, silent)
  } catch (error: any) {
    if (!silent) {
      ElMessage.error(error?.response?.data?.error || '刷新组织后台导出任务失败')
    }
  }
}

const createOrganizationAuditExportJob = async () => {
  if (!activeOrg.value) return
  organizationAuditAsyncExportLoading.value = true
  try {
    const response = await serverApi.createSecurityAuditExportJob(buildOrganizationSecurityAuditQuery())
    lastSettledOrganizationAuditExportJob = ''
    applyOrganizationAuditExportJob(response.job, true)
    await loadOrganizationAuditExportJobs()
    ElMessage.success(response.message || '已创建组织后台导出任务')
    await refreshOrganizationAuditExportJob(response.job.job_id)
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '创建组织后台导出任务失败')
  } finally {
    organizationAuditAsyncExportLoading.value = false
  }
}

const downloadOrganizationAuditExportJob = async () => {
  const job = organizationAuditExportJob.value
  if (!job?.download_ready) return
  try {
    const blob = await serverApi.downloadSecurityAuditExportJob(job.job_id)
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = job.filename || `organization-security-audit-${job.job_id}.csv`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)
    ElMessage.success('组织安全审计后台导出已下载')
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '下载组织后台导出结果失败')
  }
}

const trackOrganizationAuditExportJob = async (job: SecurityAuditExportJob) => {
  organizationAuditExportJob.value = job
  lastSettledOrganizationAuditExportJob = ''
  await refreshOrganizationAuditExportJob(job.job_id, true)
}

const downloadListedOrganizationAuditExportJob = async (job: SecurityAuditExportJob) => {
  await trackOrganizationAuditExportJob(job)
  await downloadOrganizationAuditExportJob()
}

const deleteOrganizationAuditExportJobEntry = async (job: SecurityAuditExportJob) => {
  try {
    await ElMessageBox.confirm(
      `确定删除后台导出任务 ${job.job_id} 吗？已生成的 CSV 结果也会一并移除。`,
      '删除后台导出任务',
      {
        confirmButtonText: '删除',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )
  } catch {
    return
  }
  organizationAuditExportJobActionId.value = `delete:${job.job_id}`
  try {
    const response = await serverApi.deleteSecurityAuditExportJob(job.job_id)
    clearTrackedOrganizationAuditExportJobIfNeeded(job.job_id)
    ElMessage.success(response.message || '后台导出任务已删除')
    await loadOrganizationAuditExportJobs()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '删除后台导出任务失败')
  } finally {
    organizationAuditExportJobActionId.value = ''
  }
}

const cleanupOrganizationAuditExportJobs = async () => {
  if (!activeOrg.value) return
  try {
    await ElMessageBox.confirm(
      `确定按当前保留策略清理当前组织已完成或已失败的后台导出任务吗？运行中的任务不会受影响。`,
      '清理旧导出任务',
      {
        confirmButtonText: '清理',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )
  } catch {
    return
  }
  organizationAuditCleanupLoading.value = true
  try {
    const response = await serverApi.cleanupSecurityAuditExportJobs({
      organization_id: activeOrg.value.organization_id
    })
    if (organizationAuditExportJob.value && (organizationAuditExportJob.value.status === 'completed' || organizationAuditExportJob.value.status === 'failed')) {
      await refreshOrganizationAuditExportJob(organizationAuditExportJob.value.job_id, true).catch(() => dismissOrganizationAuditExportJob())
    }
    ElMessage.success(response.result.deleted > 0 ? `已清理 ${response.result.deleted} 个旧导出任务` : '没有可清理的旧导出任务')
    await loadOrganizationAuditExportJobs()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '清理旧导出任务失败')
  } finally {
    organizationAuditCleanupLoading.value = false
  }
}

const openOrganizationAuditDetail = (entry: SecurityAuditEntry) => {
  selectedOrganizationAuditEntry.value = entry
  selectedOrganizationAuditActionLabel.value = formatSecurityAuditAction(entry.action)
  organizationAuditDetailVisible.value = true
}

const applyOrganizationAuditJumpFilter = async (filter: Partial<SecurityAuditQuery>) => {
  organizationAuditFilters.action = ''
  organizationAuditFilters.provider_id = filter.provider_id || ''
  organizationAuditFilters.query = ''
  organizationAuditFilters.success = typeof filter.success === 'boolean' ? (filter.success ? 'true' : 'false') : 'all'
  organizationAuditPage.value = 1
  organizationAuditDetailVisible.value = false
  activeTab.value = 'security-audit'
  await syncOrganizationAuditRoute()
  await loadOrganizationSecurityAudit()
}

const openOrganizationAuditResource = async (resource: {
  resource_type: string
  client_id?: string
  provider_id?: string
  organization_id?: string
}) => {
  if (resource.resource_type === 'identity_provider' && resource.provider_id) {
    const targetProvider = identityProviders.value.find(provider => provider.identity_provider_id === resource.provider_id)
    if (!targetProvider) {
      ElMessage.warning('该企业身份源可能已删除，无法直接打开配置')
      return
    }
    organizationAuditDetailVisible.value = false
    activeTab.value = 'identity-providers'
    openIdentityProviderDialog(targetProvider)
    return
  }
  ElMessage.info('当前审计记录暂不支持直接打开对应资源')
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

const syncEditingRoleFromList = () => {
  if (!editingRole.value) return
  const fresh = roles.value.find(role => role.role_id === editingRole.value?.role_id)
  if (fresh) {
    editingRole.value = fresh
  }
}

const openRoleDialog = (role?: OrganizationRole) => {
  editingRole.value = role || null
  roleForm.value = {
    name: role?.name || '',
    slug: role?.slug || '',
    description: role?.description || '',
    enabled: role?.enabled ?? true,
    permissions_text: role?.permissions?.join(', ') || ''
  }
  roleBindingForm.value = defaultRoleBindingForm()
  roleDialogVisible.value = true
}

const saveRole = async () => {
  if (!activeOrg.value) return
  detailSaving.value = 'role'
  try {
    const payload = {
      name: roleForm.value.name,
      slug: roleForm.value.slug || undefined,
      description: roleForm.value.description || undefined,
      enabled: roleForm.value.enabled,
      permissions: parsePermissionKeys(roleForm.value.permissions_text)
    }
    if (editingRole.value) {
      await serverApi.updateOrganizationRole(activeOrg.value.organization_id, editingRole.value.role_id, payload)
    } else {
      await serverApi.createOrganizationRole(activeOrg.value.organization_id, payload)
    }
    ElMessage.success('组织角色已保存')
    await loadOrganizationDetails()
    roleDialogVisible.value = false
    editingRole.value = null
    roleForm.value = defaultRoleForm()
    roleBindingForm.value = defaultRoleBindingForm()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '保存组织角色失败')
  } finally {
    detailSaving.value = ''
  }
}

const deleteRole = async (role: OrganizationRole) => {
  if (!activeOrg.value) return
  try {
    await ElMessageBox.confirm(`确定删除组织角色 ${role.name || role.slug} 吗？角色绑定和权限也会一起删除。`, '删除组织角色', {
      type: 'warning'
    })
  } catch {
    return
  }
  try {
    await serverApi.deleteOrganizationRole(activeOrg.value.organization_id, role.role_id)
    ElMessage.success('组织角色已删除')
    if (editingRole.value?.role_id === role.role_id) {
      roleDialogVisible.value = false
      editingRole.value = null
      roleForm.value = defaultRoleForm()
    }
    await loadOrganizationDetails()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '删除组织角色失败')
  }
}

const addRoleBinding = async () => {
  if (!activeOrg.value || !editingRole.value) return
  if (!roleBindingForm.value.subject_id) {
    ElMessage.warning('请选择要绑定的成员或组织组')
    return
  }
  detailSaving.value = 'role-binding'
  try {
    await serverApi.createOrganizationRoleBinding(activeOrg.value.organization_id, editingRole.value.role_id, {
      subject_type: roleBindingForm.value.subject_type,
      subject_id: roleBindingForm.value.subject_id
    })
    ElMessage.success('角色绑定已创建')
    roleBindingForm.value = defaultRoleBindingForm()
    await loadOrganizationDetails()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '创建角色绑定失败')
  } finally {
    detailSaving.value = ''
  }
}

const deleteRoleBinding = async (bindingId: string) => {
  if (!activeOrg.value || !editingRole.value) return
  try {
    await ElMessageBox.confirm('确定删除这条角色绑定吗？', '删除角色绑定', { type: 'warning' })
  } catch {
    return
  }
  detailSaving.value = 'role-binding-delete'
  try {
    await serverApi.deleteOrganizationRoleBinding(activeOrg.value.organization_id, editingRole.value.role_id, bindingId)
    ElMessage.success('角色绑定已删除')
    await loadOrganizationDetails()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '删除角色绑定失败')
  } finally {
    detailSaving.value = ''
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
    url: provider?.config?.url || '',
    base_dn: provider?.config?.base_dn || '',
    bind_dn: provider?.config?.bind_dn || '',
    bind_password: '',
    user_filter: provider?.config?.user_filter || '',
    group_member_attribute: provider?.config?.group_member_attribute || '',
    group_base_dn: provider?.config?.group_base_dn || '',
    group_filter: provider?.config?.group_filter || '',
    group_identifier_attribute: provider?.config?.group_identifier_attribute || '',
    group_name_attribute: provider?.config?.group_name_attribute || '',
    start_tls: provider?.config?.start_tls ?? false,
    insecure_skip_verify: provider?.config?.insecure_skip_verify ?? false,
    subject_attribute: provider?.config?.subject_attribute || '',
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
      url: identityProviderForm.value.url || undefined,
      base_dn: identityProviderForm.value.base_dn || undefined,
      bind_dn: identityProviderForm.value.bind_dn || undefined,
      bind_password: identityProviderForm.value.bind_password || undefined,
      user_filter: identityProviderForm.value.user_filter || undefined,
      group_member_attribute: identityProviderForm.value.group_member_attribute || undefined,
      group_base_dn: identityProviderForm.value.group_base_dn || undefined,
      group_filter: identityProviderForm.value.group_filter || undefined,
      group_identifier_attribute: identityProviderForm.value.group_identifier_attribute || undefined,
      group_name_attribute: identityProviderForm.value.group_name_attribute || undefined,
      start_tls: identityProviderForm.value.start_tls,
      insecure_skip_verify: identityProviderForm.value.insecure_skip_verify,
      subject_attribute: identityProviderForm.value.subject_attribute || undefined,
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
    if (activeTab.value === 'security-audit') await loadOrganizationSecurityAudit()
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
    if (activeTab.value === 'security-audit') await loadOrganizationSecurityAudit()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '删除企业登录源失败')
  }
}

const openIdentityProviderAudit = async (provider: OrganizationIdentityProvider) => {
  const alreadyOnAuditTab = activeTab.value === 'security-audit'
  organizationAuditFilters.action = ''
  organizationAuditFilters.provider_id = provider.identity_provider_id
  organizationAuditFilters.query = ''
  organizationAuditFilters.success = 'all'
  organizationAuditPage.value = 1
  activeTab.value = 'security-audit'
  await syncOrganizationAuditRoute()
  if (alreadyOnAuditTab) {
    await loadOrganizationSecurityAudit()
  }
}

const openIdentityProviderFailureAudit = async (provider: OrganizationIdentityProvider) => {
  const alreadyOnAuditTab = activeTab.value === 'security-audit'
  organizationAuditFilters.action = ''
  organizationAuditFilters.provider_id = provider.identity_provider_id
  organizationAuditFilters.query = ''
  organizationAuditFilters.success = 'false'
  organizationAuditPage.value = 1
  activeTab.value = 'security-audit'
  await syncOrganizationAuditRoute()
  if (alreadyOnAuditTab) {
    await loadOrganizationSecurityAudit()
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

const parsePermissionKeys = (raw: string) =>
  raw
    .split(/[\n,\s]+/)
    .map(item => item.trim())
    .filter(Boolean)

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

const identityProviderEndpointLabel = (provider: OrganizationIdentityProvider) => {
  if (provider.provider_type === 'saml') {
    return provider.config?.idp_metadata_url || '-'
  }
  if (provider.provider_type === 'ldap') {
    return provider.config?.url || '-'
  }
  return provider.config?.issuer || '-'
}

const identityProviderCallbackLabel = (provider: OrganizationIdentityProvider) => {
  if (provider.provider_type === 'saml') {
    return provider.config?.acs_url || '-'
  }
  if (provider.provider_type === 'ldap') {
    return provider.config?.base_dn || '-'
  }
  return provider.config?.redirect_uri || '-'
}

const identityProviderSummary = (provider: OrganizationIdentityProvider) => {
  if (provider.provider_type === 'saml') {
    return provider.config?.entity_id || provider.config?.name_id_format || '-'
  }
  if (provider.provider_type === 'ldap') {
    return provider.config?.group_member_attribute || provider.config?.subject_attribute || provider.config?.user_filter || '-'
  }
  return provider.config?.scopes?.join(', ') || '-'
}

const identityProviderConfigTagType = (provider: OrganizationIdentityProvider) => {
  if (provider.provider_type === 'saml') {
    return provider.config?.idp_metadata_xml_configured ? 'success' : 'info'
  }
  if (provider.provider_type === 'ldap') {
    return provider.config?.bind_password_configured ? 'success' : 'info'
  }
  return provider.config?.client_secret_configured ? 'success' : 'warning'
}

const identityProviderConfigTagText = (provider: OrganizationIdentityProvider) => {
  if (provider.provider_type === 'saml') {
    return provider.config?.idp_metadata_xml_configured ? '内置元数据' : 'URL 元数据'
  }
  if (provider.provider_type === 'ldap') {
    return provider.config?.bind_password_configured ? '已配置 Bind' : '匿名/无密码'
  }
  return provider.config?.client_secret_configured ? '已配置' : '未配置'
}

const formatSecurityAuditAction = (action: string) => {
  const labels: Record<string, string> = {
    identity_provider_create: '创建企业身份源',
    identity_provider_update: '更新企业身份源',
    identity_provider_delete: '删除企业身份源'
  }
  return labels[action] || action || '-'
}

const formatOrganizationSecurityAuditDetails = (entry: SecurityAuditEntry) => {
  if (entry.error) return entry.error
  const details = entry.details || {}
  const parts: string[] = []
  if (details.provider_type) parts.push(`类型 ${details.provider_type.toUpperCase()}`)
  if (details.provider_id) parts.push(`Provider ${details.provider_id}`)
  if (details.slug) parts.push(`Slug ${details.slug}`)
  if (details.previous_slug) parts.push(`原 Slug ${details.previous_slug}`)
  if (details.name) parts.push(`名称 ${details.name}`)
  if (details.organization_id) parts.push(`组织 ${details.organization_id}`)
  if (details.enabled) parts.push(`启用 ${details.enabled === 'true' ? '是' : '否'}`)
  if (details.priority) parts.push(`优先级 ${details.priority}`)
  if (details.is_default) parts.push(`默认 ${details.is_default === 'true' ? '是' : '否'}`)
  if (details.auto_redirect) parts.push(`自动跳转 ${details.auto_redirect === 'true' ? '是' : '否'}`)
  if (details.stage) parts.push(`阶段 ${details.stage}`)
  if (details.reason) parts.push(`原因 ${details.reason}`)
  return parts.length > 0 ? parts.join(' | ') : '-'
}

const formatOrganizationAuditExportJobStatus = (status: string) => {
  const labels: Record<string, string> = {
    pending: '排队中',
    running: '导出中',
    completed: '已完成',
    failed: '失败'
  }
  return labels[status] || status || '-'
}

const organizationAuditExportJobTagType = (status: string) => {
  if (status === 'completed') return 'success'
  if (status === 'failed') return 'danger'
  return 'info'
}

const formatOrganizationAuditExportJobScope = (job: SecurityAuditExportJob) => {
  const query = job.query || {}
  const parts: string[] = []
  if (query.provider_id) parts.push(`Provider ${query.provider_id}`)
  if (query.action) parts.push(`动作 ${formatSecurityAuditAction(query.action)}`)
  if (query.query) parts.push(`关键词 ${query.query}`)
  return parts.length > 0 ? parts.join(' | ') : '当前组织全部企业身份源审计'
}

const formatOrganizationAuditExportJobResult = (job: SecurityAuditExportJob) => {
  if (job.status === 'failed') return job.error || '-'
  if (job.status === 'completed') {
    const parts = [`${job.row_count} / ${job.total_count}`]
    if (job.truncated) parts.push('已截断')
    return parts.join(' | ')
  }
  return '-'
}

watch(activeTab, async (tab) => {
  if (hydratingOrganizationRoute) return
  if (tab === 'security-audit' && activeOrg.value) {
    await syncOrganizationAuditRoute()
    await Promise.all([loadOrganizationSecurityAudit(), loadOrganizationAuditExportJobs()])
  }
})

const normalizeOrganizationTab = (raw: string) => {
  const allowed = new Set(['domains', 'members', 'groups', 'roles', 'identity-providers', 'security-audit'])
  return allowed.has(raw) ? raw : 'domains'
}

const handleOrganizationRouteDeepLink = async () => {
  const organizationID = typeof route.query.organization_id === 'string' ? route.query.organization_id : ''
  if (!organizationID) {
    handledOrganizationDeepLink.value = ''
    return
  }

  const tab = normalizeOrganizationTab(typeof route.query.tab === 'string' ? route.query.tab : 'domains')
  const providerID = typeof route.query.provider_id === 'string' ? route.query.provider_id : ''
  const open = typeof route.query.open === 'string' ? route.query.open : ''
  const deepLinkKey = [
    organizationID,
    tab,
    providerID,
    open,
    typeof route.query.audit_action === 'string' ? route.query.audit_action : '',
    typeof route.query.audit_provider_id === 'string' ? route.query.audit_provider_id : '',
    typeof route.query.audit_query === 'string' ? route.query.audit_query : '',
    typeof route.query.audit_success === 'string' ? route.query.audit_success : '',
    typeof route.query.audit_page === 'string' ? route.query.audit_page : '',
    typeof route.query.audit_size === 'string' ? route.query.audit_size : ''
  ].join('|')
  if (handledOrganizationDeepLink.value === deepLinkKey) {
    return
  }
  handledOrganizationDeepLink.value = deepLinkKey
  hydratingOrganizationRoute = true
  try {
    let organization = organizations.value.find(item => item.organization_id === organizationID)
    if (!organization) {
      try {
        const response = await serverApi.getOrganization(organizationID)
        organization = response.organization
      } catch (error: any) {
        ElMessage.error(error?.response?.data?.error || '加载深链组织失败')
        return
      }
    }

    const shouldReloadDialog =
      !manageDialogVisible.value ||
      activeOrg.value?.organization_id !== organizationID ||
      activeTab.value !== tab

    if (shouldReloadDialog) {
      await openManageDialog(organization, tab)
    }

    if (tab === 'security-audit') {
      applyOrganizationAuditRouteState()
      await Promise.all([loadOrganizationSecurityAudit(), loadOrganizationAuditExportJobs()])
    }

    if (providerID && open === 'edit') {
      const targetProvider = identityProviders.value.find(provider => provider.identity_provider_id === providerID || provider.slug === providerID)
      if (targetProvider) {
        openIdentityProviderDialog(targetProvider)
      } else {
        ElMessage.warning('指定的企业身份源不存在或已删除')
      }
    }
  } finally {
    hydratingOrganizationRoute = false
  }
}

watch(
  () => route.query,
  async () => {
    if (syncingOrganizationRoute) return
    await handleOrganizationRouteDeepLink()
  },
  { deep: true }
)

onMounted(async () => {
  await loadOrganizations()
  await handleOrganizationRouteDeepLink()
})

onUnmounted(() => {
  clearOrganizationAuditExportPollTimer()
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

  .export-job-alert {
    margin-bottom: 16px;
  }

  .audit-jobs-card {
    margin-bottom: 16px;
  }

  .export-job-content {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
  }

  .export-job-actions {
    display: flex;
    align-items: center;
    gap: 8px;
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

  .audit-toolbar {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
    flex-wrap: wrap;
  }

  .audit-pagination {
    display: flex;
    justify-content: flex-end;
    margin-top: 18px;
  }

  .full-width {
    width: 100%;
  }

  .role-binding-type {
    min-width: 140px;
  }

  .role-bindings-table {
    margin-top: 12px;
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

  .events {
    color: #334155;
    line-height: 1.5;
  }
}

@media (max-width: 900px) {
  .organizations-page {
    .card-header,
    .toolbar,
    .inline-form,
    .identity-provider-header,
    .audit-toolbar {
      flex-direction: column;
      align-items: stretch;
    }
  }
}
</style>
