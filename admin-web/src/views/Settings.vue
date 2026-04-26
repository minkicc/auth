/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

<template>
  <div class="settings-container">
    <el-card class="settings-card">
      <template #header>
        <div class="card-header">
          <div>
            <h2>Administrators</h2>
            <p class="subhead">配置文件中的管理员仅供运维维护。后台里新增和删除的是数据库管理员，适合日常授权。</p>
          </div>
          <div class="toolbar-actions">
            <el-button :loading="adminLoading" @click="loadAdmins">刷新</el-button>
          </div>
        </div>
      </template>

      <el-alert
        v-if="adminLoadError"
        class="plugin-alert"
        :title="adminLoadError"
        type="warning"
        :closable="false"
        show-icon
      />

      <div class="inline-form">
        <el-input
          v-model="adminCreateForm.user_ref"
          placeholder="输入用户 ID 或用户名"
          @keyup.enter="createAdmin"
        />
        <el-button
          type="primary"
          :loading="adminActionLoadingId === 'create'"
          @click="createAdmin"
        >
          添加管理员
        </el-button>
      </div>

      <el-table
        v-loading="adminLoading"
        :data="admins"
        row-key="user_id"
        empty-text="暂无管理员"
      >
        <el-table-column prop="user_id" label="用户 ID" min-width="190" />
        <el-table-column label="用户名 / 昵称" min-width="180">
          <template #default="{ row }">
            <div class="stacked-copy">
              <strong>{{ row.username || '-' }}</strong>
              <span>{{ row.nickname || '-' }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="120" />
        <el-table-column label="来源" min-width="150">
          <template #default="{ row }">
            <div class="tag-cluster">
              <el-tag
                v-for="source in formatAdminSources(row.sources)"
                :key="source"
                effect="plain"
                type="info"
              >
                {{ source }}
              </el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="130" align="right">
          <template #default="{ row }">
            <el-button
              v-if="row.editable"
              text
              type="danger"
              :loading="adminActionLoadingId === `delete:${row.user_id}`"
              @click="deleteAdmin(row)"
            >
              删除
            </el-button>
            <span v-else class="muted-copy">仅配置可改</span>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card class="settings-card security-card">
      <template #header>
        <div class="card-header">
          <div>
            <h2>Secrets Security</h2>
            <p class="subhead">查看当前敏感配置加密状态，并把旧明文或旧 key 的托管配置统一重写到当前主密钥。</p>
          </div>
          <div class="toolbar-actions">
            <el-button :loading="securityLoading" @click="loadSecurityStatus">刷新</el-button>
            <el-button
              type="primary"
              :disabled="!securityStatus?.enabled"
              :loading="securityResealLoading"
              @click="resealManagedSecrets"
            >
              重写存量 Secrets
            </el-button>
          </div>
        </div>
      </template>

      <el-alert
        v-if="securityLoadError"
        class="plugin-alert"
        :title="securityLoadError"
        type="warning"
        :closable="false"
        show-icon
      />

      <div v-if="securityStatus" class="security-grid">
        <div class="security-metric">
          <strong>数据库加密</strong>
          <span>{{ securityStatus.enabled ? '已启用' : '未启用' }}</span>
        </div>
        <div class="security-metric">
          <strong>Fallback Keys</strong>
          <span>{{ securityStatus.fallback_key_count }}</span>
        </div>
        <div class="security-metric">
          <strong>托管 OIDC Clients</strong>
          <span>{{ securityStatus.managed_oidc_client_count }}</span>
        </div>
        <div class="security-metric">
          <strong>企业身份源</strong>
          <span>{{ securityStatus.managed_identity_provider_count }}</span>
        </div>
      </div>

      <el-alert
        class="plugin-alert"
        :title="securityStatus?.enabled ? '配置了当前加密主密钥后，可用“重写存量 Secrets”把旧明文记录或旧 key 加密记录统一重写为当前主密钥。' : '当前未配置 secrets.encryption_key / secrets.encryption_key_env，因此后台托管敏感配置还不会自动按主密钥重写。'"
        :type="securityStatus?.enabled ? 'success' : 'info'"
        :closable="false"
        show-icon
      />

      <el-card class="audit-card" shadow="never">
        <template #header>
          <div class="catalog-header">
            <div>
              <strong>安全审计</strong>
              <p>记录后台敏感配置变更和托管 secrets 重写，支持按动作、资源类型、精确资源 ID、操作人和资源关键词筛选。</p>
            </div>
          </div>
        </template>

        <div class="audit-toolbar">
          <el-select
            v-model="securityAuditFilters.action"
            clearable
            placeholder="全部动作"
            @change="handleSecurityAuditFilterChange"
          >
            <el-option v-for="option in securityAuditActionOptions" :key="option.value" :label="option.label" :value="option.value" />
          </el-select>
          <el-select
            v-model="securityAuditFilters.resource_type"
            clearable
            placeholder="全部资源"
            @change="handleSecurityAuditFilterChange"
          >
            <el-option v-for="option in securityAuditResourceOptions" :key="option.value" :label="option.label" :value="option.value" />
          </el-select>
          <el-input
            v-model="securityAuditFilters.client_id"
            clearable
            placeholder="精确 client_id"
            @clear="handleSecurityAuditFilterChange"
            @keyup.enter="handleSecurityAuditFilterChange"
          />
          <el-input
            v-model="securityAuditFilters.provider_id"
            clearable
            placeholder="精确 provider_id"
            @clear="handleSecurityAuditFilterChange"
            @keyup.enter="handleSecurityAuditFilterChange"
          />
          <el-input
            v-model="securityAuditFilters.organization_id"
            clearable
            placeholder="精确 organization_id"
            @clear="handleSecurityAuditFilterChange"
            @keyup.enter="handleSecurityAuditFilterChange"
          />
          <el-select
            v-model="securityAuditFilters.success"
            placeholder="全部结果"
            @change="handleSecurityAuditFilterChange"
          >
            <el-option label="全部结果" value="all" />
            <el-option label="仅成功" value="true" />
            <el-option label="仅失败" value="false" />
          </el-select>
          <el-input
            v-model="securityAuditFilters.actor_id"
            clearable
            placeholder="搜索操作人"
            @clear="handleSecurityAuditFilterChange"
            @keyup.enter="handleSecurityAuditFilterChange"
          />
          <el-input
            v-model="securityAuditFilters.query"
            clearable
            placeholder="搜索资源 ID / slug / 错误"
            @clear="handleSecurityAuditFilterChange"
            @keyup.enter="handleSecurityAuditFilterChange"
          />
          <el-date-picker
            v-model="securityAuditTimeRange"
            type="datetimerange"
            range-separator="至"
            start-placeholder="开始时间"
            end-placeholder="结束时间"
            @change="handleSecurityAuditFilterChange"
          />
          <el-button :loading="securityAuditLoading" @click="loadSecurityAudit">刷新审计</el-button>
          <el-button @click="resetSecurityAuditFilters">重置筛选</el-button>
          <el-button :loading="securityAuditExportLoading" @click="exportSecurityAudit">导出 CSV</el-button>
          <el-button :loading="securityAuditAsyncExportLoading" @click="createSecurityAuditExportJob">后台导出</el-button>
          <el-button @click="copySecurityAuditFilterLink">复制筛选链接</el-button>
        </div>

        <el-alert
          v-if="securityAuditExportJob"
          class="export-job-alert"
          :type="securityAuditExportJobAlertType"
          :title="securityAuditExportJobTitle"
          :closable="false"
          show-icon
        >
          <template #default>
            <div class="export-job-content">
              <span>{{ securityAuditExportJobSummary }}</span>
              <div class="export-job-actions">
                <el-button
                  v-if="securityAuditExportJob.download_ready"
                  link
                  type="primary"
                  @click="downloadSecurityAuditExportJob"
                >
                  下载结果
                </el-button>
                <el-button
                  v-else-if="securityAuditExportJob.status === 'pending' || securityAuditExportJob.status === 'running'"
                  link
                  type="primary"
                  @click="refreshSecurityAuditExportJob"
                >
                  刷新状态
                </el-button>
                <el-button link @click="dismissSecurityAuditExportJob">关闭</el-button>
              </div>
            </div>
          </template>
        </el-alert>

        <el-card class="audit-jobs-card" shadow="never">
          <template #header>
            <div class="catalog-header">
              <div>
                <strong>最近后台导出任务</strong>
                <p>页面刷新后仍可继续查看最近导出任务状态，并下载已完成的 CSV。</p>
              </div>
              <div class="table-actions">
                <el-button :loading="securityAuditCleanupLoading" text @click="cleanupSecurityAuditExportJobs">清理旧任务</el-button>
                <el-button :loading="securityAuditExportJobsLoading" text @click="loadSecurityAuditExportJobs">刷新任务</el-button>
              </div>
            </div>
          </template>

          <el-table
            v-loading="securityAuditExportJobsLoading"
            :data="securityAuditExportJobs"
            row-key="job_id"
            empty-text="暂无后台导出任务"
          >
            <el-table-column label="创建时间" min-width="170">
              <template #default="{ row }">{{ formatAuditTime(row.created_at) }}</template>
            </el-table-column>
            <el-table-column label="状态" width="110">
              <template #default="{ row }">
                <el-tag :type="securityAuditExportJobTagType(row.status)" effect="plain">
                  {{ formatSecurityAuditExportJobStatus(row.status) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="范围" min-width="280">
              <template #default="{ row }">
                <span class="events">{{ formatSecurityAuditExportJobScope(row) }}</span>
              </template>
            </el-table-column>
            <el-table-column label="结果" min-width="180">
              <template #default="{ row }">
                <span class="events">{{ formatSecurityAuditExportJobResult(row) }}</span>
              </template>
            </el-table-column>
            <el-table-column label="操作人" min-width="130">
              <template #default="{ row }">{{ row.actor?.id || '-' }}</template>
            </el-table-column>
            <el-table-column label="操作" width="170" fixed="right">
              <template #default="{ row }">
                <div class="table-actions">
                  <el-button link type="primary" @click="trackSecurityAuditExportJob(row)">跟踪</el-button>
                  <el-button v-if="row.download_ready" link type="primary" @click="downloadListedSecurityAuditExportJob(row)">下载</el-button>
                  <el-button
                    v-if="row.status === 'completed' || row.status === 'failed'"
                    link
                    type="danger"
                    :loading="securityAuditExportJobActionId === `delete:${row.job_id}`"
                    @click="deleteSecurityAuditExportJobEntry(row)"
                  >
                    删除
                  </el-button>
                </div>
              </template>
            </el-table-column>
          </el-table>
        </el-card>

        <el-table
          v-loading="securityAuditLoading"
          :data="securityAuditEntries"
          row-key="id"
          empty-text="暂无安全审计记录"
        >
          <el-table-column label="时间" min-width="170">
            <template #default="{ row }">
              {{ formatAuditTime(row.time) }}
            </template>
          </el-table-column>
          <el-table-column label="动作" width="140">
            <template #default="{ row }">
              <el-tag effect="plain">{{ formatSecurityAuditAction(row.action) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="操作人" min-width="150">
            <template #default="{ row }">
              {{ row.actor?.id || '-' }}
            </template>
          </el-table-column>
          <el-table-column label="结果" width="100">
            <template #default="{ row }">
              <el-tag :type="row.success ? 'success' : 'danger'" effect="plain">
                {{ row.success ? '成功' : '失败' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="详情" min-width="260">
            <template #default="{ row }">
              <span class="events">{{ formatSecurityAuditDetails(row) }}</span>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="100" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" @click="openSecurityAuditDetail(row)">查看</el-button>
            </template>
          </el-table-column>
        </el-table>

        <div class="audit-pagination">
          <el-pagination
            background
            layout="total, sizes, prev, pager, next"
            :current-page="securityAuditPage"
            :page-size="securityAuditPageSize"
            :page-sizes="[10, 20, 50, 100]"
            :total="securityAuditTotal"
            @current-change="handleSecurityAuditPageChange"
            @size-change="handleSecurityAuditSizeChange"
          />
        </div>
      </el-card>
    </el-card>

    <el-card class="settings-card oidc-card">
      <template #header>
        <div class="card-header">
          <div>
            <h2>OIDC Clients</h2>
            <p class="subhead">为业务系统和机器服务创建下游 OIDC / OAuth client，支持 PKCE、client_credentials 和组织级授权策略。</p>
          </div>
          <div class="toolbar-actions">
            <el-button :loading="oidcLoading" @click="loadOIDCClients">刷新</el-button>
            <el-button type="primary" @click="openOIDCDialog()">新建 Client</el-button>
          </div>
        </div>
      </template>

      <el-alert
        v-if="oidcLoadError"
        class="plugin-alert"
        :title="oidcLoadError"
        type="warning"
        :closable="false"
        show-icon
      />

      <el-table
        v-loading="oidcLoading"
        :data="oidcClients"
        row-key="client_id"
        empty-text="暂无 OIDC client"
      >
        <el-table-column label="名称" min-width="180">
          <template #default="{ row }">
            <div class="oidc-name">
              <strong>{{ row.name || row.client_id }}</strong>
              <span>{{ row.client_id }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="类型" width="120">
          <template #default="{ row }">
            <el-tag :type="row.public ? 'success' : 'warning'" effect="plain">
              {{ row.public ? 'Public' : 'Confidential' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="授权方式" min-width="180">
          <template #default="{ row }">
            <span class="events">{{ formatGrantTypes(row.grant_types) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'" effect="plain">
              {{ row.enabled ? '已启用' : '已禁用' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="来源" width="110">
          <template #default="{ row }">
            <el-tag :type="row.source === 'config' ? 'info' : 'primary'" effect="plain">
              {{ row.source === 'config' ? 'YAML' : '数据库' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="回调地址" min-width="240">
          <template #default="{ row }">
            <span class="events">{{ formatEvents(row.redirect_uris) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="组织策略" min-width="220">
          <template #default="{ row }">
            <span class="events">{{ formatOIDCPolicy(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="180" fixed="right">
          <template #default="{ row }">
            <div class="table-actions">
              <el-button
                v-if="row.editable"
                link
                type="primary"
                :loading="oidcActionLoadingId === `edit:${row.client_id}`"
                @click="openOIDCDialog(row)"
              >
                编辑
              </el-button>
              <el-button
                v-if="row.editable"
                link
                type="danger"
                :loading="oidcActionLoadingId === `delete:${row.client_id}`"
                @click="deleteOIDCClient(row)"
              >
                删除
              </el-button>
              <el-tag v-else effect="plain" type="info">只读</el-tag>
            </div>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card class="settings-card">
      <template #header>
        <div class="card-header">
          <div>
            <h2>Claim Mappers</h2>
            <p class="subhead">直接在后台配置 token / userinfo 自定义 claim，不需要重新打包插件。</p>
          </div>
          <div class="toolbar-actions">
            <el-button :loading="claimMapperLoading" @click="loadClaimMappers">刷新</el-button>
            <el-button type="primary" @click="openClaimMapperDialog()">新建 Mapper</el-button>
          </div>
        </div>
      </template>

      <el-alert
        v-if="claimMapperLoadError"
        class="plugin-alert"
        :title="claimMapperLoadError"
        type="warning"
        :closable="false"
        show-icon
      />

      <el-alert
        class="plugin-alert"
        title="Claim Mapper 会在 before_token_issue / before_userinfo 阶段运行，可按 client 或 organization 限定范围；服务端会拒绝覆盖 sub、iss、aud、exp、scope、client_id、org_id 等受保护 claim。"
        type="info"
        :closable="false"
        show-icon
      />

      <el-table
        v-loading="claimMapperLoading"
        :data="claimMappers"
        row-key="mapper_id"
        empty-text="暂无 Claim Mapper"
      >
        <el-table-column label="名称" min-width="180">
          <template #default="{ row }">
            <div class="oidc-name">
              <strong>{{ row.name }}</strong>
              <span>{{ row.mapper_id }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'" effect="plain">
              {{ row.enabled ? '已启用' : '已禁用' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="claim" label="Claim" min-width="150" />
        <el-table-column label="来源" min-width="220">
          <template #default="{ row }">
            <span class="events">{{ formatAdminClaimMapperSource(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="事件" min-width="220">
          <template #default="{ row }">
            <span class="events">{{ formatEvents(row.events) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="范围" min-width="260">
          <template #default="{ row }">
            <span class="events">{{ formatAdminClaimMapperScope(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="说明" min-width="180">
          <template #default="{ row }">{{ row.description || '-' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="160" fixed="right">
          <template #default="{ row }">
            <div class="table-actions">
              <el-button
                link
                type="primary"
                :loading="claimMapperActionLoadingId === `edit:${row.mapper_id}`"
                @click="openClaimMapperDialog(row)"
              >
                编辑
              </el-button>
              <el-button
                link
                type="danger"
                :loading="claimMapperActionLoadingId === `delete:${row.mapper_id}`"
                @click="deleteClaimMapper(row)"
              >
                删除
              </el-button>
            </div>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card class="settings-card">
      <template #header>
        <div class="card-header">
          <div>
            <h2>{{ $t('settings.title') }}</h2>
            <p class="subhead">安装、启停和卸载本地插件包，查看签名校验与包指纹，或浏览当前启用的内置插件能力。</p>
          </div>
          <el-button :loading="loading" @click="loadPlugins">刷新</el-button>
        </div>
      </template>

      <el-alert
        class="plugin-alert"
        title="本地插件 ZIP 包内需要包含 mkauth-plugin.yaml，并声明 permissions；flow_action 插件若使用 HTTP Action，需要声明 hook:* 与 network:http_action。签名、host allowlist 和权限 allowlist 会在服务端安装前统一校验。"
        type="info"
        :closable="false"
        show-icon
      />

      <div class="toolbar">
        <div class="toolbar-copy">
          <strong>插件安装</strong>
          <span>支持覆盖安装同名插件，安装完成后会自动重载，无需重启服务。</span>
        </div>
        <div class="toolbar-actions">
          <el-switch
            v-model="replaceOnInstall"
            inline-prompt
            active-text="覆盖"
            inactive-text="新增"
          />
          <input
            ref="fileInput"
            class="hidden-input"
            type="file"
            accept=".zip,application/zip"
            @change="handleFileChange"
          />
          <el-button type="primary" :loading="actionLoadingId === 'preview:upload'" @click="triggerFileSelect">上传 ZIP 安装</el-button>
        </div>
      </div>

      <div class="toolbar">
        <div class="toolbar-copy">
          <strong>URL 安装</strong>
          <span>可直接安装远程 ZIP 包，也可配合下方 catalog 列表做一键安装。</span>
        </div>
        <div class="toolbar-actions remote-actions">
          <el-input
            v-model="remoteInstallURL"
            placeholder="https://example.com/plugins/claims-http.zip"
            clearable
            @keyup.enter="installFromURL()"
          />
          <el-button
            type="primary"
            :loading="actionLoadingId === 'install:url'"
            @click="installFromURL()"
          >
            通过 URL 安装
          </el-button>
        </div>
      </div>

      <el-alert
        v-if="catalogLoadError"
        class="plugin-alert"
        :title="catalogLoadError"
        type="warning"
        :closable="false"
        show-icon
      />

      <el-card v-if="catalogPlugins.length > 0" class="catalog-card" shadow="never">
        <template #header>
          <div class="catalog-header">
            <div>
              <strong>插件目录</strong>
              <p>来自预配置 catalog 的可安装插件列表。</p>
            </div>
          </div>
        </template>

        <el-table :data="catalogPlugins" row-key="download_url" empty-text="暂无远程插件">
          <el-table-column label="目录" min-width="140">
            <template #default="{ row }">
              <span>{{ row.catalog_name || row.catalog_id }}</span>
            </template>
          </el-table-column>
          <el-table-column prop="name" label="名称" min-width="180" />
          <el-table-column prop="id" label="ID" min-width="160" />
          <el-table-column prop="type" label="类型" min-width="120" />
          <el-table-column label="权限" min-width="220">
            <template #default="{ row }">
              <span class="events">{{ formatPermissions(row.permissions) }}</span>
            </template>
          </el-table-column>
          <el-table-column label="版本" width="100">
            <template #default="{ row }">
              {{ row.version || '-' }}
            </template>
          </el-table-column>
          <el-table-column label="安装状态" width="130">
            <template #default="{ row }">
              <el-tag :type="catalogStatusTagType(row)" effect="plain">
                {{ catalogStatusLabel(row) }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="签名要求" width="100">
            <template #default="{ row }">
              <el-tag :type="row.signature_required ? 'success' : 'info'" effect="plain">
                {{ row.signature_required ? '要求' : '可选' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="校验值" min-width="180">
            <template #default="{ row }">
              <span class="hash">{{ formatHash(row.package_sha256) }}</span>
            </template>
          </el-table-column>
          <el-table-column label="说明" min-width="220">
            <template #default="{ row }">
              {{ row.description || '-' }}
            </template>
          </el-table-column>
          <el-table-column label="操作" width="140" fixed="right">
            <template #default="{ row }">
              <el-button
                link
                type="primary"
                :loading="actionLoadingId === `catalog:${row.catalog_id}:${row.id}`"
                @click="installFromURL(row)"
              >
                {{ catalogActionLabel(row) }}
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-card>

      <el-table
        v-loading="loading"
        :data="plugins"
        row-key="id"
        empty-text="暂无插件"
      >
        <el-table-column prop="name" label="名称" min-width="180" />
        <el-table-column prop="id" label="ID" min-width="160" />
        <el-table-column prop="type" label="类型" min-width="140" />
        <el-table-column label="来源" width="120">
          <template #default="{ row }">
            <el-tag :type="sourceTagType(row.source)" effect="plain">{{ row.source }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? '已启用' : '已禁用' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="完整性" width="120">
          <template #default="{ row }">
            <el-tag :type="integrityTagType(row)" effect="plain">{{ integrityLabel(row) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="版本" width="100">
          <template #default="{ row }">
            {{ row.version || '-' }}
          </template>
        </el-table-column>
        <el-table-column label="包指纹" min-width="200">
          <template #default="{ row }">
            <span class="hash">{{ formatHash(row.package_sha256) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="事件" min-width="220">
          <template #default="{ row }">
            <span class="events">{{ formatEvents(row.events) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="权限" min-width="240">
          <template #default="{ row }">
            <span class="events">{{ formatPermissions(row.permissions) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="Claims" min-width="260">
          <template #default="{ row }">
            <span class="events">{{ formatClaimMappings(row.claim_mappings) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="说明" min-width="220">
          <template #default="{ row }">
            {{ row.description || '-' }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <div class="table-actions">
              <el-button
                v-if="canManage(row)"
                link
                type="primary"
                :loading="actionLoadingId === `toggle:${row.id}`"
                @click="togglePlugin(row)"
              >
                {{ row.enabled ? '禁用' : '启用' }}
              </el-button>
              <el-button
                v-if="canConfigure(row)"
                link
                type="primary"
                :loading="actionLoadingId === `config:${row.id}`"
                @click="openPluginConfig(row)"
              >
                配置
              </el-button>
              <el-button
                v-if="canManage(row)"
                link
                type="danger"
                :loading="actionLoadingId === `delete:${row.id}`"
                @click="deletePlugin(row)"
              >
                删除
              </el-button>
              <el-tag v-else effect="plain" type="info">配置型</el-tag>
            </div>
          </template>
        </el-table-column>
      </el-table>

      <el-card class="audit-card" shadow="never">
        <template #header>
          <div class="catalog-header">
            <div>
              <strong>回滚快照</strong>
              <p>覆盖安装或卸载前自动保存，可在这里恢复。</p>
            </div>
          </div>
        </template>

        <el-table :data="backupEntries" row-key="id" empty-text="暂无回滚快照">
          <el-table-column label="时间" min-width="170">
            <template #default="{ row }">
              {{ formatAuditTime(row.created_at) }}
            </template>
          </el-table-column>
          <el-table-column label="插件" min-width="190">
            <template #default="{ row }">
              {{ row.plugin_name || row.plugin_id || '-' }}
            </template>
          </el-table-column>
          <el-table-column label="原因" width="120">
            <template #default="{ row }">
              <el-tag effect="plain">{{ formatBackupReason(row.reason) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="包指纹" min-width="180">
            <template #default="{ row }">
              <span class="hash">{{ formatHash(row.package_sha256) }}</span>
            </template>
          </el-table-column>
          <el-table-column label="快照 ID" min-width="220">
            <template #default="{ row }">
              <span class="hash">{{ row.id }}</span>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="110" fixed="right">
            <template #default="{ row }">
              <el-button
                link
                type="primary"
                :loading="actionLoadingId === `restore:${row.id}`"
                @click="restoreBackup(row)"
              >
                恢复
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-card>

      <el-card class="audit-card" shadow="never">
        <template #header>
          <div class="catalog-header">
            <div>
              <strong>操作审计</strong>
              <p>最近的插件安装、启停和卸载记录。</p>
            </div>
          </div>
        </template>

        <el-table :data="auditEntries" row-key="id" empty-text="暂无审计记录">
          <el-table-column label="时间" min-width="170">
            <template #default="{ row }">
              {{ formatAuditTime(row.time) }}
            </template>
          </el-table-column>
          <el-table-column label="动作" width="130">
            <template #default="{ row }">
              <el-tag effect="plain">{{ formatAuditAction(row.action) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="插件" min-width="190">
            <template #default="{ row }">
              {{ row.plugin_name || row.plugin_id || '-' }}
            </template>
          </el-table-column>
          <el-table-column label="操作人" min-width="150">
            <template #default="{ row }">
              {{ row.actor?.id || '-' }}
            </template>
          </el-table-column>
          <el-table-column label="来源" min-width="180">
            <template #default="{ row }">
              {{ row.source || '-' }}
            </template>
          </el-table-column>
          <el-table-column label="结果" width="100">
            <template #default="{ row }">
              <el-tag :type="row.success ? 'success' : 'danger'" effect="plain">
                {{ row.success ? '成功' : '失败' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="详情" min-width="240">
            <template #default="{ row }">
              <span class="events">{{ formatAuditDetails(row) }}</span>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </el-card>

    <el-dialog
      v-model="installPreviewDialogVisible"
      title="确认安装插件"
      width="680px"
      @closed="clearInstallPreview"
    >
      <template v-if="installPreview">
        <el-alert
          class="plugin-alert"
          :title="installPreview.exists ? '检测到同 ID 插件，确认后会覆盖安装并创建回滚快照。' : '预检通过，确认后将安装该插件。'"
          :type="installPreview.exists ? 'warning' : 'success'"
          :closable="false"
          show-icon
        />
        <el-descriptions :column="2" border>
          <el-descriptions-item label="名称">{{ installPreview.name || installPreview.id }}</el-descriptions-item>
          <el-descriptions-item label="ID">{{ installPreview.id }}</el-descriptions-item>
          <el-descriptions-item label="版本">{{ installPreview.version || '-' }}</el-descriptions-item>
          <el-descriptions-item label="类型">{{ installPreview.type }}</el-descriptions-item>
          <el-descriptions-item label="安装方式">
            <el-tag :type="installPreview.effective_replace ? 'warning' : 'success'" effect="plain">
              {{ installPreview.effective_replace ? '覆盖安装' : '新增安装' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="安装后状态">
            {{ installPreview.enabled_after_install ? '启用' : '禁用' }}
          </el-descriptions-item>
          <el-descriptions-item label="签名状态">
            <el-tag :type="installPreview.signature_verified ? 'success' : 'warning'" effect="plain">
              {{ installPreview.signature_verified ? `已验签${installPreview.signer_key_id ? `:${installPreview.signer_key_id}` : ''}` : '未签名' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="包指纹">
            <span class="hash">{{ formatHash(installPreview.package_sha256) }}</span>
          </el-descriptions-item>
          <el-descriptions-item v-if="installPreview.existing" label="当前版本">
            {{ installPreview.existing.version || '-' }}
          </el-descriptions-item>
          <el-descriptions-item v-if="installPreview.existing" label="当前指纹">
            <span class="hash">{{ formatHash(installPreview.existing_package_sha256) }}</span>
          </el-descriptions-item>
        </el-descriptions>

        <div class="preview-block">
          <strong>权限</strong>
          <p class="events">{{ formatPermissions(installPreview.permissions) }}</p>
        </div>
        <div class="preview-block">
          <strong>事件</strong>
          <p class="events">{{ formatEvents(installPreview.events) }}</p>
        </div>
        <div v-if="installPreview.claim_mappings?.length" class="preview-block">
          <strong>Claim 映射</strong>
          <p class="events">{{ formatClaimMappings(installPreview.claim_mappings) }}</p>
        </div>
        <div v-if="installPreview.preserved_config_keys?.length || installPreview.dropped_config_keys?.length" class="preview-block">
          <strong>配置继承</strong>
          <p v-if="installPreview.preserved_config_keys?.length" class="events">
            保留：{{ installPreview.preserved_config_keys.join(', ') }}
          </p>
          <p v-if="installPreview.dropped_config_keys?.length" class="events danger-text">
            丢弃：{{ installPreview.dropped_config_keys.join(', ') }}
          </p>
        </div>
        <div v-if="installPreview.warnings?.length" class="preview-block">
          <strong>提示</strong>
          <p v-for="warning in installPreview.warnings" :key="warning" class="events warning-text">{{ warning }}</p>
        </div>
      </template>
      <template #footer>
        <el-button @click="installPreviewDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="installLoading" @click="confirmInstallPreview">
          {{ installPreview?.effective_replace ? '确认覆盖安装' : '确认安装' }}
        </el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="configDialogVisible"
      :title="`配置插件 ${activeConfigPlugin?.name || activeConfigPlugin?.id || ''}`"
      width="560px"
    >
      <el-form label-position="top">
        <el-form-item
          v-for="field in configSchema"
          :key="field.key"
          :label="`${field.label || field.key}${field.required ? ' *' : ''}`"
        >
          <el-switch
            v-if="field.type === 'boolean'"
            v-model="configValues[field.key]"
            active-value="true"
            inactive-value="false"
          />
          <el-select
            v-else-if="field.type === 'select'"
            v-model="configValues[field.key]"
            :placeholder="field.description || field.key"
            clearable
            class="config-control"
          >
            <el-option
              v-for="option in field.options || []"
              :key="option"
              :label="option"
              :value="option"
            />
          </el-select>
          <el-input
            v-else
            v-model="configValues[field.key]"
            :type="field.type === 'secret' ? 'password' : field.type === 'text' ? 'textarea' : 'text'"
            :show-password="field.type === 'secret'"
            :placeholder="configPlaceholder(field)"
            clearable
          />
          <p v-if="field.description" class="field-help">{{ field.description }}</p>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="configDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="configLoading" @click="savePluginConfig">保存配置</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="oidcDialogVisible"
      :title="oidcDialogMode === 'create' ? '新建 OIDC Client' : `编辑 OIDC Client ${oidcForm.original_client_id}`"
      width="720px"
    >
      <el-form label-position="top">
        <div class="oidc-form-grid">
          <el-form-item label="名称">
            <el-input v-model="oidcForm.name" placeholder="Demo SPA" clearable />
          </el-form-item>
          <el-form-item label="Client ID *">
            <el-input v-model="oidcForm.client_id" placeholder="demo-spa" clearable />
          </el-form-item>
        </div>

        <div class="oidc-form-grid">
          <el-form-item label="Client 类型">
            <el-switch
              v-model="oidcForm.public"
              inline-prompt
              active-text="Public"
              inactive-text="Confidential"
            />
          </el-form-item>
          <el-form-item label="状态">
            <el-switch
              v-model="oidcForm.enabled"
              inline-prompt
              active-text="启用"
              inactive-text="禁用"
            />
          </el-form-item>
        </div>

        <div class="oidc-form-grid">
          <el-form-item label="Require PKCE">
            <el-switch v-model="oidcForm.require_pkce" />
          </el-form-item>
          <el-form-item label="Require Organization">
            <el-switch v-model="oidcForm.require_organization" />
          </el-form-item>
        </div>

        <el-form-item label="Grant Types">
          <el-input
            v-model="oidcForm.grant_types_text"
            type="textarea"
            :rows="2"
            placeholder="每行一个，例如 authorization_code 或 client_credentials"
          />
          <div class="form-tip">浏览器/用户登录使用 authorization_code；机器服务调用使用 client_credentials，必须是 Confidential client。</div>
        </el-form-item>

        <el-form-item :label="oidcForm.public ? 'Client Secret（可留空）' : 'Client Secret *'">
          <el-input
            v-model="oidcForm.client_secret"
            type="password"
            show-password
            :placeholder="oidcSecretPlaceholder()"
            clearable
          />
        </el-form-item>

        <el-form-item label="Service Account Subject">
          <el-input
            v-model="oidcForm.service_account_subject"
            placeholder="留空默认 svc:<client_id>"
            clearable
          />
          <div class="form-tip">仅 client_credentials 生效，会作为机器 token 的 sub。</div>
        </el-form-item>

        <el-form-item label="Redirect URIs">
          <el-input
            v-model="oidcForm.redirect_uris_text"
            type="textarea"
            :rows="4"
            placeholder="每行一个，例如：https://app.example.com/callback"
          />
          <div class="form-tip">authorization_code 需要至少一个回调地址；纯 client_credentials 客户端可以留空。</div>
        </el-form-item>

        <el-form-item label="Scopes">
          <el-input
            v-model="oidcForm.scopes_text"
            type="textarea"
            :rows="2"
            placeholder="每行一个；用户登录默认 openid / profile / email，机器服务建议显式配置如 admin_api"
          />
        </el-form-item>

        <el-form-item label="Allowed Organizations">
          <el-input
            v-model="oidcForm.allowed_organizations_text"
            type="textarea"
            :rows="2"
            placeholder="每行一个 organization slug 或 ID"
          />
        </el-form-item>

        <div class="oidc-form-grid">
          <el-form-item label="Required Org Roles (Any)">
            <el-input
              v-model="oidcForm.required_org_roles_text"
              type="textarea"
              :rows="3"
              placeholder="每行一个角色名"
            />
          </el-form-item>
          <el-form-item label="Required Org Groups (Any)">
            <el-input
              v-model="oidcForm.required_org_groups_text"
              type="textarea"
              :rows="3"
              placeholder="每行一个组名"
            />
          </el-form-item>
        </div>

        <div class="oidc-form-grid">
          <el-form-item label="Required Org Roles (All)">
            <el-input
              v-model="oidcForm.required_org_roles_all_text"
              type="textarea"
              :rows="3"
              placeholder="每行一个角色名，要求全部命中"
            />
          </el-form-item>
          <el-form-item label="Required Org Groups (All)">
            <el-input
              v-model="oidcForm.required_org_groups_all_text"
              type="textarea"
              :rows="3"
              placeholder="每行一个组名，要求全部命中"
            />
          </el-form-item>
        </div>

        <el-form-item label="Scope Policies JSON">
          <el-input
            v-model="oidcForm.scope_policies_json"
            type="textarea"
            :rows="8"
            placeholder='例如：{"admin_api":{"required_org_roles_all":["admin"],"required_org_groups":["Security"]}}'
          />
          <div class="form-tip">按 scope 追加更严格的组织策略。支持 require_organization、allowed_organizations、required_org_roles、required_org_roles_all、required_org_groups、required_org_groups_all。</div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="oidcDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="oidcDialogSubmitting" @click="saveOIDCClient">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="claimMapperDialogVisible"
      :title="claimMapperDialogMode === 'create' ? '新建 Claim Mapper' : `编辑 Claim Mapper ${claimMapperForm.mapper_id}`"
      width="720px"
    >
      <el-form label-position="top">
        <div class="oidc-form-grid">
          <el-form-item label="名称 *">
            <el-input v-model="claimMapperForm.name" placeholder="Tenant Claim" clearable />
          </el-form-item>
          <el-form-item label="状态">
            <el-switch
              v-model="claimMapperForm.enabled"
              inline-prompt
              active-text="启用"
              inactive-text="禁用"
            />
          </el-form-item>
        </div>

        <div class="oidc-form-grid">
          <el-form-item label="Claim *">
            <el-input v-model="claimMapperForm.claim" placeholder="tenant_key" clearable />
          </el-form-item>
          <el-form-item label="Value From">
            <el-input v-model="claimMapperForm.value_from" placeholder="claim.org_roles / user.user_id" clearable />
          </el-form-item>
        </div>

        <el-form-item label="Static Value">
          <el-input
            v-model="claimMapperForm.value"
            type="textarea"
            :rows="3"
            placeholder="例如：tenant:${claim.org_slug}:${client_id}。如果设置了 Value From，这里请留空。"
          />
          <div class="form-tip">支持模板：${claim.org_slug}、${client_id}、${user.username}、${metadata.path}。Static Value 和 Value From 二选一。</div>
        </el-form-item>

        <el-form-item label="事件">
          <el-input
            v-model="claimMapperForm.events_text"
            type="textarea"
            :rows="2"
            placeholder="before_token_issue / before_userinfo，每行一个"
          />
        </el-form-item>

        <div class="oidc-form-grid">
          <el-form-item label="限定 Clients">
            <el-input
              v-model="claimMapperForm.clients_text"
              type="textarea"
              :rows="3"
              placeholder="每行一个 client_id；留空表示全部"
            />
          </el-form-item>
          <el-form-item label="限定 Organizations">
            <el-input
              v-model="claimMapperForm.organizations_text"
              type="textarea"
              :rows="3"
              placeholder="每行一个 organization ID 或 slug；留空表示全部"
            />
          </el-form-item>
        </div>

        <el-form-item label="说明">
          <el-input
            v-model="claimMapperForm.description"
            type="textarea"
            :rows="2"
            placeholder="描述这个 claim 的用途"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="claimMapperDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="claimMapperDialogSubmitting" @click="saveClaimMapper">保存</el-button>
      </template>
    </el-dialog>

    <SecurityAuditDetailDrawer
      v-model="securityAuditDetailVisible"
      :entry="selectedSecurityAuditEntry"
      :action-label="selectedSecurityAuditActionLabel"
      title="后台安全审计详情"
      @apply-filter="applySecurityAuditJumpFilter"
      @open-resource="openSecurityAuditResource"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus/es/components/message/index'
import { ElMessageBox } from 'element-plus/es/components/message-box/index'
import { serverApi, type AdminClaimMapper, type AdminPrincipal, type CatalogPluginInfo, type OIDCClient, type OIDCOrganizationPolicy, type PluginAuditEntry, type PluginBackupInfo, type PluginClaimMapping, type PluginConfigField, type PluginInfo, type PluginInstallPreview, type SecurityAuditEntry, type SecurityAuditExportJob, type SecurityAuditQuery, type SecuritySecretsStatus } from '@/api'
import SecurityAuditDetailDrawer from '@/components/SecurityAuditDetailDrawer.vue'

type OIDCDialogMode = 'create' | 'edit'
type ClaimMapperDialogMode = 'create' | 'edit'

interface OIDCClientFormState {
  original_client_id: string
  name: string
  client_id: string
  client_secret: string
  grant_types_text: string
  service_account_subject: string
  redirect_uris_text: string
  scopes_text: string
  allowed_organizations_text: string
  required_org_roles_text: string
  required_org_roles_all_text: string
  required_org_groups_text: string
  required_org_groups_all_text: string
  scope_policies_json: string
  public: boolean
  require_pkce: boolean
  require_organization: boolean
  enabled: boolean
  client_secret_configured: boolean
}

type SecurityAuditSuccessFilter = 'all' | 'true' | 'false'

interface SecurityAuditFilterState {
  action: string
  resource_type: string
  client_id: string
  provider_id: string
  organization_id: string
  actor_id: string
  query: string
  success: SecurityAuditSuccessFilter
}

interface AdminCreateFormState {
  user_ref: string
}

interface ClaimMapperFormState {
  mapper_id: string
  name: string
  description: string
  enabled: boolean
  claim: string
  value: string
  value_from: string
  events_text: string
  clients_text: string
  organizations_text: string
}

const loading = ref(false)
const actionLoadingId = ref('')
const replaceOnInstall = ref(false)
const plugins = ref<PluginInfo[]>([])
const catalogPlugins = ref<CatalogPluginInfo[]>([])
const auditEntries = ref<PluginAuditEntry[]>([])
const backupEntries = ref<PluginBackupInfo[]>([])
const catalogLoadError = ref('')
const remoteInstallURL = ref('')
const fileInput = ref<HTMLInputElement | null>(null)
const selectedInstallFile = ref<File | null>(null)
const installPreviewDialogVisible = ref(false)
const installLoading = ref(false)
const installPreview = ref<PluginInstallPreview | null>(null)
const configDialogVisible = ref(false)
const configLoading = ref(false)
const activeConfigPlugin = ref<PluginInfo | null>(null)
const configSchema = ref<PluginConfigField[]>([])
const configValues = ref<Record<string, string>>({})
const configConfigured = ref<Record<string, boolean>>({})
const oidcLoading = ref(false)
const oidcActionLoadingId = ref('')
const oidcLoadError = ref('')
const oidcClients = ref<OIDCClient[]>([])
const claimMapperLoading = ref(false)
const claimMapperActionLoadingId = ref('')
const claimMapperLoadError = ref('')
const claimMappers = ref<AdminClaimMapper[]>([])
const adminLoading = ref(false)
const adminActionLoadingId = ref('')
const adminLoadError = ref('')
const admins = ref<AdminPrincipal[]>([])
const adminCreateForm = reactive<AdminCreateFormState>({
  user_ref: ''
})
const oidcDialogVisible = ref(false)
const oidcDialogMode = ref<OIDCDialogMode>('create')
const oidcDialogSubmitting = ref(false)
const claimMapperDialogVisible = ref(false)
const claimMapperDialogMode = ref<ClaimMapperDialogMode>('create')
const claimMapperDialogSubmitting = ref(false)
const securityLoading = ref(false)
const securityResealLoading = ref(false)
const securityAuditLoading = ref(false)
const securityAuditExportLoading = ref(false)
const securityAuditAsyncExportLoading = ref(false)
const securityAuditCleanupLoading = ref(false)
const securityLoadError = ref('')
const securityStatus = ref<SecuritySecretsStatus | null>(null)
const securityAuditEntries = ref<SecurityAuditEntry[]>([])
const securityAuditExportJobs = ref<SecurityAuditExportJob[]>([])
const securityAuditPage = ref(1)
const securityAuditPageSize = ref(10)
const securityAuditTotal = ref(0)
const securityAuditTimeRange = ref<[Date, Date] | null>(null)
const securityAuditDetailVisible = ref(false)
const selectedSecurityAuditEntry = ref<SecurityAuditEntry | null>(null)
const selectedSecurityAuditActionLabel = ref('')
const securityAuditExportJob = ref<SecurityAuditExportJob | null>(null)
const securityAuditExportJobsLoading = ref(false)
const securityAuditExportJobActionId = ref('')
const securityAuditFilters = reactive<SecurityAuditFilterState>({
  action: '',
  resource_type: '',
  client_id: '',
  provider_id: '',
  organization_id: '',
  actor_id: '',
  query: '',
  success: 'all'
})
const oidcForm = reactive<OIDCClientFormState>({
  original_client_id: '',
  name: '',
  client_id: '',
  client_secret: '',
  grant_types_text: '',
  service_account_subject: '',
  redirect_uris_text: '',
  scopes_text: '',
  allowed_organizations_text: '',
  required_org_roles_text: '',
  required_org_roles_all_text: '',
  required_org_groups_text: '',
  required_org_groups_all_text: '',
  scope_policies_json: '',
  public: false,
  require_pkce: true,
  require_organization: false,
  enabled: true,
  client_secret_configured: false
})
const claimMapperForm = reactive<ClaimMapperFormState>({
  mapper_id: '',
  name: '',
  description: '',
  enabled: true,
  claim: '',
  value: '',
  value_from: '',
  events_text: 'before_token_issue\nbefore_userinfo',
  clients_text: '',
  organizations_text: ''
})

const securityAuditActionOptions = [
  { label: '重写托管 Secrets', value: 'secrets_reseal' },
  { label: '创建 OIDC Client', value: 'oidc_client_create' },
  { label: '更新 OIDC Client', value: 'oidc_client_update' },
  { label: '删除 OIDC Client', value: 'oidc_client_delete' },
  { label: '创建企业身份源', value: 'identity_provider_create' },
  { label: '更新企业身份源', value: 'identity_provider_update' },
  { label: '删除企业身份源', value: 'identity_provider_delete' },
  { label: '创建 Claim Mapper', value: 'claim_mapper_create' },
  { label: '更新 Claim Mapper', value: 'claim_mapper_update' },
  { label: '删除 Claim Mapper', value: 'claim_mapper_delete' },
  { label: '添加管理员', value: 'admin_principal_create' },
  { label: '移除管理员', value: 'admin_principal_delete' },
  { label: '添加组织管理员', value: 'organization_admin_create' },
  { label: '移除组织管理员', value: 'organization_admin_delete' }
]

const securityAuditResourceOptions = [
  { label: 'OIDC Client', value: 'oidc_client' },
  { label: '企业身份源', value: 'identity_provider' },
  { label: 'Claim Mapper', value: 'claim_mapper' },
  { label: '管理员', value: 'admin_principal' },
  { label: '组织管理员', value: 'organization_admin' }
]

const route = useRoute()
const router = useRouter()
const settingsAuditQueryKeys = [
  'audit_action',
  'audit_resource_type',
  'audit_client_id',
  'audit_provider_id',
  'audit_organization_id',
  'audit_actor_id',
  'audit_query',
  'audit_success',
  'audit_time_from',
  'audit_time_to',
  'audit_page',
  'audit_size'
] as const
let syncingSettingsAuditRoute = false
let securityAuditExportPollTimer: number | null = null
let lastSettledSecurityAuditExportJob = ''

const canManage = (plugin: PluginInfo) => plugin.source === 'local'
const canConfigure = (plugin: PluginInfo) => canManage(plugin) && !!plugin.config_schema?.length

const sourceTagType = (source: string) => {
  if (source === 'builtin') return 'success'
  if (source === 'local') return 'warning'
  return 'info'
}

const integrityLabel = (plugin: PluginInfo) => {
  if (plugin.source === 'builtin') return '内置'
  if (plugin.source !== 'local') return '配置型'
  return plugin.signature_verified ? `已验签${plugin.signer_key_id ? `:${plugin.signer_key_id}` : ''}` : '未签名'
}

const integrityTagType = (plugin: PluginInfo) => {
  if (plugin.source === 'builtin') return 'success'
  if (plugin.source !== 'local') return 'info'
  return plugin.signature_verified ? 'success' : 'warning'
}

const formatEvents = (events?: string[]) => {
  if (!events || events.length === 0) return '-'
  return events.join(', ')
}

const formatPermissions = (permissions?: string[]) => {
  if (!permissions || permissions.length === 0) return '-'
  return permissions.join(', ')
}

const formatClaimMappings = (mappings?: PluginClaimMapping[]) => {
  if (!mappings || mappings.length === 0) return '-'
  return mappings
    .map(mapping => {
      const source = mapping.value_from ? `from ${mapping.value_from}` : `= ${mapping.value ?? ''}`
      const scopes = [
        mapping.clients?.length ? `clients:${mapping.clients.join('|')}` : '',
        mapping.organizations?.length ? `orgs:${mapping.organizations.join('|')}` : '',
      ].filter(Boolean)
      return `${mapping.claim} ${source}${scopes.length ? ` (${scopes.join(', ')})` : ''}`
    })
    .join('; ')
}

const formatHash = (hash?: string) => {
  if (!hash) return '-'
  if (hash.length <= 16) return hash
  return `${hash.slice(0, 12)}...${hash.slice(-8)}`
}

const formatGrantTypes = (grantTypes?: string[]) => {
  if (!grantTypes || grantTypes.length === 0) return 'authorization_code'
  return grantTypes.join(', ')
}

const serializeLineList = (values?: string[]) => {
  if (!values || values.length === 0) return ''
  return values.join('\n')
}

const parseLineList = (value: string) => {
  return value
    .split(/\n|,/)
    .map(item => item.trim())
    .filter(Boolean)
}

const serializeScopePolicies = (policies?: Record<string, OIDCOrganizationPolicy>) => {
  if (!policies || Object.keys(policies).length === 0) return ''
  return JSON.stringify(policies, null, 2)
}

const parseScopePolicies = (value: string): Record<string, OIDCOrganizationPolicy> | undefined => {
  const raw = value.trim()
  if (!raw) return undefined
  const parsed = JSON.parse(raw)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Scope Policies JSON 必须是对象')
  }
  return parsed as Record<string, OIDCOrganizationPolicy>
}

const resetOIDCForm = () => {
  oidcForm.original_client_id = ''
  oidcForm.name = ''
  oidcForm.client_id = ''
  oidcForm.client_secret = ''
  oidcForm.grant_types_text = 'authorization_code'
  oidcForm.service_account_subject = ''
  oidcForm.redirect_uris_text = ''
  oidcForm.scopes_text = 'openid\nprofile\nemail'
  oidcForm.allowed_organizations_text = ''
  oidcForm.required_org_roles_text = ''
  oidcForm.required_org_roles_all_text = ''
  oidcForm.required_org_groups_text = ''
  oidcForm.required_org_groups_all_text = ''
  oidcForm.scope_policies_json = ''
  oidcForm.public = false
  oidcForm.require_pkce = true
  oidcForm.require_organization = false
  oidcForm.enabled = true
  oidcForm.client_secret_configured = false
}

const resetClaimMapperForm = () => {
  claimMapperForm.mapper_id = ''
  claimMapperForm.name = ''
  claimMapperForm.description = ''
  claimMapperForm.enabled = true
  claimMapperForm.claim = ''
  claimMapperForm.value = ''
  claimMapperForm.value_from = ''
  claimMapperForm.events_text = 'before_token_issue\nbefore_userinfo'
  claimMapperForm.clients_text = ''
  claimMapperForm.organizations_text = ''
}

const loadAdmins = async () => {
  adminLoading.value = true
  try {
    const response = await serverApi.listAdmins()
    admins.value = response.admins || []
    adminLoadError.value = ''
  } catch (error: any) {
    admins.value = []
    adminLoadError.value = error?.response?.data?.error || '加载管理员列表失败'
  } finally {
    adminLoading.value = false
  }
}

const createAdmin = async () => {
  const userRef = adminCreateForm.user_ref.trim()
  if (!userRef) {
    ElMessage.warning('请输入用户 ID 或用户名')
    return
  }
  adminActionLoadingId.value = 'create'
  try {
    const response = await serverApi.createAdmin({ user_ref: userRef })
    adminCreateForm.user_ref = ''
    ElMessage.success(response.admin?.username ? `已添加管理员 ${response.admin.username}` : '已添加管理员')
    await loadAdmins()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '添加管理员失败')
  } finally {
    adminActionLoadingId.value = ''
  }
}

const deleteAdmin = async (adminUser: AdminPrincipal) => {
  try {
    await ElMessageBox.confirm(
      `确定移除管理员 ${adminUser.username || adminUser.user_id} 吗？`,
      '移除管理员',
      {
        confirmButtonText: '移除',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )
  } catch {
    return
  }
  adminActionLoadingId.value = `delete:${adminUser.user_id}`
  try {
    const response = await serverApi.deleteAdmin(adminUser.user_id)
    ElMessage.success(response.message || '管理员已移除')
    await loadAdmins()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '移除管理员失败')
  } finally {
    adminActionLoadingId.value = ''
  }
}

const formatAdminSources = (sources: string[]) => {
  return (sources || []).map(source => {
    if (source === 'config') return '配置'
    if (source === 'database') return '数据库'
    return source
  })
}

const loadSecurityStatus = async () => {
  securityLoading.value = true
  try {
    const response = await serverApi.getSecuritySecretsStatus()
    securityStatus.value = response.status
    securityLoadError.value = ''
  } catch (error: any) {
    securityStatus.value = null
    securityLoadError.value = error?.response?.data?.error || '加载 secrets 加密状态失败'
  } finally {
    securityLoading.value = false
  }
}

const loadSecurityAudit = async () => {
  securityAuditLoading.value = true
  try {
    const response = await serverApi.getSecurityAudit(buildSecurityAuditQuery({
      page: securityAuditPage.value,
      size: securityAuditPageSize.value
    }))
    securityAuditEntries.value = response.audit || []
    securityAuditTotal.value = response.total || 0
    securityAuditPage.value = response.page || securityAuditPage.value
    securityAuditPageSize.value = response.size || securityAuditPageSize.value
  } catch {
    securityAuditEntries.value = []
    securityAuditTotal.value = 0
  } finally {
    securityAuditLoading.value = false
  }
}

const loadSecurityAuditExportJobs = async () => {
  securityAuditExportJobsLoading.value = true
  try {
    const response = await serverApi.listSecurityAuditExportJobs({ page: 1, size: 8 })
    securityAuditExportJobs.value = response.jobs || []
  } catch {
    securityAuditExportJobs.value = []
  } finally {
    securityAuditExportJobsLoading.value = false
  }
}

const clearTrackedSecurityAuditExportJobIfNeeded = (jobId: string) => {
  if (securityAuditExportJob.value?.job_id === jobId) {
    dismissSecurityAuditExportJob()
  }
}

const buildSecurityAuditQuery = (overrides: Partial<SecurityAuditQuery> = {}): SecurityAuditQuery => {
  const timeFrom = securityAuditTimeRange.value?.[0] ? securityAuditTimeRange.value[0].toISOString() : undefined
  const timeTo = securityAuditTimeRange.value?.[1] ? securityAuditTimeRange.value[1].toISOString() : undefined
  return {
    action: securityAuditFilters.action || undefined,
    resource_type: securityAuditFilters.resource_type || undefined,
    client_id: securityAuditFilters.client_id.trim() || undefined,
    provider_id: securityAuditFilters.provider_id.trim() || undefined,
    organization_id: securityAuditFilters.organization_id.trim() || undefined,
    actor_id: securityAuditFilters.actor_id.trim() || undefined,
    query: securityAuditFilters.query.trim() || undefined,
    time_from: timeFrom,
    time_to: timeTo,
    success: securityAuditFilters.success === 'all' ? undefined : securityAuditFilters.success === 'true',
    ...overrides
  }
}

const parseSettingsAuditDate = (raw?: string) => {
  if (!raw) return null
  const parsed = new Date(raw)
  if (Number.isNaN(parsed.getTime())) return null
  return parsed
}

const applySettingsAuditRouteState = () => {
  const query = route.query
  securityAuditFilters.action = typeof query.audit_action === 'string' ? query.audit_action : ''
  securityAuditFilters.resource_type = typeof query.audit_resource_type === 'string' ? query.audit_resource_type : ''
  securityAuditFilters.client_id = typeof query.audit_client_id === 'string' ? query.audit_client_id : ''
  securityAuditFilters.provider_id = typeof query.audit_provider_id === 'string' ? query.audit_provider_id : ''
  securityAuditFilters.organization_id = typeof query.audit_organization_id === 'string' ? query.audit_organization_id : ''
  securityAuditFilters.actor_id = typeof query.audit_actor_id === 'string' ? query.audit_actor_id : ''
  securityAuditFilters.query = typeof query.audit_query === 'string' ? query.audit_query : ''
  securityAuditFilters.success =
    query.audit_success === 'true' || query.audit_success === 'false'
      ? query.audit_success
      : 'all'

  const page = typeof query.audit_page === 'string' ? Number.parseInt(query.audit_page, 10) : NaN
  securityAuditPage.value = Number.isFinite(page) && page > 0 ? page : 1
  const size = typeof query.audit_size === 'string' ? Number.parseInt(query.audit_size, 10) : NaN
  securityAuditPageSize.value = Number.isFinite(size) && size > 0 ? size : 10

  const timeFrom = typeof query.audit_time_from === 'string' ? parseSettingsAuditDate(query.audit_time_from) : null
  const timeTo = typeof query.audit_time_to === 'string' ? parseSettingsAuditDate(query.audit_time_to) : null
  securityAuditTimeRange.value = timeFrom && timeTo ? [timeFrom, timeTo] : null
}

const buildSettingsAuditRouteQuery = () => {
  const preservedQuery = Object.fromEntries(
    Object.entries(route.query).filter(([key]) => !settingsAuditQueryKeys.includes(key as (typeof settingsAuditQueryKeys)[number]))
  ) as Record<string, string>

  const nextQuery: Record<string, string> = { ...preservedQuery }
  if (securityAuditFilters.action) nextQuery.audit_action = securityAuditFilters.action
  if (securityAuditFilters.resource_type) nextQuery.audit_resource_type = securityAuditFilters.resource_type
  if (securityAuditFilters.client_id.trim()) nextQuery.audit_client_id = securityAuditFilters.client_id.trim()
  if (securityAuditFilters.provider_id.trim()) nextQuery.audit_provider_id = securityAuditFilters.provider_id.trim()
  if (securityAuditFilters.organization_id.trim()) nextQuery.audit_organization_id = securityAuditFilters.organization_id.trim()
  if (securityAuditFilters.actor_id.trim()) nextQuery.audit_actor_id = securityAuditFilters.actor_id.trim()
  if (securityAuditFilters.query.trim()) nextQuery.audit_query = securityAuditFilters.query.trim()
  if (securityAuditFilters.success !== 'all') nextQuery.audit_success = securityAuditFilters.success
  if (securityAuditTimeRange.value?.[0]) nextQuery.audit_time_from = securityAuditTimeRange.value[0].toISOString()
  if (securityAuditTimeRange.value?.[1]) nextQuery.audit_time_to = securityAuditTimeRange.value[1].toISOString()
  if (securityAuditPage.value > 1) nextQuery.audit_page = String(securityAuditPage.value)
  if (securityAuditPageSize.value !== 10) nextQuery.audit_size = String(securityAuditPageSize.value)
  return nextQuery
}

const syncSettingsAuditRoute = async () => {
  syncingSettingsAuditRoute = true
  try {
    await router.replace({
      name: 'Settings',
      query: buildSettingsAuditRouteQuery()
    })
  } finally {
    syncingSettingsAuditRoute = false
  }
}

const handleSecurityAuditFilterChange = async () => {
  securityAuditPage.value = 1
  await syncSettingsAuditRoute()
  await loadSecurityAudit()
}

const handleSecurityAuditPageChange = async (page: number) => {
  securityAuditPage.value = page
  await syncSettingsAuditRoute()
  await loadSecurityAudit()
}

const handleSecurityAuditSizeChange = async (size: number) => {
  securityAuditPageSize.value = size
  securityAuditPage.value = 1
  await syncSettingsAuditRoute()
  await loadSecurityAudit()
}

const resetSecurityAuditFilters = async () => {
  securityAuditFilters.action = ''
  securityAuditFilters.resource_type = ''
  securityAuditFilters.client_id = ''
  securityAuditFilters.provider_id = ''
  securityAuditFilters.organization_id = ''
  securityAuditFilters.actor_id = ''
  securityAuditFilters.query = ''
  securityAuditFilters.success = 'all'
  securityAuditTimeRange.value = null
  securityAuditPage.value = 1
  securityAuditPageSize.value = 10
  await syncSettingsAuditRoute()
  await loadSecurityAudit()
}

const exportSecurityAudit = async () => {
  securityAuditExportLoading.value = true
  try {
    const blob = await serverApi.exportSecurityAuditCSV(buildSecurityAuditQuery())
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    const timestamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19)
    link.href = url
    link.download = `security-audit-${timestamp}.csv`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)
    ElMessage.success('安全审计 CSV 导出成功')
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '导出安全审计失败')
  } finally {
    securityAuditExportLoading.value = false
  }
}

const clearSecurityAuditExportPollTimer = () => {
  if (securityAuditExportPollTimer !== null) {
    window.clearTimeout(securityAuditExportPollTimer)
    securityAuditExportPollTimer = null
  }
}

const dismissSecurityAuditExportJob = () => {
  clearSecurityAuditExportPollTimer()
  securityAuditExportJob.value = null
  lastSettledSecurityAuditExportJob = ''
}

const securityAuditExportJobAlertType = computed(() => {
  const status = securityAuditExportJob.value?.status
  if (status === 'completed') return 'success'
  if (status === 'failed') return 'error'
  return 'info'
})

const securityAuditExportJobTitle = computed(() => {
  const job = securityAuditExportJob.value
  if (!job) return ''
  if (job.status === 'completed') return `后台导出已完成 · ${job.job_id}`
  if (job.status === 'failed') return `后台导出失败 · ${job.job_id}`
  return `后台导出进行中 · ${job.job_id}`
})

const securityAuditExportJobSummary = computed(() => {
  const job = securityAuditExportJob.value
  if (!job) return ''
  if (job.status === 'completed') {
    const parts = [`共匹配 ${job.total_count} 条`, `已导出 ${job.row_count} 条`]
    if (job.truncated) parts.push('结果已按上限截断')
    return parts.join('，')
  }
  if (job.status === 'failed') {
    return job.error || '后台导出任务执行失败'
  }
  return '服务器正在后台准备 CSV，完成后可直接下载，不会阻塞当前页面操作。'
})

const scheduleSecurityAuditExportPoll = (jobId: string) => {
  clearSecurityAuditExportPollTimer()
  securityAuditExportPollTimer = window.setTimeout(() => {
    refreshSecurityAuditExportJob(jobId, true)
  }, 1500)
}

const applySecurityAuditExportJob = (job: SecurityAuditExportJob, silent = false) => {
  securityAuditExportJob.value = job
  if (job.status === 'pending' || job.status === 'running') {
    scheduleSecurityAuditExportPoll(job.job_id)
    return
  }
  clearSecurityAuditExportPollTimer()
  void loadSecurityAuditExportJobs()
  const settledKey = `${job.job_id}:${job.status}`
  if (silent || lastSettledSecurityAuditExportJob === settledKey) return
  lastSettledSecurityAuditExportJob = settledKey
  if (job.status === 'completed') {
    ElMessage.success('后台安全审计导出已完成')
  } else if (job.status === 'failed') {
    ElMessage.error(job.error || '后台安全审计导出失败')
  }
}

const refreshSecurityAuditExportJob = async (jobId?: string, silent = false) => {
  const targetJobID = jobId || securityAuditExportJob.value?.job_id
  if (!targetJobID) return
  try {
    const response = await serverApi.getSecurityAuditExportJob(targetJobID)
    applySecurityAuditExportJob(response.job, silent)
  } catch (error: any) {
    if (!silent) {
      ElMessage.error(error?.response?.data?.error || '刷新后台导出任务失败')
    }
  }
}

const createSecurityAuditExportJob = async () => {
  securityAuditAsyncExportLoading.value = true
  try {
    const response = await serverApi.createSecurityAuditExportJob(buildSecurityAuditQuery())
    lastSettledSecurityAuditExportJob = ''
    applySecurityAuditExportJob(response.job, true)
    await loadSecurityAuditExportJobs()
    ElMessage.success(response.message || '已创建后台导出任务')
    await refreshSecurityAuditExportJob(response.job.job_id)
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '创建后台导出任务失败')
  } finally {
    securityAuditAsyncExportLoading.value = false
  }
}

const downloadSecurityAuditExportJob = async () => {
  const job = securityAuditExportJob.value
  if (!job?.download_ready) return
  try {
    const blob = await serverApi.downloadSecurityAuditExportJob(job.job_id)
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = job.filename || `security-audit-${job.job_id}.csv`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)
    ElMessage.success('后台安全审计导出已下载')
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '下载后台导出结果失败')
  }
}

const trackSecurityAuditExportJob = async (job: SecurityAuditExportJob) => {
  securityAuditExportJob.value = job
  lastSettledSecurityAuditExportJob = ''
  await refreshSecurityAuditExportJob(job.job_id, true)
}

const downloadListedSecurityAuditExportJob = async (job: SecurityAuditExportJob) => {
  await trackSecurityAuditExportJob(job)
  await downloadSecurityAuditExportJob()
}

const deleteSecurityAuditExportJobEntry = async (job: SecurityAuditExportJob) => {
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
  securityAuditExportJobActionId.value = `delete:${job.job_id}`
  try {
    const response = await serverApi.deleteSecurityAuditExportJob(job.job_id)
    clearTrackedSecurityAuditExportJobIfNeeded(job.job_id)
    ElMessage.success(response.message || '后台导出任务已删除')
    await loadSecurityAuditExportJobs()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '删除后台导出任务失败')
  } finally {
    securityAuditExportJobActionId.value = ''
  }
}

const cleanupSecurityAuditExportJobs = async () => {
  try {
    await ElMessageBox.confirm(
      `确定按当前保留策略清理已完成或已失败的后台导出任务吗？运行中的任务不会受影响。`,
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
  securityAuditCleanupLoading.value = true
  try {
    const response = await serverApi.cleanupSecurityAuditExportJobs()
    if (securityAuditExportJob.value && (securityAuditExportJob.value.status === 'completed' || securityAuditExportJob.value.status === 'failed')) {
      await refreshSecurityAuditExportJob(securityAuditExportJob.value.job_id, true).catch(() => dismissSecurityAuditExportJob())
    }
    ElMessage.success(response.result.deleted > 0 ? `已清理 ${response.result.deleted} 个旧导出任务` : '没有可清理的旧导出任务')
    await loadSecurityAuditExportJobs()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '清理旧导出任务失败')
  } finally {
    securityAuditCleanupLoading.value = false
  }
}

const openSecurityAuditDetail = (entry: SecurityAuditEntry) => {
  selectedSecurityAuditEntry.value = entry
  selectedSecurityAuditActionLabel.value = formatSecurityAuditAction(entry.action)
  securityAuditDetailVisible.value = true
}

const applySecurityAuditJumpFilter = async (filter: Partial<SecurityAuditQuery>) => {
  securityAuditFilters.action = ''
  securityAuditFilters.resource_type = filter.resource_type || ''
  securityAuditFilters.client_id = filter.client_id || ''
  securityAuditFilters.provider_id = filter.provider_id || ''
  securityAuditFilters.organization_id = filter.organization_id || ''
  securityAuditFilters.actor_id = ''
  securityAuditFilters.query = ''
  securityAuditFilters.success = typeof filter.success === 'boolean' ? (filter.success ? 'true' : 'false') : 'all'
  securityAuditTimeRange.value = null
  securityAuditPage.value = 1
  securityAuditDetailVisible.value = false
  await syncSettingsAuditRoute()
  await loadSecurityAudit()
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

const copySecurityAuditFilterLink = async () => {
  await syncSettingsAuditRoute()
  const resolved = router.resolve({
    name: 'Settings',
    query: buildSettingsAuditRouteQuery()
  })
  const base = typeof window !== 'undefined' ? window.location.origin : ''
  const targetURL = `${base}${resolved.href}`
  try {
    await writeClipboard(targetURL)
    ElMessage.success('安全审计筛选链接已复制')
  } catch {
    ElMessage.error('复制筛选链接失败')
  }
}

const openSecurityAuditResource = async (resource: {
  resource_type: string
  client_id?: string
  provider_id?: string
  organization_id?: string
  mapper_id?: string
}) => {
  if (resource.resource_type === 'oidc_client' && resource.client_id) {
    let targetClient = oidcClients.value.find(client => client.client_id === resource.client_id)
    if (!targetClient) {
      await loadOIDCClients()
      targetClient = oidcClients.value.find(client => client.client_id === resource.client_id)
    }
    if (!targetClient) {
      ElMessage.warning('该 OIDC Client 可能已删除，无法直接打开配置')
      return
    }
    securityAuditDetailVisible.value = false
    openOIDCDialog(targetClient)
    return
  }
  if (resource.resource_type === 'identity_provider' && resource.provider_id && resource.organization_id) {
    securityAuditDetailVisible.value = false
    await router.push({
      name: 'Organizations',
      query: {
        organization_id: resource.organization_id,
        tab: 'identity-providers',
        provider_id: resource.provider_id,
        open: 'edit'
      }
    })
    return
  }
  if (resource.resource_type === 'claim_mapper' && resource.mapper_id) {
    let targetMapper = claimMappers.value.find(mapper => mapper.mapper_id === resource.mapper_id)
    if (!targetMapper) {
      await loadClaimMappers()
      targetMapper = claimMappers.value.find(mapper => mapper.mapper_id === resource.mapper_id)
    }
    if (!targetMapper) {
      ElMessage.warning('该 Claim Mapper 可能已删除，无法直接打开配置')
      return
    }
    securityAuditDetailVisible.value = false
    openClaimMapperDialog(targetMapper)
    return
  }
  if (resource.resource_type === 'organization_admin' && resource.organization_id) {
    securityAuditDetailVisible.value = false
    await router.push({
      name: 'Organizations',
      query: {
        organization_id: resource.organization_id,
        tab: 'admins'
      }
    })
    return
  }
  ElMessage.info('当前审计记录暂不支持直接打开对应资源')
}

const resealManagedSecrets = async () => {
  securityResealLoading.value = true
  try {
    const response = await serverApi.resealManagedSecrets()
    ElMessage.success(response.message || '已重写托管 secrets')
    await Promise.all([loadSecurityStatus(), loadSecurityAudit(), loadOIDCClients()])
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '重写托管 secrets 失败')
    await loadSecurityAudit()
  } finally {
    securityResealLoading.value = false
  }
}

const loadOIDCClients = async () => {
  oidcLoading.value = true
  try {
    const response = await serverApi.getOIDCClients()
    oidcClients.value = response.clients || []
    oidcLoadError.value = ''
  } catch (error: any) {
    oidcClients.value = []
    oidcLoadError.value = error?.response?.data?.error || '加载 OIDC clients 失败'
  } finally {
    oidcLoading.value = false
  }
}

const loadClaimMappers = async () => {
  claimMapperLoading.value = true
  try {
    const response = await serverApi.getClaimMappers()
    claimMappers.value = response.claim_mappers || []
    claimMapperLoadError.value = ''
  } catch (error: any) {
    claimMappers.value = []
    claimMapperLoadError.value = error?.response?.data?.error || '加载 Claim Mappers 失败'
  } finally {
    claimMapperLoading.value = false
  }
}

const formatOIDCPolicy = (client: OIDCClient) => {
  if (!client.require_organization &&
    (!client.required_org_roles?.length) &&
    (!client.required_org_roles_all?.length) &&
    (!client.required_org_groups?.length) &&
    (!client.required_org_groups_all?.length) &&
    (!client.allowed_organizations?.length) &&
    (!client.scope_policies || Object.keys(client.scope_policies).length === 0)) {
    return '无组织限制'
  }
  const parts: string[] = []
  if (client.require_organization) parts.push('需要组织上下文')
  if (client.allowed_organizations?.length) parts.push(`组织:${client.allowed_organizations.join(', ')}`)
  if (client.required_org_roles?.length) parts.push(`角色任一:${client.required_org_roles.join(', ')}`)
  if (client.required_org_roles_all?.length) parts.push(`角色全部:${client.required_org_roles_all.join(', ')}`)
  if (client.required_org_groups?.length) parts.push(`组任一:${client.required_org_groups.join(', ')}`)
  if (client.required_org_groups_all?.length) parts.push(`组全部:${client.required_org_groups_all.join(', ')}`)
  if (client.scope_policies && Object.keys(client.scope_policies).length > 0) parts.push(`Scope 策略:${Object.keys(client.scope_policies).length}`)
  return parts.join(' | ')
}

const formatAdminClaimMapperSource = (mapper: AdminClaimMapper) => {
  if (mapper.value_from) return `from ${mapper.value_from}`
  if (mapper.value) return `= ${mapper.value}`
  return '-'
}

const formatAdminClaimMapperScope = (mapper: AdminClaimMapper) => {
  const parts: string[] = []
  if (mapper.clients?.length) parts.push(`clients:${mapper.clients.join(', ')}`)
  if (mapper.organizations?.length) parts.push(`orgs:${mapper.organizations.join(', ')}`)
  return parts.length > 0 ? parts.join(' | ') : '全部'
}

const formatSecurityAuditAction = (action: string) => {
  const labels: Record<string, string> = {
    secrets_reseal: '重写托管 Secrets',
    oidc_client_create: '创建 OIDC Client',
    oidc_client_update: '更新 OIDC Client',
    oidc_client_delete: '删除 OIDC Client',
    identity_provider_create: '创建企业身份源',
    identity_provider_update: '更新企业身份源',
    identity_provider_delete: '删除企业身份源',
    claim_mapper_create: '创建 Claim Mapper',
    claim_mapper_update: '更新 Claim Mapper',
    claim_mapper_delete: '删除 Claim Mapper',
    admin_principal_create: '添加管理员',
    admin_principal_delete: '移除管理员',
    organization_admin_create: '添加组织管理员',
    organization_admin_delete: '移除组织管理员'
  }
  return labels[action] || action || '-'
}

const formatSecurityAuditDetails = (entry: SecurityAuditEntry) => {
  if (entry.error) return entry.error
  const details = entry.details || {}
  const parts: string[] = []
  if (details.resource_type === 'oidc_client') {
    if (details.client_id) parts.push(`Client ${details.client_id}`)
    if (details.previous_client_id) parts.push(`原 Client ${details.previous_client_id}`)
    if (details.name) parts.push(`名称 ${details.name}`)
    if (details.source) parts.push(`来源 ${details.source}`)
    if (details.redirect_uri_count) parts.push(`回调 ${details.redirect_uri_count}`)
    if (details.require_organization) parts.push(`组织限制 ${details.require_organization === 'true' ? '开启' : '关闭'}`)
    if (details.required_org_roles_count) parts.push(`角色任一 ${details.required_org_roles_count}`)
    if (details.required_org_roles_all_count) parts.push(`角色全部 ${details.required_org_roles_all_count}`)
    if (details.required_org_groups_count) parts.push(`组任一 ${details.required_org_groups_count}`)
    if (details.required_org_groups_all_count) parts.push(`组全部 ${details.required_org_groups_all_count}`)
    if (details.scope_policy_count) parts.push(`Scope 策略 ${details.scope_policy_count}`)
  }
  if (details.resource_type === 'identity_provider') {
    if (details.provider_type) parts.push(`类型 ${details.provider_type.toUpperCase()}`)
    if (details.slug) parts.push(`Slug ${details.slug}`)
    if (details.previous_slug) parts.push(`原 Slug ${details.previous_slug}`)
    if (details.name) parts.push(`名称 ${details.name}`)
    if (details.organization_id) parts.push(`组织 ${details.organization_id}`)
  }
  if (details.resource_type === 'claim_mapper') {
    if (details.mapper_id) parts.push(`Mapper ${details.mapper_id}`)
    if (details.name) parts.push(`名称 ${details.name}`)
    if (details.claim) parts.push(`Claim ${details.claim}`)
    if (details.value_from) parts.push(`来源 ${details.value_from}`)
    if (details.client_count) parts.push(`Clients ${details.client_count}`)
    if (details.organization_count) parts.push(`组织 ${details.organization_count}`)
    if (details.event_count) parts.push(`事件 ${details.event_count}`)
  }
  if (details.resource_type === 'organization_admin') {
    if (details.organization_id) parts.push(`组织 ${details.organization_id}`)
    if (details.user_id) parts.push(`用户 ${details.user_id}`)
    if (details.username) parts.push(`用户名 ${details.username}`)
  }
  if (details.oidc_clients) parts.push(`OIDC clients ${details.oidc_clients}`)
  if (details.identity_providers) parts.push(`身份源 ${details.identity_providers}`)
  if (details.fallback_key_count) parts.push(`fallback keys ${details.fallback_key_count}`)
  if (details.enabled) parts.push(`启用 ${details.enabled === 'true' ? '是' : '否'}`)
  if (details.public) parts.push(`Public ${details.public === 'true' ? '是' : '否'}`)
  if (details.require_pkce) parts.push(`PKCE ${details.require_pkce === 'true' ? '开启' : '关闭'}`)
  if (details.priority) parts.push(`优先级 ${details.priority}`)
  if (details.is_default) parts.push(`默认 ${details.is_default === 'true' ? '是' : '否'}`)
  if (details.auto_redirect) parts.push(`自动跳转 ${details.auto_redirect === 'true' ? '是' : '否'}`)
  if (details.stage) parts.push(`阶段 ${details.stage}`)
  if (details.reason) parts.push(`原因 ${details.reason}`)
  return parts.length > 0 ? parts.join(' | ') : '-'
}

const formatSecurityAuditExportJobStatus = (status: string) => {
  const labels: Record<string, string> = {
    pending: '排队中',
    running: '导出中',
    completed: '已完成',
    failed: '失败'
  }
  return labels[status] || status || '-'
}

const securityAuditExportJobTagType = (status: string) => {
  if (status === 'completed') return 'success'
  if (status === 'failed') return 'danger'
  return 'info'
}

const formatSecurityAuditExportJobScope = (job: SecurityAuditExportJob) => {
  const query = job.query || {}
  const parts: string[] = []
  if (query.organization_id) parts.push(`组织 ${query.organization_id}`)
  if (query.provider_id) parts.push(`Provider ${query.provider_id}`)
  if (query.client_id) parts.push(`Client ${query.client_id}`)
  if (query.resource_type) parts.push(`资源 ${query.resource_type}`)
  if (query.action) parts.push(`动作 ${formatSecurityAuditAction(query.action)}`)
  if (query.query) parts.push(`关键词 ${query.query}`)
  return parts.length > 0 ? parts.join(' | ') : '全部安全审计'
}

const formatSecurityAuditExportJobResult = (job: SecurityAuditExportJob) => {
  if (job.status === 'failed') return job.error || '-'
  if (job.status === 'completed') {
    const parts = [`${job.row_count} / ${job.total_count}`]
    if (job.truncated) parts.push('已截断')
    return parts.join(' | ')
  }
  return '-'
}

const openOIDCDialog = (client?: OIDCClient) => {
  resetOIDCForm()
  if (!client) {
    oidcDialogMode.value = 'create'
    oidcDialogVisible.value = true
    return
  }
  oidcDialogMode.value = 'edit'
  oidcForm.original_client_id = client.client_id
  oidcForm.name = client.name || ''
  oidcForm.client_id = client.client_id
  oidcForm.client_secret = ''
  oidcForm.grant_types_text = serializeLineList(client.grant_types?.length ? client.grant_types : ['authorization_code'])
  oidcForm.service_account_subject = client.service_account_subject || ''
  oidcForm.redirect_uris_text = serializeLineList(client.redirect_uris)
  oidcForm.scopes_text = serializeLineList(client.scopes)
  oidcForm.allowed_organizations_text = serializeLineList(client.allowed_organizations)
  oidcForm.required_org_roles_text = serializeLineList(client.required_org_roles)
  oidcForm.required_org_roles_all_text = serializeLineList(client.required_org_roles_all)
  oidcForm.required_org_groups_text = serializeLineList(client.required_org_groups)
  oidcForm.required_org_groups_all_text = serializeLineList(client.required_org_groups_all)
  oidcForm.scope_policies_json = serializeScopePolicies(client.scope_policies)
  oidcForm.public = client.public
  oidcForm.require_pkce = client.require_pkce
  oidcForm.require_organization = client.require_organization
  oidcForm.enabled = client.enabled
  oidcForm.client_secret_configured = client.client_secret_configured
  oidcDialogVisible.value = true
}

const oidcSecretPlaceholder = () => {
  if (oidcDialogMode.value === 'edit' && oidcForm.client_secret_configured) return '已配置；留空则保持不变'
  if (oidcForm.public) return 'Public client 可留空'
  return '请输入 client secret'
}

const saveOIDCClient = async () => {
  let scopePolicies: Record<string, OIDCOrganizationPolicy> | undefined
  try {
    scopePolicies = parseScopePolicies(oidcForm.scope_policies_json)
  } catch (error: any) {
    ElMessage.error(error?.message || 'Scope Policies JSON 格式错误')
    return
  }
  const payload = {
    name: oidcForm.name.trim(),
    client_id: oidcForm.client_id.trim(),
    client_secret: oidcForm.client_secret.trim(),
    grant_types: parseLineList(oidcForm.grant_types_text),
    service_account_subject: oidcForm.service_account_subject.trim(),
    redirect_uris: parseLineList(oidcForm.redirect_uris_text),
    scopes: parseLineList(oidcForm.scopes_text),
    public: oidcForm.public,
    require_pkce: oidcForm.require_pkce,
    require_organization: oidcForm.require_organization,
    allowed_organizations: parseLineList(oidcForm.allowed_organizations_text),
    required_org_roles: parseLineList(oidcForm.required_org_roles_text),
    required_org_roles_all: parseLineList(oidcForm.required_org_roles_all_text),
    required_org_groups: parseLineList(oidcForm.required_org_groups_text),
    required_org_groups_all: parseLineList(oidcForm.required_org_groups_all_text),
    scope_policies: scopePolicies,
    enabled: oidcForm.enabled
  }
  oidcDialogSubmitting.value = true
  try {
    if (oidcDialogMode.value === 'create') {
      const response = await serverApi.createOIDCClient(payload)
      ElMessage.success(response.client?.client_id ? `已创建 ${response.client.client_id}` : 'OIDC client 创建成功')
    } else {
      const response = await serverApi.updateOIDCClient(oidcForm.original_client_id, payload)
      ElMessage.success(response.client?.client_id ? `已更新 ${response.client.client_id}` : 'OIDC client 更新成功')
    }
    oidcDialogVisible.value = false
    await Promise.all([loadOIDCClients(), loadSecurityAudit()])
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '保存 OIDC client 失败')
    await loadSecurityAudit()
  } finally {
    oidcDialogSubmitting.value = false
  }
}

const deleteOIDCClient = async (client: OIDCClient) => {
  try {
    await ElMessageBox.confirm(
      `确定删除 OIDC client ${client.name || client.client_id} 吗？`,
      '删除 OIDC Client',
      {
        confirmButtonText: '删除',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )
  } catch {
    return
  }

  oidcActionLoadingId.value = `delete:${client.client_id}`
  try {
    const response = await serverApi.deleteOIDCClient(client.client_id)
    ElMessage.success(response.message || 'OIDC client 已删除')
    await Promise.all([loadOIDCClients(), loadSecurityAudit()])
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '删除 OIDC client 失败')
    await loadSecurityAudit()
  } finally {
    oidcActionLoadingId.value = ''
  }
}

const openClaimMapperDialog = (mapper?: AdminClaimMapper) => {
  resetClaimMapperForm()
  if (!mapper) {
    claimMapperDialogMode.value = 'create'
    claimMapperDialogVisible.value = true
    return
  }
  claimMapperDialogMode.value = 'edit'
  claimMapperForm.mapper_id = mapper.mapper_id
  claimMapperForm.name = mapper.name || ''
  claimMapperForm.description = mapper.description || ''
  claimMapperForm.enabled = mapper.enabled
  claimMapperForm.claim = mapper.claim || ''
  claimMapperForm.value = mapper.value || ''
  claimMapperForm.value_from = mapper.value_from || ''
  claimMapperForm.events_text = serializeLineList(mapper.events)
  claimMapperForm.clients_text = serializeLineList(mapper.clients)
  claimMapperForm.organizations_text = serializeLineList(mapper.organizations)
  claimMapperDialogVisible.value = true
}

const saveClaimMapper = async () => {
  const payload = {
    name: claimMapperForm.name.trim(),
    description: claimMapperForm.description.trim(),
    enabled: claimMapperForm.enabled,
    claim: claimMapperForm.claim.trim(),
    value: claimMapperForm.value.trim(),
    value_from: claimMapperForm.value_from.trim(),
    events: parseLineList(claimMapperForm.events_text),
    clients: parseLineList(claimMapperForm.clients_text),
    organizations: parseLineList(claimMapperForm.organizations_text)
  }
  claimMapperDialogSubmitting.value = true
  try {
    if (claimMapperDialogMode.value === 'create') {
      const response = await serverApi.createClaimMapper(payload)
      ElMessage.success(response.claim_mapper?.name ? `已创建 ${response.claim_mapper.name}` : 'Claim Mapper 创建成功')
    } else {
      const response = await serverApi.updateClaimMapper(claimMapperForm.mapper_id, payload)
      ElMessage.success(response.claim_mapper?.name ? `已更新 ${response.claim_mapper.name}` : 'Claim Mapper 更新成功')
    }
    claimMapperDialogVisible.value = false
    await Promise.all([loadClaimMappers(), loadPlugins(), loadSecurityAudit()])
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '保存 Claim Mapper 失败')
    await loadSecurityAudit()
  } finally {
    claimMapperDialogSubmitting.value = false
  }
}

const deleteClaimMapper = async (mapper: AdminClaimMapper) => {
  try {
    await ElMessageBox.confirm(
      `确定删除 Claim Mapper ${mapper.name || mapper.mapper_id} 吗？`,
      '删除 Claim Mapper',
      {
        confirmButtonText: '删除',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )
  } catch {
    return
  }

  claimMapperActionLoadingId.value = `delete:${mapper.mapper_id}`
  try {
    const response = await serverApi.deleteClaimMapper(mapper.mapper_id)
    ElMessage.success(response.message || 'Claim Mapper 已删除')
    await Promise.all([loadClaimMappers(), loadPlugins(), loadSecurityAudit()])
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '删除 Claim Mapper 失败')
    await loadSecurityAudit()
  } finally {
    claimMapperActionLoadingId.value = ''
  }
}

const catalogStatusLabel = (plugin: CatalogPluginInfo) => {
  if (plugin.update_available) {
    return plugin.installed_version ? `可更新 ${plugin.installed_version}→${plugin.version || '?'}` : '可更新'
  }
  if (plugin.installed) {
    return plugin.installed_version ? `已安装 ${plugin.installed_version}` : '已安装'
  }
  return '未安装'
}

const catalogStatusTagType = (plugin: CatalogPluginInfo) => {
  if (plugin.update_available) return 'warning'
  if (plugin.installed) return 'success'
  return 'info'
}

const catalogActionLabel = (plugin: CatalogPluginInfo) => {
  if (plugin.update_available) return '更新'
  if (plugin.installed) return '重装'
  return '安装'
}

const configPlaceholder = (field: PluginConfigField) => {
  if (field.sensitive && configConfigured.value[field.key]) return '已配置；留空则保持不变'
  return field.description || field.default || field.key
}

const formatAuditAction = (action: string) => {
  const labels: Record<string, string> = {
    install_upload: '上传安装',
    replace_upload: '覆盖安装',
    install_url: 'URL安装',
    install_catalog: '目录安装',
    enable: '启用',
    disable: '禁用',
    uninstall: '卸载',
    restore: '恢复',
    configure: '配置'
  }
  return labels[action] || action || '-'
}

const formatBackupReason = (reason?: string) => {
  const labels: Record<string, string> = {
    replace: '覆盖前',
    uninstall: '卸载前',
    restore_replace: '恢复前'
  }
  return labels[reason || ''] || reason || '-'
}

const formatAuditTime = (value?: string) => {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString()
}

const formatAuditDetails = (entry: PluginAuditEntry) => {
  if (entry.error) return entry.error
  const details = entry.details || {}
  if (details.enabled) return details.enabled === 'true' ? '已启用' : '已禁用'
  if (details.package_sha256) return `包 ${formatHash(details.package_sha256)}`
  if (details.filename) return details.filename
  return '-'
}

const loadPlugins = async () => {
  loading.value = true
  try {
    const response = await serverApi.getPlugins()
    plugins.value = response.plugins || []
    catalogLoadError.value = ''
    try {
      const auditResponse = await serverApi.getPluginAudit(100)
      auditEntries.value = auditResponse.audit || []
    } catch {
      auditEntries.value = []
    }
    try {
      const backupResponse = await serverApi.getPluginBackups(100)
      backupEntries.value = backupResponse.backups || []
    } catch {
      backupEntries.value = []
    }
    try {
      const catalogResponse = await serverApi.getPluginCatalog()
      catalogPlugins.value = catalogResponse.plugins || []
    } catch (error: any) {
      catalogPlugins.value = []
      catalogLoadError.value = error?.response?.data?.error || '加载远程插件目录失败'
    }
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载插件列表失败')
  } finally {
    loading.value = false
  }
}

const triggerFileSelect = () => {
  fileInput.value?.click()
}

const handleFileChange = async (event: Event) => {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return

  actionLoadingId.value = 'preview:upload'
  try {
    const response = await serverApi.previewPlugin(file, replaceOnInstall.value)
    selectedInstallFile.value = file
    installPreview.value = response.preview
    installPreviewDialogVisible.value = true
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '插件预检失败')
  } finally {
    input.value = ''
    actionLoadingId.value = ''
  }
}

const confirmInstallPreview = async () => {
  if (!selectedInstallFile.value || !installPreview.value) return
  installLoading.value = true
  try {
    const response = await serverApi.installPlugin(selectedInstallFile.value, installPreview.value.effective_replace || replaceOnInstall.value)
    ElMessage.success(response.message || '插件安装成功')
    installPreviewDialogVisible.value = false
    selectedInstallFile.value = null
    installPreview.value = null
    await loadPlugins()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '插件安装失败')
  } finally {
    installLoading.value = false
  }
}

const clearInstallPreview = () => {
  if (installLoading.value) return
  selectedInstallFile.value = null
  installPreview.value = null
}

const installFromURL = async (catalogPlugin?: CatalogPluginInfo) => {
  actionLoadingId.value = catalogPlugin ? `catalog:${catalogPlugin.catalog_id}:${catalogPlugin.id}` : 'install:url'
  try {
    let response
    if (catalogPlugin) {
      response = await serverApi.installPluginFromCatalog({
        catalog_id: catalogPlugin.catalog_id,
        plugin_id: catalogPlugin.id,
        replace: catalogPlugin.installed || replaceOnInstall.value
      })
    } else {
      const url = remoteInstallURL.value.trim()
      if (!url) {
        ElMessage.warning('请输入插件 ZIP 下载地址')
        return
      }
      response = await serverApi.installPluginFromURL({
        url,
        replace: replaceOnInstall.value,
        source: `url:${url}`
      })
    }
    ElMessage.success(response.message || '插件安装成功')
    if (!catalogPlugin) {
      remoteInstallURL.value = ''
    }
    await loadPlugins()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '插件安装失败')
  } finally {
    actionLoadingId.value = ''
  }
}

const togglePlugin = async (plugin: PluginInfo) => {
  actionLoadingId.value = `toggle:${plugin.id}`
  try {
    const response = await serverApi.updatePlugin(plugin.id, !plugin.enabled)
    ElMessage.success(response.message || '插件状态已更新')
    await loadPlugins()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '插件状态更新失败')
  } finally {
    actionLoadingId.value = ''
  }
}

const deletePlugin = async (plugin: PluginInfo) => {
  try {
    await ElMessageBox.confirm(
      `确定删除插件 ${plugin.name || plugin.id} 吗？此操作会立即卸载本地插件目录。`,
      '删除插件',
      {
        confirmButtonText: '删除',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )
  } catch {
    return
  }

  actionLoadingId.value = `delete:${plugin.id}`
  try {
    const response = await serverApi.deletePlugin(plugin.id)
    ElMessage.success(response.message || '插件已删除')
    await loadPlugins()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '插件删除失败')
  } finally {
    actionLoadingId.value = ''
  }
}

const openPluginConfig = async (plugin: PluginInfo) => {
  actionLoadingId.value = `config:${plugin.id}`
  try {
    const view = await serverApi.getPluginConfig(plugin.id)
    activeConfigPlugin.value = plugin
    configSchema.value = view.schema || []
    configValues.value = { ...(view.values || {}) }
    configConfigured.value = { ...(view.configured || {}) }
    configDialogVisible.value = true
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载插件配置失败')
  } finally {
    actionLoadingId.value = ''
  }
}

const savePluginConfig = async () => {
  if (!activeConfigPlugin.value) return
  configLoading.value = true
  try {
    const response = await serverApi.updatePluginConfig(activeConfigPlugin.value.id, configValues.value)
    ElMessage.success(response.message || '插件配置已保存')
    configDialogVisible.value = false
    await loadPlugins()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '插件配置保存失败')
  } finally {
    configLoading.value = false
  }
}

const restoreBackup = async (backup: PluginBackupInfo) => {
  try {
    await ElMessageBox.confirm(
      `确定恢复插件 ${backup.plugin_name || backup.plugin_id} 到该快照吗？当前同名插件会先自动备份。`,
      '恢复插件快照',
      {
        confirmButtonText: '恢复',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )
  } catch {
    return
  }

  actionLoadingId.value = `restore:${backup.id}`
  try {
    const response = await serverApi.restorePluginBackup(backup.id)
    ElMessage.success(response.message || '插件已恢复')
    await loadPlugins()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '插件恢复失败')
  } finally {
    actionLoadingId.value = ''
  }
}

watch(
  () => route.query,
  async () => {
    if (route.name !== 'Settings' || syncingSettingsAuditRoute) return
    applySettingsAuditRouteState()
    await loadSecurityAudit()
  },
  { deep: true }
)

onMounted(() => {
  applySettingsAuditRouteState()
  loadAdmins()
  loadSecurityStatus()
  loadSecurityAudit()
  loadSecurityAuditExportJobs()
  loadOIDCClients()
  loadClaimMappers()
  loadPlugins()
})

onUnmounted(() => {
  clearSecurityAuditExportPollTimer()
})
</script>

<style lang="scss" scoped>
.settings-container {
  .settings-card {
    margin-bottom: 20px;
  }

  .inline-form {
    display: flex;
    gap: 12px;
    margin-bottom: 18px;
  }

  .stacked-copy {
    display: flex;
    flex-direction: column;
    gap: 4px;

    strong {
      color: #111827;
    }

    span {
      color: #6b7280;
      font-size: 0.92rem;
    }
  }

  .tag-cluster {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .muted-copy {
    color: #9ca3af;
    font-size: 0.92rem;
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

    .subhead {
      margin: 0;
      color: #6b7280;
      line-height: 1.5;
    }
  }

  .plugin-alert {
    margin-bottom: 18px;
  }

  .export-job-alert {
    margin-bottom: 18px;
  }

  .audit-jobs-card {
    margin-bottom: 18px;
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
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 18px;
    padding: 16px 18px;
    border-radius: 14px;
    background: linear-gradient(135deg, rgba(244, 247, 250, 0.95), rgba(234, 241, 247, 0.95));
  }

  .toolbar-copy {
    display: flex;
    flex-direction: column;
    gap: 4px;

    span {
      color: #64748b;
      line-height: 1.5;
    }
  }

  .toolbar-actions {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-shrink: 0;
  }

  .remote-actions {
    width: min(720px, 100%);
  }

  .catalog-card {
    margin-bottom: 18px;
    border-radius: 14px;
  }

  .audit-card {
    margin-top: 18px;
    border-radius: 14px;
  }

  .audit-toolbar {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
    flex-wrap: wrap;

    :deep(.el-select) {
      width: 180px;
    }

    :deep(.el-input) {
      width: 220px;
    }

    :deep(.el-date-editor) {
      width: 360px;
    }
  }

  .audit-pagination {
    margin-top: 16px;
    display: flex;
    justify-content: flex-end;
  }

  .catalog-header {
    p {
      margin: 6px 0 0;
      color: #64748b;
    }
  }

  .hidden-input {
    display: none;
  }

  .events {
    color: #475569;
    word-break: break-word;
  }

  .hash {
    color: #334155;
    font-family: 'SFMono-Regular', 'Menlo', monospace;
    font-size: 12px;
  }

  .table-actions {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .security-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 14px;
    margin-bottom: 18px;
  }

  .security-metric {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 14px 16px;
    border-radius: 14px;
    background: linear-gradient(135deg, rgba(248, 250, 252, 0.96), rgba(237, 242, 247, 0.96));

    strong {
      color: #0f172a;
      font-size: 13px;
    }

    span {
      color: #334155;
      font-size: 18px;
      font-weight: 600;
    }
  }

  .oidc-name {
    display: flex;
    flex-direction: column;
    gap: 4px;

    strong {
      color: #0f172a;
    }

    span {
      color: #64748b;
      font-size: 12px;
      font-family: 'SFMono-Regular', 'Menlo', monospace;
    }
  }

  .oidc-form-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 16px;
  }

  .preview-block {
    margin-top: 14px;
    padding: 12px 14px;
    border-radius: 12px;
    background: #f8fafc;

    strong {
      display: block;
      margin-bottom: 6px;
      color: #0f172a;
    }

    p {
      margin: 4px 0;
    }
  }

  .warning-text {
    color: #b45309;
  }

  .danger-text {
    color: #b91c1c;
  }

  .config-control {
    width: 100%;
  }

  .field-help {
    margin: 6px 0 0;
    color: #64748b;
    font-size: 12px;
    line-height: 1.5;
  }

  .form-tip {
    margin-top: 8px;
    color: #64748b;
    font-size: 12px;
    line-height: 1.5;
  }
}

@media (max-width: 900px) {
  .settings-container {
    .card-header,
    .toolbar {
      flex-direction: column;
      align-items: stretch;
    }

    .oidc-form-grid {
      grid-template-columns: 1fr;
    }

    .security-grid {
      grid-template-columns: 1fr 1fr;
    }

    .audit-pagination {
      justify-content: flex-start;
    }

    .toolbar-actions {
      justify-content: flex-start;
      flex-wrap: wrap;
    }

    .remote-actions {
      width: 100%;
    }
  }
}

@media (max-width: 640px) {
  .settings-container {
    .security-grid {
      grid-template-columns: 1fr;
    }
  }
}
</style>
