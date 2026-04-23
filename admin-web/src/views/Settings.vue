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
          <el-button type="primary" @click="triggerFileSelect">上传 ZIP 安装</el-button>
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
                安装
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
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index'
import { ElMessageBox } from 'element-plus/es/components/message-box/index'
import { serverApi, type CatalogPluginInfo, type PluginAuditEntry, type PluginBackupInfo, type PluginConfigField, type PluginInfo } from '@/api'

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
const configDialogVisible = ref(false)
const configLoading = ref(false)
const activeConfigPlugin = ref<PluginInfo | null>(null)
const configSchema = ref<PluginConfigField[]>([])
const configValues = ref<Record<string, string>>({})
const configConfigured = ref<Record<string, boolean>>({})

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

const formatHash = (hash?: string) => {
  if (!hash) return '-'
  if (hash.length <= 16) return hash
  return `${hash.slice(0, 12)}...${hash.slice(-8)}`
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
    restore: '恢复'
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

  loading.value = true
  try {
    const response = await serverApi.installPlugin(file, replaceOnInstall.value)
    ElMessage.success(response.message || '插件安装成功')
    await loadPlugins()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '插件安装失败')
  } finally {
    input.value = ''
    loading.value = false
  }
}

const installFromURL = async (catalogPlugin?: CatalogPluginInfo) => {
  actionLoadingId.value = catalogPlugin ? `catalog:${catalogPlugin.catalog_id}:${catalogPlugin.id}` : 'install:url'
  try {
    let response
    if (catalogPlugin) {
      response = await serverApi.installPluginFromCatalog({
        catalog_id: catalogPlugin.catalog_id,
        plugin_id: catalogPlugin.id,
        replace: replaceOnInstall.value
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

onMounted(() => {
  loadPlugins()
})
</script>

<style lang="scss" scoped>
.settings-container {
  .settings-card {
    margin-bottom: 20px;
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

  .config-control {
    width: 100%;
  }

  .field-help {
    margin: 6px 0 0;
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

    .toolbar-actions {
      justify-content: flex-start;
      flex-wrap: wrap;
    }

    .remote-actions {
      width: 100%;
    }
  }
}
</style>
