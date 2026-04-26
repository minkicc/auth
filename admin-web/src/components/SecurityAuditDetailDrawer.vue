<template>
  <el-drawer
    :model-value="modelValue"
    size="680px"
    append-to-body
    destroy-on-close
    @close="emit('update:modelValue', false)"
  >
    <template #header>
      <div class="drawer-header">
        <strong>{{ title }}</strong>
        <p>{{ actionLabel || entry?.action || '-' }}</p>
      </div>
    </template>

    <div v-if="entry" class="audit-detail">
      <section class="detail-section">
        <h4>快捷操作</h4>
        <div class="action-row">
          <el-button size="small" @click="copyText(entry.id, '审计 ID')">复制审计 ID</el-button>
          <el-button
            v-for="target in copyTargets"
            :key="target.label"
            size="small"
            @click="copyText(target.value, target.label)"
          >
            复制{{ target.label }}
          </el-button>
          <el-button size="small" @click="copyText(detailsJSON, '详情 JSON')">复制详情 JSON</el-button>
        </div>
        <div v-if="filterTargets.length > 0" class="action-row action-row-secondary">
          <el-button
            v-for="target in filterTargets"
            :key="target.label"
            size="small"
            type="primary"
            plain
            @click="emit('apply-filter', target.filter)"
          >
            {{ target.label }}
          </el-button>
        </div>
        <div v-if="resourceTargets.length > 0" class="action-row action-row-secondary">
          <el-button
            v-for="target in resourceTargets"
            :key="target.label"
            size="small"
            type="success"
            plain
            @click="emit('open-resource', target.resource)"
          >
            {{ target.label }}
          </el-button>
        </div>
      </section>

      <section class="detail-section">
        <h4>基本信息</h4>
        <el-descriptions :column="1" border>
          <el-descriptions-item label="时间">{{ formatDate(entry.time) }}</el-descriptions-item>
          <el-descriptions-item label="动作">{{ actionLabel || entry.action || '-' }}</el-descriptions-item>
          <el-descriptions-item label="结果">
            <el-tag :type="entry.success ? 'success' : 'danger'" effect="plain">
              {{ entry.success ? '成功' : '失败' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="审计 ID">{{ entry.id }}</el-descriptions-item>
        </el-descriptions>
      </section>

      <section class="detail-section">
        <h4>操作人</h4>
        <el-descriptions :column="1" border>
          <el-descriptions-item label="账号">{{ entry.actor?.id || '-' }}</el-descriptions-item>
          <el-descriptions-item label="IP">{{ entry.actor?.ip || '-' }}</el-descriptions-item>
          <el-descriptions-item label="User-Agent">
            <span class="break-text">{{ entry.actor?.user_agent || '-' }}</span>
          </el-descriptions-item>
        </el-descriptions>
      </section>

      <section v-if="entry.error" class="detail-section">
        <h4>错误信息</h4>
        <pre class="raw-block">{{ entry.error }}</pre>
      </section>

      <section class="detail-section">
        <h4>结构化详情</h4>
        <el-empty v-if="detailRows.length === 0" description="没有额外详情字段" :image-size="72" />
        <el-descriptions v-else :column="1" border>
          <el-descriptions-item
            v-for="row in detailRows"
            :key="row.key"
            :label="row.key"
          >
            <span class="break-text">{{ row.value }}</span>
          </el-descriptions-item>
        </el-descriptions>
      </section>

      <section class="detail-section">
        <h4>详情 JSON</h4>
        <pre class="raw-block">{{ detailsJSON }}</pre>
      </section>
    </div>
  </el-drawer>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index'
import type { SecurityAuditEntry, SecurityAuditQuery } from '@/api'

const props = withDefaults(defineProps<{
  modelValue: boolean
  entry: SecurityAuditEntry | null
  title?: string
  actionLabel?: string
}>(), {
  title: '安全审计详情',
  actionLabel: ''
})

const emit = defineEmits<{
  (event: 'update:modelValue', value: boolean): void
  (event: 'apply-filter', filter: Partial<SecurityAuditQuery>): void
  (event: 'open-resource', resource: {
    resource_type: string
    client_id?: string
    provider_id?: string
    organization_id?: string
    mapper_id?: string
  }): void
}>()

const detailRows = computed(() => {
  return Object.entries(props.entry?.details || {})
    .map(([key, value]) => ({ key, value }))
    .sort((left, right) => left.key.localeCompare(right.key))
})

const detailsJSON = computed(() => {
  return JSON.stringify(props.entry?.details || {}, null, 2)
})

const copyTargets = computed(() => {
  const details = props.entry?.details || {}
  const targets: Array<{ label: string; value: string }> = []
  const pushTarget = (label: string, value?: string) => {
    if (!value || value === '-') return
    targets.push({ label, value })
  }
  pushTarget('操作人', props.entry?.actor?.id)
  pushTarget('client_id', details.client_id)
  pushTarget('provider_id', details.provider_id)
  pushTarget('mapper_id', details.mapper_id)
  pushTarget('organization_id', details.organization_id)
  pushTarget('slug', details.slug)
  return targets
})

const filterTargets = computed(() => {
  const details = props.entry?.details || {}
  const resourceType = details.resource_type
  const targets: Array<{ label: string; filter: Partial<SecurityAuditQuery> }> = []
  const pushTarget = (label: string, filter: Partial<SecurityAuditQuery>) => {
    targets.push({ label, filter })
  }
  if (details.client_id) {
    pushTarget('筛选同 client_id', {
      resource_type: resourceType || 'oidc_client',
      client_id: details.client_id
    })
    pushTarget('筛选该 Client 失败记录', {
      resource_type: resourceType || 'oidc_client',
      client_id: details.client_id,
      success: false
    })
  }
  if (details.provider_id) {
    pushTarget('筛选同 provider_id', {
      resource_type: resourceType || 'identity_provider',
      provider_id: details.provider_id,
      organization_id: details.organization_id || undefined
    })
    pushTarget('筛选该 Provider 失败记录', {
      resource_type: resourceType || 'identity_provider',
      provider_id: details.provider_id,
      organization_id: details.organization_id || undefined,
      success: false
    })
  }
  if (details.organization_id) {
    pushTarget('筛选同 organization_id', {
      organization_id: details.organization_id
    })
  }
  if (details.mapper_id) {
    pushTarget('筛选同 Claim Mapper', {
      resource_type: resourceType || 'claim_mapper',
      query: details.mapper_id
    })
  }
  return targets
})

const resourceTargets = computed(() => {
  const details = props.entry?.details || {}
  const resourceType = details.resource_type
  const targets: Array<{
    label: string
    resource: {
      resource_type: string
      client_id?: string
      provider_id?: string
      organization_id?: string
      mapper_id?: string
    }
  }> = []
  if (resourceType === 'oidc_client' && details.client_id) {
    targets.push({
      label: '打开 OIDC Client 配置',
      resource: {
        resource_type: resourceType,
        client_id: details.client_id
      }
    })
  }
  if (resourceType === 'identity_provider' && details.provider_id && details.organization_id) {
    targets.push({
      label: '打开企业身份源配置',
      resource: {
        resource_type: resourceType,
        provider_id: details.provider_id,
        organization_id: details.organization_id
      }
    })
  }
  if (resourceType === 'claim_mapper' && details.mapper_id) {
    targets.push({
      label: '打开 Claim Mapper 配置',
      resource: {
        resource_type: resourceType,
        mapper_id: details.mapper_id
      }
    })
  }
  if (resourceType === 'organization_admin' && details.organization_id) {
    targets.push({
      label: '打开组织管理员',
      resource: {
        resource_type: resourceType,
        organization_id: details.organization_id
      }
    })
  }
  return targets
})

const formatDate = (value?: string) => {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString()
}

const copyText = async (value: string, label: string) => {
  try {
    await writeClipboard(value)
    ElMessage.success(`${label} 已复制`)
  } catch {
    ElMessage.error(`${label} 复制失败`)
  }
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
  if (!succeeded) {
    throw new Error('copy failed')
  }
}
</script>

<style scoped lang="scss">
.drawer-header {
  strong {
    display: block;
    font-size: 1rem;
    font-weight: 600;
  }

  p {
    margin: 6px 0 0;
    color: #64748b;
  }
}

.audit-detail {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.detail-section {
  h4 {
    margin: 0 0 10px;
    font-size: 0.95rem;
    font-weight: 600;
    color: #0f172a;
  }
}

.action-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.action-row-secondary {
  margin-top: 10px;
}

.raw-block {
  margin: 0;
  padding: 12px 14px;
  border-radius: 10px;
  background: #f8fafc;
  color: #0f172a;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-word;
}

.break-text {
  white-space: pre-wrap;
  word-break: break-word;
}
</style>
