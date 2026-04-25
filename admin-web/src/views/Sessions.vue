/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

<template>
  <div class="sessions-container">
    <el-card class="sessions-card">
      <template #header>
        <div class="card-header">
          <div>
            <h2>{{ $t('sessions.title') }}</h2>
            <p class="subhead">查看当前管理员账号在主站里的标准会话。这里管理的是平台登录会话，不是后台本身的 UI 会话壳。</p>
          </div>
          <div class="table-actions">
            <el-button :loading="loading" @click="loadSessions">{{ $t('common.refresh') }}</el-button>
            <el-button type="danger" :loading="terminatingAll" @click="terminateAllSessions">
              {{ $t('sessions.revoke_all') }}
            </el-button>
          </div>
        </div>
      </template>

      <el-alert
        v-if="error"
        class="sessions-alert"
        :title="error"
        type="warning"
        :closable="false"
        show-icon
      />

      <el-table
        v-loading="loading"
        :data="sessions"
        row-key="id"
        empty-text="暂无主站会话"
      >
        <el-table-column prop="id" label="Session ID" min-width="240" />
        <el-table-column prop="ip" :label="$t('sessions.ip_address')" width="150" />
        <el-table-column :label="$t('sessions.device')" min-width="260">
          <template #default="{ row }">
            <div class="user-agent-cell">{{ row.user_agent || '-' }}</div>
          </template>
        </el-table-column>
        <el-table-column :label="$t('sessions.start_time')" width="180">
          <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column :label="$t('sessions.expire_time')" width="180">
          <template #default="{ row }">{{ formatDateTime(row.expires_at) }}</template>
        </el-table-column>
        <el-table-column :label="$t('common.actions')" width="120" align="right">
          <template #default="{ row }">
            <el-button
              text
              type="danger"
              :loading="terminatingSessionId === row.id"
              @click="terminateSession(row.id)"
            >
              {{ $t('sessions.revoke') }}
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index'
import { ElMessageBox } from 'element-plus/es/components/message-box/index'
import { context } from '@/context'
import { type SessionData, serverApi } from '@/api'

const loading = ref(false)
const terminatingAll = ref(false)
const terminatingSessionId = ref('')
const error = ref('')
const sessions = ref<SessionData[]>([])

const loadSessions = async () => {
  if (!context.userId) {
    sessions.value = []
    return
  }
  loading.value = true
  try {
    const response = await serverApi.getUserSessions(context.userId)
    sessions.value = response.sessions || []
    error.value = ''
  } catch (err: any) {
    sessions.value = []
    error.value = err?.response?.data?.error || '加载主站会话失败'
  } finally {
    loading.value = false
  }
}

const terminateSession = async (sessionId: string) => {
  try {
    await ElMessageBox.confirm('确定要撤销这个主站会话吗？', '提示', {
      confirmButtonText: '撤销',
      cancelButtonText: '取消',
      type: 'warning'
    })
  } catch {
    return
  }

  terminatingSessionId.value = sessionId
  try {
    const response = await serverApi.terminateUserSession(context.userId, sessionId)
    sessions.value = sessions.value.filter(session => session.id !== sessionId)
    ElMessage.success(response.message || '会话已撤销')
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error || '撤销会话失败')
  } finally {
    terminatingSessionId.value = ''
  }
}

const terminateAllSessions = async () => {
  try {
    await ElMessageBox.confirm('确定要撤销当前账号的所有主站会话吗？', '提示', {
      confirmButtonText: '全部撤销',
      cancelButtonText: '取消',
      type: 'warning'
    })
  } catch {
    return
  }

  terminatingAll.value = true
  try {
    const response = await serverApi.terminateAllUserSessions(context.userId)
    sessions.value = []
    ElMessage.success(response.message || '所有会话已撤销')
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error || '撤销所有会话失败')
  } finally {
    terminatingAll.value = false
  }
}

const formatDateTime = (value?: string) => {
  if (!value) return '-'
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toLocaleString()
}

onMounted(() => {
  loadSessions()
})
</script>

<style lang="scss" scoped>
.sessions-card {
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
}

.sessions-alert {
  margin-bottom: 18px;
}

.user-agent-cell {
  color: #374151;
  word-break: break-word;
  line-height: 1.5;
}
</style>
