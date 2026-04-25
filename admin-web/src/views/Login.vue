/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

<template>
  <div class="login-container">
    <el-card class="login-card">
      <template #header>
        <div class="login-header">
          <img src="/minki-logo.svg" alt="minki-auth logo" class="brand-logo" />
          <div class="brand-copy">
            <h2>minki-auth admin</h2>
            <p>{{ $t('auth.welcome') }}</p>
          </div>
        </div>
      </template>

      <div class="login-copy">
        <h3>{{ $t('auth.adminAccessTitle') }}</h3>
        <p>{{ $t('auth.adminAccessDescription') }}</p>
      </div>

      <el-alert
        v-if="errorMessage"
        :title="errorMessage"
        type="warning"
        show-icon
        :closable="false"
        class="login-alert"
      />

      <div class="login-actions">
        <el-button
          type="primary"
          :loading="bootstrapping"
          style="width: 100%"
          @click="bootstrapSession"
        >
          {{ bootstrapping ? $t('auth.login_loading') : $t('auth.continueWithCurrentAccount') }}
        </el-button>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { serverApi } from '@/api'
import { isAuthenticated } from '@/utils'

const router = useRouter()
const bootstrapping = ref(false)
const errorMessage = ref('')

const bootstrapSession = async () => {
  try {
    bootstrapping.value = true
    errorMessage.value = ''
    await serverApi.bootstrapSession()
    await router.replace('/')
  } catch (error: any) {
    errorMessage.value = error?.response?.data?.error || 'Failed to continue with the current account'
    localStorage.removeItem('admin_session')
  } finally {
    bootstrapping.value = false
  }
}

onMounted(async () => {
  if (isAuthenticated()) {
    try {
      await serverApi.verifySession()
      await router.replace('/')
      return
    } catch {
      localStorage.removeItem('admin_session')
    }
  }

  await bootstrapSession()
})
</script>

<style lang="scss" scoped>
.login-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background:
    radial-gradient(circle at top left, rgba(17, 63, 84, 0.12), transparent 35%),
    linear-gradient(180deg, #f5f7fa 0%, #eef3f6 100%);
  padding: 24px;
}

.login-card {
  width: 440px;
  max-width: 100%;

  .login-header {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 14px;

    h2 {
      margin: 0;
      font-size: 1.5rem;
      color: #113F54;
    }

    p {
      margin: 4px 0 0;
      color: #607482;
      font-size: 0.95rem;
    }

    .brand-logo {
      width: 42px;
      height: 42px;
      border-radius: 12px;
      box-shadow: 0 10px 24px rgba(17, 63, 84, 0.18);
      flex-shrink: 0;
    }

    .brand-copy {
      text-align: left;
    }
  }
}

.login-copy {
  margin-bottom: 18px;

  h3 {
    margin: 0 0 10px;
    color: #113F54;
    font-size: 1.2rem;
  }

  p {
    margin: 0;
    color: #607482;
    line-height: 1.6;
  }
}

.login-alert {
  margin-bottom: 18px;
}

.login-actions {
  display: flex;
  gap: 12px;
}
</style>
