/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

<template>
  <div class="app-layout">
    <el-container class="layout-container">
      <!-- 顶部导航 -->
      <el-header height="60px" class="header">
        <div class="logo">
          <img src="/minki-logo.svg" alt="minki-auth logo" class="brand-logo" />
          <div class="brand-copy">
            <h1>minki-auth</h1>
            <span>admin</span>
          </div>
        </div>
        <div class="user-info">
          <language-switcher class="language-switcher" />
          <span>{{ context.username }}</span>
          <el-dropdown trigger="click" @command="handleCommand">
            <el-avatar size="small" :icon="UserFilled" />
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="sessions">{{ $t('common.mySessions') }}</el-dropdown-item>
                <el-dropdown-item command="logout">{{ $t('common.logout') }}</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>
      
      <el-container>
        <!-- 侧边栏导航 -->
        <el-aside width="200px" class="aside">
          <el-menu
            :default-active="activeMenu"
            router
            class="el-menu-vertical"
            background-color="#001529"
            text-color="#909399"
            active-text-color="#409EFF"
          >
            <el-menu-item index="/">
              <el-icon><House /></el-icon>
              <span>{{ $t('layout.menu.dashboard') }}</span>
            </el-menu-item>
            <el-menu-item index="/users">
              <el-icon><User /></el-icon>
              <span>{{ $t('layout.menu.users') }}</span>
            </el-menu-item>
            <el-menu-item index="/activity">
              <el-icon><DataLine /></el-icon>
              <span>{{ $t('layout.menu.activity') }}</span>
            </el-menu-item>
            <el-menu-item index="/settings">
              <el-icon><Setting /></el-icon>
              <span>{{ $t('layout.menu.settings') }}</span>
            </el-menu-item>
          </el-menu>
        </el-aside>
        
        <!-- 主内容区 -->
        <el-main class="main">
          <el-breadcrumb separator="/" class="breadcrumb">
            <el-breadcrumb-item :to="{ path: '/' }">首页</el-breadcrumb-item>
            <el-breadcrumb-item>{{ currentPageTitle }}</el-breadcrumb-item>
          </el-breadcrumb>
          
          <router-view v-slot="{ Component }">
            <transition name="fade" mode="out-in">
              <component :is="Component" />
            </transition>
          </router-view>
        </el-main>
      </el-container>
    </el-container>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { DataLine, House, Setting, User, UserFilled } from '@element-plus/icons-vue'
import { context } from '@/context'
import { ElMessage } from 'element-plus/es/components/message/index'
import { ElMessageBox } from 'element-plus/es/components/message-box/index'
import LanguageSwitcher from '@/components/LanguageSwitcher.vue'
import { serverApi } from '@/api'


const route = useRoute()
const router = useRouter()

// 计算当前活动菜单
const activeMenu = computed(() => {
  return route.path
})

// 计算当前页面标题
const currentPageTitle = computed(() => {
  return route.meta.title || '未知页面'
})

// 处理下拉菜单命令
const handleCommand = (command: string) => {
  if (command === 'logout') {
    ElMessageBox.confirm(
      '确定要退出登录吗？',
      '提示',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    ).then(() => {
      serverApi.logout()
      ElMessage({
        type: 'success',
        message: '已成功退出登录'
      })
      localStorage.removeItem('admin_session')
      router.push('/login')
    }).catch(() => {})
  } else if (command === 'sessions') {
    router.push('/sessions')
  }
}


</script>

<style lang="scss" scoped>
.app-layout {
  height: 100%;
  
  .layout-container {
    height: 100%;
  }
  
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background-color: #fff;
    box-shadow: 0 1px 4px rgba(0, 21, 41, 0.08);
    z-index: 10;
    
    .logo {
      display: flex;
      align-items: center;
      gap: 12px;

      .brand-logo {
        width: 34px;
        height: 34px;
        border-radius: 10px;
        box-shadow: 0 8px 18px rgba(17, 63, 84, 0.16);
        flex-shrink: 0;
      }

      .brand-copy {
        display: flex;
        align-items: baseline;
        gap: 8px;
      }

      h1 {
        margin: 0;
        font-size: 1.25rem;
        color: #001529;
      }

      span {
        color: #607482;
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.08em;
      }
    }
    
    .user-info {
      display: flex;
      align-items: center;
      gap: 15px;
      
      .language-switcher {
        margin-right: 10px;
      }
      
      span {
        margin-right: 10px;
        color: #fff;
      }
    }
  }
  
  .aside {
    background-color: #001529;
    overflow-x: hidden;
    
    .el-menu-vertical {
      border-right: none;
    }
  }
  
  .main {
    background-color: #f0f2f5;
    height: calc(100vh - 60px);
    overflow-y: auto;
    
    .breadcrumb {
      margin-bottom: 16px;
    }
  }
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
