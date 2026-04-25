/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

import { serverApi } from '@/api'
import { isAuthenticated } from '@/utils'
import { createRouter, createWebHistory, RouteRecordRaw } from 'vue-router'


const routes: Array<RouteRecordRaw> = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/Login.vue'),
    meta: { requiresAuth: false }
  },
  {
    path: '/',
    component: () => import('@/views/Layout.vue'),
    meta: { requiresAuth: true },
    children: [
      {
        path: '',
        name: 'Dashboard',
        component: () => import('@/views/Dashboard.vue'),
        meta: { title: '仪表盘' }
      },
      {
        path: 'users',
        name: 'Users',
        component: () => import('@/views/Users.vue'),
        meta: { title: '用户管理' }
      },
      {
        path: 'organizations',
        name: 'Organizations',
        component: () => import('@/views/Organizations.vue'),
        meta: { title: '组织管理' }
      },
      {
        path: 'activity',
        name: 'Activity',
        component: () => import('@/views/Activity.vue'),
        meta: { title: '活跃情况' }
      },
      {
        path: 'sessions',
        name: 'Sessions',
        component: () => import('@/views/Sessions.vue'),
        meta: { title: '我的会话' }
      },
      {
        path: 'settings',
        name: 'Settings',
        component: () => import('@/views/Settings.vue'),
        meta: { title: '系统设置' }
      }
    ]
  },
  {
    path: '/:catchAll(.*)',
    name: 'NotFound',
    component: () => import('@/views/NotFound.vue')
  }
]

const router = createRouter({
  history: createWebHistory(import.meta.env.VITE_BASE_URL),
  routes
})

// 路由守卫
router.beforeEach(async (to) => {
  const requiresAuth = to.matched.some(record => record.meta.requiresAuth !== false)
  const hasLocalSession = isAuthenticated()

  if (!requiresAuth) {
    if (to.path === '/login' && hasLocalSession) {
      try {
        await serverApi.verifySession()
        return '/'
      } catch {
        return true
      }
    }

    return true
  }

  if (!hasLocalSession) {
    return '/login'
  }

  try {
    await serverApi.verifySession()
    return true
  } catch {
    return '/login'
  }
})

export default router
