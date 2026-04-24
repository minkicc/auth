/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

import { serverApi } from '@/api/serverApi'
import { createRouter, createWebHistory } from 'vue-router'

const applyRouteAuthData = (query: Record<string, unknown>) => {
  const client_id = typeof query.client_id === 'string' ? query.client_id : ''
  const redirect_uri = typeof query.redirect_uri === 'string'
    ? query.redirect_uri
    : typeof query.redirect_url === 'string'
      ? query.redirect_url
      : undefined
  const login_hint = typeof query.login_hint === 'string' ? query.login_hint : undefined
  const domain_hint = typeof query.domain_hint === 'string' ? query.domain_hint : undefined
  const org_hint = typeof query.org_hint === 'string' ? query.org_hint : undefined
  serverApi.updateAuthData(client_id, redirect_uri, login_hint, domain_hint, org_hint)
}

const routes = [
  {
    path: '/',
    redirect: '/profile',
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/Login.vue'),
    beforeEnter: (to) => {
      applyRouteAuthData(to.query)
    }
  },
  {
    path: '/select-organization',
    name: 'OrganizationSelect',
    component: () => import('../views/OrganizationSelect.vue'),
    beforeEnter: (to) => {
      applyRouteAuthData(to.query)
    }
  },
  {
    path: '/profile',
    name: 'Profile',
    component: () => import('../views/Profile.vue'),
  },
  {
    path: '/verify-email',
    name: 'EmailVerify',
    component: () => import('../components/auth/EmailVerify.vue'),
    beforeEnter: (to) => {
      applyRouteAuthData(to.query)
    }
  },
  {
    path: '/wechat/callback',
    name: 'WeixinCallback',
    component: () => import('../components/auth/WeixinCallback.vue'),
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: () => import('../views/NotFound.vue'),
    beforeEnter: () => {
      window.location.href = `/`; // 跳转到后端路由
    }
  }
]

const router = createRouter({
  history: createWebHistory(import.meta.env.VITE_BASE_URL),
  routes
})

export default router
