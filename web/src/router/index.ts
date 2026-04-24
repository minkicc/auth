/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

import { serverApi } from '@/api/serverApi'
import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    redirect: '/profile',
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/Login.vue'),
    // 记录client_id和redirect_uri
    beforeEnter: (to) => {
      const client_id = typeof to.query.client_id === 'string' ? to.query.client_id : ''
      const redirect_uri = typeof to.query.redirect_uri === 'string'
        ? to.query.redirect_uri
        : typeof to.query.redirect_url === 'string'
          ? to.query.redirect_url
          : undefined
      const login_hint = typeof to.query.login_hint === 'string' ? to.query.login_hint : undefined
      const domain_hint = typeof to.query.domain_hint === 'string' ? to.query.domain_hint : undefined
      serverApi.updateAuthData(client_id, redirect_uri, login_hint, domain_hint)
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
      const client_id = typeof to.query.client_id === 'string' ? to.query.client_id : ''
      const redirect_uri = typeof to.query.redirect_uri === 'string'
        ? to.query.redirect_uri
        : typeof to.query.redirect_url === 'string'
          ? to.query.redirect_url
          : undefined
      const login_hint = typeof to.query.login_hint === 'string' ? to.query.login_hint : undefined
      const domain_hint = typeof to.query.domain_hint === 'string' ? to.query.domain_hint : undefined
      serverApi.updateAuthData(client_id, redirect_uri, login_hint, domain_hint)
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
