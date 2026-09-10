import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'

// 路由懒加载 — 首屏只加载LoginPage/HomePage，EvaluationPage按需加载
// 显式 RouteRecordRaw[] 注解：redirect-only 兜底路由与 component 路由联合推断会 TS 报错
const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/pages/LoginPage.vue'),
    // 登录/登出等过渡期间临时停留的元信息，避免重复跳转循环
    meta: { public: true },
  },
  {
    path: '/',
    name: 'home',
    component: () => import('@/pages/HomePage.vue'),
  },
  {
    path: '/evaluation',
    name: 'evaluation',
    component: () => import('@/pages/EvaluationPage.vue'),
  },
  {
    path: '/admin/users',
    name: 'admin-users',
    component: () => import('@/pages/AdminUsers.vue'),
    // 后端 API 强校验 admin；此处仅登录门禁，页面内再校验 role===admin
  },
  // 兜底：未知路径重定向首页（避免演示时输错 URL 出空白页）
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

// 创建路由实例
const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior() {
    return { top: 0 }
  },
})

/**
 * 强制登录守卫：未登录无法访问任何业务功能，一律重定向到登录页。
 * 判据取 localStorage token（同步可靠）；token 的真实有效性由各页 initAuth 经
 * /api/auth/me 校验，失效会自动清理并兜底回到登录页。
 */
router.beforeEach((to) => {
  const authed = !!localStorage.getItem('auth_token')
  if (!to.meta.public && !authed) {
    // 记录来源，登录后若需可跳回（当前统一回首页）
    return { path: '/login', query: to.path !== '/' ? { redirect: to.fullPath } : {} }
  }
  if (to.meta.public && authed) {
    return { path: '/' }
  }
  return true
})

export default router
