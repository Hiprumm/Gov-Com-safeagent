import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'

// 路由懒加载 — 首屏只加载HomePage，EvaluationPage按需加载
// 显式 RouteRecordRaw[] 注解：redirect-only 兜底路由与 component 路由联合推断会 TS 报错
const routes: RouteRecordRaw[] = [
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

export default router
