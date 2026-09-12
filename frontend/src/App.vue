<template>
  <router-view v-slot="{ Component }">
    <!-- 修复：mode="out-in" 在懒加载路由组件切换（如 /admin/users → /）时 enter 阶段
         不挂载组件导致空白页；改为默认 mode（enter/leave 并发）不再等待 leave 完成 -->
    <transition name="fade">
      <component :is="Component" />
    </transition>
  </router-view>
  <ToastContainer />
</template>

<script setup lang="ts">
import ToastContainer from '@/components/ToastContainer.vue'
</script>
