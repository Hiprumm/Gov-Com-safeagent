import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import path from 'path'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  test: {
    environment: 'happy-dom',
    globals: false, // 显式 import（describe/it/expect），避免隐式全局类型依赖
    include: ['src/**/*.{test,spec}.ts'],
    setupFiles: [],
  },
})
