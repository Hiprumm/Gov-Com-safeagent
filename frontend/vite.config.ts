import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'
import Inspector from 'unplugin-vue-dev-locator/vite'

export default defineConfig({
  build: {
    sourcemap: 'hidden',
    target: 'es2020', // 现代浏览器，启用更小的产物
    cssCodeSplit: true, // CSS 代码分割
    chunkSizeWarningLimit: 700, // echarts 核心体积较大，调整阈值
    minify: 'esbuild', // esbuild 压缩（比 terser 快）
    reportCompressedSize: false, // 跳过 gzip 报告加速构建
    rollupOptions: {
      output: {
        // 手动分包 — 将大依赖拆分为独立 chunk，提升首屏加载速度
        manualChunks: {
          // Vue 核心
          'vue-vendor': ['vue', 'vue-router'],
          // 图表库（体积大，独立分包，按需加载）
          'echarts-vendor': ['echarts', 'vue-echarts'],
          // 图标库
          'icons-vendor': ['lucide-vue-next'],
        },
        // chunk 文件名带 hash，便于长期缓存
        chunkFileNames: 'assets/js/[name]-[hash].js',
        entryFileNames: 'assets/js/[name]-[hash].js',
        assetFileNames: 'assets/[ext]/[name]-[hash].[ext]',
      },
    },
  },
  plugins: [
    vue(),
    Inspector(),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8083',
        changeOrigin: true,
      },
      '/ai': {
        target: 'http://localhost:8083',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/ai/, '/api'),
      },
      // WebSocket 代理 — 将 /ws/* 转发到后端，避免前端直连后端端口
      '/ws': {
        target: 'ws://localhost:8083',
        ws: true,
        changeOrigin: true,
      },
    },
  },
})
