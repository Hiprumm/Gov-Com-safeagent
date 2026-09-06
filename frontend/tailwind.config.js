/** @type {import('tailwindcss').Config} */

export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{js,ts,vue}"],
  theme: {
    container: {
      center: true,
    },
    extend: {
      colors: {
        // 主题感知色 — 引用 style.css 中 :root(浅色)/.dark(深色) 的 CSS 变量
        // RGB 三元组格式，支持 bg-critical/10 透明度写法
        // 注意：页面底色 key 命名 'canvas'，不能叫 'base'——
        // 否则与默认字号 scale 的 text-base 撞名，Tailwind 会同时生成
        // 「字号」与「base 颜色」两个同名工具类，导致文字颜色被污染成背景色。
        canvas: 'rgb(var(--c-base) / <alpha-value>)',
        surface: 'rgb(var(--c-surface) / <alpha-value>)',
        elevated: 'rgb(var(--c-elevated) / <alpha-value>)',
        hover: 'rgb(var(--c-hover) / <alpha-value>)',
        // 文字层级
        primary: 'rgb(var(--c-primary) / <alpha-value>)',
        secondary: 'rgb(var(--c-secondary) / <alpha-value>)',
        muted: 'rgb(var(--c-muted) / <alpha-value>)',
        disabled: 'rgb(var(--c-disabled) / <alpha-value>)',
        // 边框
        'border-default': 'rgb(var(--c-border-default) / <alpha-value>)',
        'border-hover': 'rgb(var(--c-border-hover) / <alpha-value>)',
        'border-active': 'rgb(var(--c-border-active) / <alpha-value>)',
        // 语义色
        safe: 'rgb(var(--c-safe) / <alpha-value>)',
        low: 'rgb(var(--c-low) / <alpha-value>)',
        medium: 'rgb(var(--c-medium) / <alpha-value>)',
        high: 'rgb(var(--c-high) / <alpha-value>)',
        critical: 'rgb(var(--c-critical) / <alpha-value>)',
        accent: 'rgb(var(--c-accent) / <alpha-value>)',
        accent2: 'rgb(var(--c-accent2) / <alpha-value>)',
      },
      fontFamily: {
        display: ['Noto Sans SC', 'sans-serif'],
        body: ['Noto Sans SC', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      // 阴影 — 同样走 CSS 变量，浅色/深色各自适配
      boxShadow: {
        sm: 'var(--shadow-sm)',
        md: 'var(--shadow-md)',
        lg: 'var(--shadow-lg)',
        xl: 'var(--shadow-xl)',
        // 强调光晕 — 用于聚焦/激活状态，呼应品牌色
        glow: 'var(--shadow-glow)',
      },
      keyframes: {
        'card-in': {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'list-in': {
          '0%': { opacity: '0', transform: 'translateX(-8px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        'risk-pulse': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.5' },
        },
        'toast-in': {
          '0%': { opacity: '0', transform: 'translateX(100%)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        'toast-out': {
          '0%': { opacity: '1', transform: 'translateX(0)' },
          '100%': { opacity: '0', transform: 'translateX(100%)' },
        },
      },
      animation: {
        'card-in': 'cardFadeIn 0.25s ease-out backwards',
        'list-in': 'listItemIn 0.2s ease-out backwards',
        'shimmer': 'shimmer 1.5s ease-in-out infinite',
        'risk-pulse': 'riskPulse 2s ease-in-out infinite',
        'toast-in': 'toastIn 0.25s ease-out',
        'toast-out': 'toastOut 0.2s ease-in forwards',
      },
    },
  },
  plugins: [],
};
