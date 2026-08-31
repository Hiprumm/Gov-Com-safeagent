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
        // 背景层级
        base: '#0B1120',
        surface: '#111827',
        elevated: '#1E293B',
        hover: '#334155',
        // 文字层级
        primary: '#E2E8F0',
        secondary: '#94A3B8',
        muted: '#64748B',
        disabled: '#475569',
        // 边框
        'border-default': '#1E293B',
        'border-hover': '#334155',
        'border-active': '#06B6D4',
        // 语义色
        safe: '#10B981',
        low: '#3B82F6',
        medium: '#F59E0B',
        high: '#F97316',
        critical: '#EF4444',
        accent: '#06B6D4',
        accent2: '#8B5CF6',
      },
      fontFamily: {
        display: ['Noto Sans SC', 'sans-serif'],
        body: ['Noto Sans SC', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      // 深色主题阴影 — 使用低透明度黑，多层叠加增加层次感
      boxShadow: {
        sm: '0 1px 2px 0 rgba(0, 0, 0, 0.3)',
        md: '0 4px 6px -1px rgba(0, 0, 0, 0.4), 0 2px 4px -2px rgba(0, 0, 0, 0.3)',
        lg: '0 10px 15px -3px rgba(0, 0, 0, 0.5), 0 4px 6px -4px rgba(0, 0, 0, 0.3)',
        xl: '0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.3)',
        // 强调光晕 — 用于聚焦/激活状态，呼应品牌色
        glow: '0 0 0 1px rgba(6, 182, 212, 0.35), 0 0 20px rgba(6, 182, 212, 0.18)',
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
