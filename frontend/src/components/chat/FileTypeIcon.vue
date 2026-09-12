<script setup lang="ts">
/**
 * 文件类型图标：根据文件扩展名 / MIME 类型渲染「文件卡片 + 类型标识」，
 * 每种类型有独立配色，用于缩略图网格中非图片文件的占位展示。
 */
import { computed } from 'vue'

const props = defineProps<{
  /** MIME 类型，如 image/png */
  type: string
  /** 文件名（含扩展名），用于优先按扩展名判定 */
  name?: string
}>()

interface TypeMeta {
  label: string
  bg: string
  text: string
}

/** 扩展名 -> 类型键 */
const EXT_KEY: Record<string, string> = {
  pdf: 'pdf',
  png: 'img', jpg: 'img', jpeg: 'img', gif: 'img', webp: 'img', svg: 'img', bmp: 'img', ico: 'img',
  doc: 'doc', docx: 'doc', wps: 'doc',
  xls: 'xls', xlsx: 'xls', csv: 'xls',
  ppt: 'ppt', pptx: 'ppt',
  zip: 'zip', rar: 'zip', '7z': 'zip', tar: 'zip', gz: 'zip',
  txt: 'txt', md: 'txt', log: 'txt',
  js: 'code', ts: 'code', tsx: 'code', jsx: 'code', py: 'code', java: 'code', c: 'code', cpp: 'code', h: 'code',
  go: 'code', rs: 'code', html: 'code', htm: 'code', css: 'code', json: 'code', xml: 'code', yaml: 'code', yml: 'code', sh: 'code', vue: 'code',
  mp3: 'audio', wav: 'audio', flac: 'audio', aac: 'audio', ogg: 'audio', m4a: 'audio',
  mp4: 'video', avi: 'video', mkv: 'video', mov: 'video', webm: 'video', flv: 'video',
}

/** MIME 前缀/精确串 -> 类型键 */
const MIME_KEY: Record<string, string> = {
  'image/': 'img',
  'application/pdf': 'pdf',
  'application/msword': 'doc',
  'application/vnd.openxmlformats-officedocument.wordprocessingml': 'doc',
  'application/vnd.ms-excel': 'xls',
  'application/vnd.openxmlformats-officedocument.spreadsheetml': 'xls',
  'application/vnd.ms-powerpoint': 'ppt',
  'application/vnd.openxmlformats-officedocument.presentationml': 'ppt',
  'application/zip': 'zip',
  'application/x-zip-compressed': 'zip',
  'application/x-rar-compressed': 'zip',
  'application/x-7z-compressed': 'zip',
  'application/gzip': 'zip',
  'text/': 'txt',
  'application/json': 'code',
  'application/xml': 'code',
  'text/javascript': 'code',
  'audio/': 'audio',
  'video/': 'video',
}

const META: Record<string, TypeMeta> = {
  img:   { label: 'IMG', bg: 'bg-low/15', text: 'text-low' },
  pdf:   { label: 'PDF', bg: 'bg-critical/15', text: 'text-critical' },
  doc:   { label: 'DOC', bg: 'bg-accent/15', text: 'text-accent' },
  xls:   { label: 'XLS', bg: 'bg-safe/15', text: 'text-safe' },
  ppt:   { label: 'PPT', bg: 'bg-medium/15', text: 'text-medium' },
  zip:   { label: 'ZIP', bg: 'bg-high/15', text: 'text-high' },
  txt:   { label: 'TXT', bg: 'bg-elevated', text: 'text-secondary' },
  code:  { label: '</>', bg: 'bg-elevated', text: 'text-muted' },
  audio: { label: 'MP3', bg: 'bg-low/10', text: 'text-low' },
  video: { label: 'MP4', bg: 'bg-high/15', text: 'text-high' },
  file:  { label: 'FILE', bg: 'bg-elevated', text: 'text-muted' },
}

const meta = computed<TypeMeta>(() => {
  const mime = (props.type || '').toLowerCase()
  const ext = ((props.name || '').split('.').pop() || '').toLowerCase()
  const key = (ext && EXT_KEY[ext]) || MIME_KEY[mime] || (mime && MIME_KEY[`${mime.split('/')[0]}/`]) || 'file'
  return META[key] || META.file
})
</script>

<template>
  <div class="relative w-12 h-12 rounded-lg flex items-center justify-center" :class="meta.bg">
    <svg viewBox="0 0 24 24" class="w-9 h-9" :class="meta.text" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <path d="M14 2v6h6" />
    </svg>
    <span class="absolute inset-0 flex items-center justify-center text-[9px] font-bold tracking-wide select-none" :class="meta.text">{{ meta.label }}</span>
  </div>
</template>
