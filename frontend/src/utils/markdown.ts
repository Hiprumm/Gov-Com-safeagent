import MarkdownIt from 'markdown-it'

// 关闭 HTML 解析（防 XSS），开启链接自动识别与换行；表格为 markdown-it 默认能力
const md = new MarkdownIt({
  html: false,
  linkify: true,
  breaks: true,
})

/**
 * 将 Markdown 文本渲染为安全 HTML（表格/标题/列表/粗体等）。
 * 用于会话中 AI 生成的结构化报表等内容。
 */
export function renderMarkdown(text: string): string {
  if (!text) return ''
  try {
    return md.render(text)
  } catch {
    // 渲染失败时回退为纯文本转义
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  }
}
