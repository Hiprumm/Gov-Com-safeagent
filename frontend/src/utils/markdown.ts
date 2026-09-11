import MarkdownIt from 'markdown-it'

// 关闭 HTML 解析（防 XSS），开启链接自动识别与换行；表格为 markdown-it 默认能力
const md = new MarkdownIt({
  html: false,
  linkify: true,
  breaks: true,
})

/**
 * 将 Markdown 文本渲染为安全 HTML（表格/标题/列表/粗体等）。
 * 代码块自动包裹标题栏（语言标签 + 复制按钮），样式见 style.css 的 .md-code-*。
 */
export function renderMarkdown(text: string): string {
  if (!text) return ''
  try {
    let html = md.render(text)
    // 代码块增强：外层包 .md-code-wrap + 标题栏（带语言标签与复制按钮，复制通过事件委托处理）
    html = html.replace(
      /<pre><code(\s+class="language-([^"]+)")?>/g,
      (_m, cls: string, lang?: string) =>
        `<div class="md-code-wrap"><div class="md-code-bar"><span class="md-code-lang">${lang || 'code'}</span><button type="button" class="md-code-copy">复制</button></div><pre><code${cls || ''}>`,
    )
    html = html.replace(/<\/code><\/pre>/g, '</code></pre></div>')
    // 表格增强：外层包 .md-table-wrap（圆角/裁剪交给 div，跨浏览器兼容，
    // 避免 border-radius+overflow 直接作用于 <table> 在部分浏览器失效）
    html = html.replace(/<table>/g, '<div class="md-table-wrap"><table>')
    html = html.replace(/<\/table>/g, '</table></div>')
    return html
  } catch {
    // 渲染失败时回退为纯文本转义
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  }
}
