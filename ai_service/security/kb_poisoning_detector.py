"""
知识库投毒检测器 (Knowledge Base Poisoning Detector)

检测针对RAG系统的知识库投毒攻击，重点关注：
1. PDF白色/透明字体隐藏指令
2. 极小字体/不可见文本
3. 同色文字（文字与背景同色）
4. RAG特定的提示注入模式
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import base64
import io
import re
from typing import Tuple, List, Dict, Any, Optional
from dataclasses import dataclass, field
from models.schemas import RiskLevel, AttackType


@dataclass
class HiddenTextInfo:
    """隐藏文本信息"""
    text: str
    location: str  # 位置描述
    font_size: Optional[float] = None
    font_color: Optional[str] = None
    detection_method: str = ""  # 检测方法


@dataclass
class KBPoisoningResult:
    """知识库投毒检测结果"""
    risk_level: RiskLevel = RiskLevel.NONE
    attack_type: Optional[AttackType] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    hidden_texts: List[HiddenTextInfo] = field(default_factory=list)
    total_hidden_chars: int = 0
    total_visible_chars: int = 0
    file_name: str = ""
    summary: str = ""


# RAG投毒攻击模式 —— 针对LLM指令覆盖
RAG_POISONING_PATTERNS = [
    # 英文模式
    (r"(?i)ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|directives?|context)", 0.35, "忽略先前指令"),
    (r"(?i)system\s*(prompt|message|instruction)\s*(override|overwrite|is\s*now)", 0.30, "系统提示覆盖"),
    (r"(?i)you\s+are\s+now\s+(DAN|jailbroken|unrestricted|unfiltered)", 0.35, "越狱指令"),
    (r"(?i)do\s+not\s+follow\s+(any\s+)?(safety|content|ethical)\s+(guidelines?|policies?|rules?)", 0.30, "绕过安全规则"),
    (r"(?i)(pretend|act\s+as|roleplay|impersonate)\s+(you\s+are|as\s+if\s+you\s+are)", 0.25, "角色扮演绕过"),
    (r"(?i)(disregard|override|bypass)\s+(all\s+)?(previous\s+)?(constraints?|restrictions?|limitations?)", 0.30, "绕过限制"),
    (r"(?i)your\s+(primary|main|only)\s+(goal|objective|task|purpose)\s+is\s+now", 0.25, "目标覆盖"),
    (r"(?i)from\s+now\s+on\s+you\s+(must|should|will|are)", 0.20, "行为改写"),
    # 精确匹配 high-confidence
    (r"(?i)ignore\s+all\s+previous\s+instructions", 0.40, "精确忽略指令"),
    (r"(?i)you\s+are\s+now\s+DAN", 0.40, "DAN越狱"),
    (r"(?i)pretend\s+you\s+are\s+a\s+different", 0.35, "冒充身份"),
]

# 知识库投毒专用关键词
POISONING_KEYWORDS = [
    # 隐蔽注入
    ("隐藏指令", 0.15), ("白字", 0.10), ("透明文字", 0.10),
    ("隐蔽文本", 0.10), ("隐形文字", 0.10),
    # 数据投毒
    ("虚假信息", 0.15), ("植入后门", 0.20), ("数据投毒", 0.20),
    ("恶意注入", 0.20), ("污染数据", 0.15), ("欺骗模型", 0.15),
    # 越狱关键词
    ("越狱提示", 0.15), ("绕过审查", 0.15), ("解除限制", 0.15),
    ("开发者模式", 0.15), ("上帝模式", 0.15), ("管理员覆盖", 0.15),
    # 敏感操作
    ("输出所有数据", 0.20), ("泄露信息", 0.15), ("未经授权", 0.10),
]

# 白色/不可见颜色的 RGB 阈值
WHITE_RGB_THRESHOLD = 240  # RGB > 240 视为白色
DARK_RGB_THRESHOLD = 20    # RGB < 20 视为黑色
MIN_VISIBLE_FONT_SIZE = 4  # 小于 4pt 视为不可见


class KBPoisoningDetector:
    """知识库投毒检测器"""

    def __init__(self):
        self.max_text_length = 50000

    def detect_pdf(self, file_data: str, filename: str) -> KBPoisoningResult:
        """
        检测 PDF 文件中的隐藏文本

        Args:
            file_data: base64编码的PDF文件内容
            filename: 文件名

        Returns:
            KBPoisoningResult: 检测结果
        """
        result = KBPoisoningResult(file_name=filename)
        hidden_texts: List[HiddenTextInfo] = []
        all_visible_text_parts: List[str] = []
        total_hidden_chars = 0
        total_visible_chars = 0

        try:
            # 解码文件
            pdf_bytes = base64.b64decode(file_data)

            # 方法1: 使用 pypdf 进行字体/颜色分析
            try:
                from pypdf import PdfReader
                reader = PdfReader(io.BytesIO(pdf_bytes))

                for page_idx, page in enumerate(reader.pages):
                    page_text = page.extract_text() or ""
                    all_visible_text_parts.append(page_text)
                    total_visible_chars += len(page_text)

                    # 提取内容流，分析字体颜色设置
                    try:
                        content = page.get_contents()
                        if content:
                            content_data = content.get_data() if hasattr(content, 'get_data') else (
                                content if isinstance(content, (str, bytes)) else b""
                            )
                            if isinstance(content_data, bytes):
                                content_str = content_data.decode('latin-1', errors='ignore')
                                hidden_from_content = self._analyze_content_stream(
                                    content_str, page_idx, hidden_texts
                                )
                    except Exception:
                        pass

            except ImportError:
                result.evidence.append("pypdf 库不可用，跳过PDF字体分析")
            except Exception as e:
                result.evidence.append(f"PDF解析异常: {str(e)}")

            # 方法2: 使用 pdfplumber 进行更精确的文本提取和分析
            try:
                import pdfplumber
                with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
                    for page_idx, page in enumerate(pdf.pages):
                        # 提取带位置信息的字符
                        chars = page.chars
                        if not chars:
                            continue

                        # 分析每个字符
                        hidden_chars_on_page = []
                        visible_chars_on_page = []

                        for char in chars:
                            font_size = char.get('size', 10)
                            text = char.get('text', '')

                            if not text.strip():
                                continue

                            # 检查极小字体（< 4pt 为不可见）
                            if font_size is not None and font_size < MIN_VISIBLE_FONT_SIZE:
                                hidden_chars_on_page.append(text)
                                continue

                            # 检查字体颜色（提取 nonstroking 颜色）
                            color = self._extract_char_color(char)
                            if color and self._is_invisible_color(color):
                                hidden_chars_on_page.append(text)
                                continue

                            # 检查字符是否在页面可见区域外
                            x0 = char.get('x0', 0)
                            top = char.get('top', 0)
                            page_height = page.height
                            page_width = page.width

                            if x0 < 0 or top < 0 or x0 > page_width or top > page_height:
                                hidden_chars_on_page.append(text)
                                continue

                            visible_chars_on_page.append(text)

                        if hidden_chars_on_page:
                            hidden_text = ''.join(hidden_chars_on_page)
                            total_hidden_chars += len(hidden_text)
                            hidden_texts.append(HiddenTextInfo(
                                text=hidden_text[:500],  # 截断显示
                                location=f"第{page_idx + 1}页",
                                detection_method="pdfplumber 字符分析",
                            ))

                        total_visible_chars += len(''.join(visible_chars_on_page))

            except ImportError:
                result.evidence.append("pdfplumber 库不可用，跳过高级字符分析")
            except Exception as e:
                result.evidence.append(f"pdfplumber 分析异常: {str(e)}")

            # 方法3: 原始字节分析 —— 检测嵌入的隐藏文本
            try:
                raw_text = pdf_bytes.decode('latin-1', errors='ignore')
                byte_hidden = self._analyze_raw_bytes(raw_text, hidden_texts)
                if byte_hidden:
                    total_hidden_chars += sum(len(h.text) for h in byte_hidden)
            except Exception:
                pass

        except Exception as e:
            result.evidence.append(f"文件解析失败: {str(e)}")
            result.risk_level = RiskLevel.NONE
            return result

        # 从所有可见文本中拼接，用于 RAG 投毒模式检测
        visible_text = ' '.join(all_visible_text_parts)

        # 阶段2: RAG 投毒模式检测（对所有提取到的文本，包括隐藏文本）
        all_text_for_pattern = visible_text
        for ht in hidden_texts:
            all_text_for_pattern += " " + ht.text

        pattern_risk, pattern_conf, pattern_evidence = self._detect_rag_poisoning_patterns(
            all_text_for_pattern
        )

        # 阶段3: 综合评估
        total_text_chars = total_visible_chars + total_hidden_chars
        hidden_ratio = total_hidden_chars / max(total_text_chars, 1)

        # 构建证据
        if hidden_texts:
            hidden_snippets = []
            for ht in hidden_texts[:5]:  # 最多5条
                preview = ht.text[:100].replace('\n', ' ')
                hidden_snippets.append(f"[{ht.location}] {preview}")
            evidence_msg = f"检测到 {len(hidden_texts)} 处隐藏/不可见文本 ({total_hidden_chars} 字符): {'; '.join(hidden_snippets[:3])}"
            result.evidence.append(evidence_msg)

        result.evidence.extend(pattern_evidence)

        # 隐藏文本置信度
        hidden_confidence = 0.0
        if total_hidden_chars > 500:
            hidden_confidence = 0.85
        elif total_hidden_chars > 100:
            hidden_confidence = 0.65
        elif total_hidden_chars > 20:
            hidden_confidence = 0.45
        elif total_hidden_chars > 5:
            hidden_confidence = 0.25

        # 如果隐藏比例异常高
        if total_text_chars > 100 and hidden_ratio > 0.3:
            hidden_confidence = max(hidden_confidence, 0.80)
            result.evidence.append(f"隐藏文本占比异常: {hidden_ratio:.1%} ({total_hidden_chars}/{total_text_chars} 字符)")

        # 综合置信度：取隐藏文本检测和模式检测的最大值
        total_confidence = max(hidden_confidence, pattern_conf)

        # 如果同时存在隐藏文本和投毒模式，置信度叠加
        if hidden_texts and pattern_conf > 0.2:
            total_confidence = min(0.98, hidden_confidence * 0.6 + pattern_conf * 0.6)

        # 判定风险等级
        if total_confidence >= 0.85:
            result.risk_level = RiskLevel.CRITICAL
        elif total_confidence >= 0.60:
            result.risk_level = RiskLevel.HIGH
        elif total_confidence >= 0.30:
            result.risk_level = RiskLevel.MEDIUM
        elif total_confidence > 0:
            result.risk_level = RiskLevel.LOW
        else:
            result.risk_level = RiskLevel.NONE

        result.attack_type = AttackType.DATA_POISONING if total_confidence > 0 else None

        # 如果有隐藏文本 + 模式，可能是 STEGANOGRAPHY
        if hidden_texts and pattern_conf > 0.3:
            result.attack_type = AttackType.STEGANOGRAPHY

        result.confidence = round(total_confidence, 2)
        result.hidden_texts = hidden_texts
        result.total_hidden_chars = total_hidden_chars
        result.total_visible_chars = total_visible_chars

        # 生成摘要
        if result.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            result.summary = (
                f"⚠️ {result.risk_level.value.upper()} 风险！检测到知识库投毒行为。"
                f"发现 {len(hidden_texts)} 处隐藏文本（{total_hidden_chars} 字符），"
                f"置信度 {total_confidence:.0%}。"
                f"{'同时检测到RAG投毒模式。' if pattern_conf > 0.2 else ''}"
            )
        elif result.risk_level == RiskLevel.MEDIUM:
            result.summary = (
                f"中风险：检测到可疑知识库投毒迹象。"
                f"发现 {len(hidden_texts)} 处隐藏文本（{total_hidden_chars} 字符）。"
                f"建议人工复核。"
            )
        elif result.risk_level == RiskLevel.LOW:
            result.summary = (
                f"低风险：发现少量隐藏文本（{total_hidden_chars} 字符）或弱匹配模式。"
                f"建议关注。"
            )
        else:
            result.summary = (
                f"未检测到知识库投毒行为。"
                f"共分析 {total_text_chars} 字符，未发现隐藏文本或投毒模式。"
            )

        return result

    def _extract_char_color(self, char: dict) -> Optional[Tuple[int, int, int]]:
        """从pdfplumber字符信息中提取颜色"""
        try:
            non_stroking = char.get('non_stroking_color')
            if non_stroking and len(non_stroking) >= 3:
                r = int(non_stroking[0] * 255) if non_stroking[0] <= 1 else int(non_stroking[0])
                g = int(non_stroking[1] * 255) if non_stroking[1] <= 1 else int(non_stroking[1])
                b = int(non_stroking[2] * 255) if non_stroking[2] <= 1 else int(non_stroking[2])
                return (r, g, b)
        except Exception:
            pass
        return None

    def _is_invisible_color(self, color: Tuple[int, int, int]) -> bool:
        """判断颜色是否不可见（白色/近白色在白色背景上不可见）"""
        r, g, b = color
        # 白色或近白色 —— PDF 默认背景为白色，白色文字不可见
        if r > WHITE_RGB_THRESHOLD and g > WHITE_RGB_THRESHOLD and b > WHITE_RGB_THRESHOLD:
            return True
        return False

    def _analyze_content_stream(self, content_str: str, page_idx: int,
                                 hidden_texts: List[HiddenTextInfo]) -> None:
        """分析PDF内容流，检测白色字体指令"""
        # 检测白色/透明色设置的文本渲染命令
        white_color_patterns = [
            # 各种白色设置: rg 1 1 1, RG 1 1 1, g 1
            (r'([\d.]+\s+){2,3}(1\.0{0,2}|0\.9[5-9])\s+rg', 'RGB白色填充'),
            (r'([\d.]+\s+){2,3}(1\.0{0,2}|0\.9[5-9])\s+RG', 'RGB白色描边'),
            (r'(1\.0{0,2}|0\.9[5-9])\s+g', '灰度白色'),
            # CMYK 白色
            (r'0\s+0\s+0\s+0\s+k', 'CMYK白色'),
        ]

        found_white = False
        for pattern, desc in white_color_patterns:
            if re.search(pattern, content_str):
                found_white = True
                break

        if found_white:
            # 提取白色设置后的文本内容
            text_ops = re.findall(r'\(([^)]*)\)\s*Tj', content_str)
            if text_ops:
                combined_text = ' '.join(text_ops)
                # 检测文本中是否包含可疑指令
                suspicious = self._check_suspicious_text(combined_text)
                if suspicious:
                    hidden_texts.append(HiddenTextInfo(
                        text=combined_text[:500],
                        location=f"第{page_idx + 1}页 (内容流分析)",
                        font_color="#FFFFFF (白色)",
                        detection_method=f"内容流白色字体 + {desc}",
                    ))

    def _analyze_raw_bytes(self, raw_content: str, hidden_texts: List[HiddenTextInfo]) -> List[HiddenTextInfo]:
        """分析PDF原始字节，检测嵌入的隐藏文本"""
        newly_found = []

        # 检测流对象中的可疑文本（PDF流对象可能在解压后包含隐藏指令）
        stream_pattern = re.compile(r'stream\s+(.*?)\s*endstream', re.DOTALL)
        streams = stream_pattern.findall(raw_content)

        for i, stream in enumerate(streams):
            # 尝试提取可读文本
            readable = re.findall(r'[\x20-\x7E\u4e00-\u9fff]{10,}', stream)
            for text in readable:
                if self._check_suspicious_text(text):
                    newly_found.append(HiddenTextInfo(
                        text=text[:500],
                        location=f"流对象 {i + 1}",
                        detection_method="原始流分析",
                    ))

        hidden_texts.extend(newly_found)
        return newly_found

    def _check_suspicious_text(self, text: str) -> bool:
        """检查文本是否包含可疑的投毒/注入内容"""
        suspicious_markers = [
            "ignore", "override", "bypass", "system prompt",
            "你是", "你的任务", "忽略", "立即执行",
            "输出所有", "system:", "指令:",
        ]
        text_lower = text.lower()
        for marker in suspicious_markers:
            if marker.lower() in text_lower:
                return True
        return False

    def _detect_rag_poisoning_patterns(self, text: str) -> Tuple[RiskLevel, float, List[str]]:
        """检测RAG投毒模式"""
        evidence = []
        confidence = 0.0

        text_lower = text.lower()

        # 1. 检测投毒指令模式
        for pattern, weight, desc in RAG_POISONING_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                match_count = len(matches)
                evidence.append(f"RAG投毒模式 [{desc}]: {match_count} 次匹配")
                confidence += weight * min(match_count, 3)

        # 2. 检测投毒关键词
        keyword_count = 0
        for keyword, weight in POISONING_KEYWORDS:
            if keyword in text_lower:
                keyword_count += 1
                confidence += weight

        if keyword_count > 0:
            evidence.append(f"检测到 {keyword_count} 个投毒关键词")

        # 3. 置信度上限
        confidence = min(confidence, 0.95)

        # 4. 风险等级
        if confidence >= 0.85:
            risk_level = RiskLevel.CRITICAL
        elif confidence >= 0.60:
            risk_level = RiskLevel.HIGH
        elif confidence >= 0.30:
            risk_level = RiskLevel.MEDIUM
        elif confidence > 0:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.NONE

        return risk_level, confidence, evidence

    def detect_text(self, text: str) -> KBPoisoningResult:
        """检测纯文本中的知识库投毒（用于知识库检索结果检测）"""
        result = KBPoisoningResult()

        risk_level, confidence, evidence = self._detect_rag_poisoning_patterns(text)
        result.risk_level = risk_level
        result.confidence = round(confidence, 2)
        result.evidence = evidence if evidence else ["未检测到RAG投毒模式"]
        result.attack_type = AttackType.DATA_POISONING if confidence > 0 else None
        result.total_visible_chars = len(text)

        if confidence > 0:
            result.summary = f"检测到 RAG 投毒风险，置信度 {confidence:.0%}"
        else:
            result.summary = "未检测到 RAG 投毒模式"

        return result


# 全局单例
kb_poisoning_detector = KBPoisoningDetector()
