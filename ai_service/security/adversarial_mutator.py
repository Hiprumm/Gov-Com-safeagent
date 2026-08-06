"""
对抗样本自动变异引擎 (Adversarial Mutator)

生成对抗样本变体，用于测试安全检测引擎的鲁棒性。
支持的变异策略（10种）：
1. 全角字符替换 —— 半角→全角 Unicode 映射
2. Unicode 同形异义字 —— 视觉相同但编码不同 (homoglyph)
3. 空格/零宽字符插入 —— 打散关键词规避匹配
4. 大小写混淆 —— 随机大小写
5. 转义/编码绕过 —— URL编码、HTML实体
6. 分隔符插入 —— 在关键词中插入无害字符
7. Base64 编码绕过 —— 将攻击payload进行Base64编码
8. HTML/XML 实体编码 —— &#xHH; / \\uXXXX 实体编码
9. 多语言混合注入 —— 中英日韩混合打散检测规则
10. 空格变体替换 —— 非标准空格(U+00A0等)替换普通空格
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import random
import base64
import string
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field


# ==================== 字符映射表 ====================

# 半角 → 全角字符映射
HALF_TO_FULL = {
    c: chr(ord(c) + 0xFEE0) for c in string.ascii_letters + string.digits
    if ord(c) + 0xFEE0 <= 0xFF5E
}
# 特殊字符
HALF_TO_FULL.update({
    ' ': '\u3000', '!': '\uFF01', '"': '\uFF02', '#': '\uFF03',
    '$': '\uFF04', '%': '\uFF05', '&': '\uFF06', "'": '\uFF07',
    '(': '\uFF08', ')': '\uFF09', '*': '\uFF0A', '+': '\uFF0B',
    ',': '\uFF0C', '-': '\uFF0D', '.': '\uFF0E', '/': '\uFF0F',
    ':': '\uFF1A', ';': '\uFF1B', '<': '\uFF1C', '=': '\uFF1D',
    '>': '\uFF1E', '?': '\uFF1F', '@': '\uFF10',
})

# Unicode 同形异义字 (homoglyph) 映射
HOMOGLYPH_MAP = {
    'a': ['\u0430', '\u00E0', '\u00E1'],  # Cyrillic a, à, á
    'e': ['\u0435', '\u00E8', '\u00E9'],  # Cyrillic e, è, é
    'i': ['\u0456', '\u00EC', '\u00ED'],  # Cyrillic i, ì, í
    'o': ['\u043E', '\u00F2', '\u00F3'],  # Cyrillic o, ò, ó
    'c': ['\u0441', '\u00E7'],            # Cyrillic s (looks like c), ç
    'p': ['\u0440'],                      # Cyrillic r (looks like p)
    'x': ['\u0445'],                      # Cyrillic kh (looks like x)
    's': ['\u0455'],                      # Cyrillic dze (looks like s)
    'y': ['\u0443'],                      # Cyrillic u (looks like y)
    'A': ['\u0410'],                      # Cyrillic A
    'B': ['\u0412'],                      # Cyrillic V (looks like B)
    'E': ['\u0415'],                      # Cyrillic E
    'H': ['\u041D'],                      # Cyrillic N (looks like H)
    'K': ['\u041A'],                      # Cyrillic K
    'M': ['\u041C'],                      # Cyrillic M
    'O': ['\u041E'],                      # Cyrillic O
    'P': ['\u0420'],                      # Cyrillic R (looks like P)
    'T': ['\u0422'],                      # Cyrillic T
    'X': ['\u0425'],                      # Cyrillic Kh (looks like X)
}

# 零宽字符
ZERO_WIDTH_CHARS = [
    '\u200B',  # Zero Width Space
    '\u200C',  # Zero Width Non-Joiner
    '\u200D',  # Zero Width Joiner
    '\uFEFF',  # Zero Width No-Break Space
    '\u2060',  # Word Joiner
]

# 空格变体
SPACE_VARIANTS = [
    ' ', '\u00A0', '\u2000', '\u2001', '\u2002',
    '\u2003', '\u2004', '\u2005', '\u2006', '\u2007',
    '\u2008', '\u2009', '\u200A', '\u3000',
]


@dataclass
class MutationVariant:
    """一个变异样本"""
    text: str
    mutation_type: str
    description: str


@dataclass
class BypassTestResult:
    """单个样本的 Bypass 测试结果"""
    original_text: str
    original_risk: str
    original_confidence: float
    variants: List[Dict] = field(default_factory=list)
    bypass_rate: float = 0.0     # 成功绕过比例
    resistance_score: float = 0.0  # 抗绕过能力分数（越高越好）


class AdversarialMutator:
    """对抗样本变异器"""

    def __init__(self, seed: int = None):
        if seed is not None:
            random.seed(seed)

    def mutate(self, text: str, strategy: str = None) -> List[MutationVariant]:
        """
        对输入文本应用变异策略

        Args:
            text: 原始输入文本
            strategy: 指定策略 (fullwidth|homoglyph|zerowidth|space|case|encoding|delimiter|all)

        Returns:
            变异样本列表
        """
        variants = []

        if strategy == "fullwidth" or strategy is None:
            variants.extend(self._fullwidth_mutate(text))
        if strategy == "homoglyph" or strategy is None:
            variants.extend(self._homoglyph_mutate(text))
        if strategy == "zerowidth" or strategy is None:
            variants.extend(self._zerowidth_mutate(text))
        if strategy == "space" or strategy is None:
            variants.extend(self._space_insert_mutate(text))
        if strategy == "case" or strategy is None:
            variants.extend(self._case_variation(text))
        if strategy == "encoding" or strategy is None:
            variants.extend(self._encoding_bypass(text))
        if strategy == "delimiter" or strategy is None:
            variants.extend(self._delimiter_bypass(text))
        if strategy == "base64" or strategy is None:
            variants.extend(self._base64_bypass(text))
        if strategy == "entity" or strategy is None:
            variants.extend(self._entity_bypass(text))
        if strategy == "multilang" or strategy is None:
            variants.extend(self._multilang_bypass(text))

        return variants

    def _fullwidth_mutate(self, text: str) -> List[MutationVariant]:
        """全角字符替换"""
        result = []
        full = ''.join(HALF_TO_FULL.get(c, c) for c in text)
        result.append(MutationVariant(
            text=full,
            mutation_type="fullwidth",
            description="全角字符替换：将所有半角字符替换为全角形式"
        ))

        # 混合：随机50%字符替换
        mixed = ''.join(
            HALF_TO_FULL.get(c, c) if random.random() < 0.5 else c
            for c in text
        )
        result.append(MutationVariant(
            text=mixed,
            mutation_type="fullwidth_mixed",
            description="半全角混合：随机50%字符替换为全角"
        ))
        return result

    def _homoglyph_mutate(self, text: str) -> List[MutationVariant]:
        """Unicode 同形异义字替换"""
        result = []
        # 25% 替换率
        chars = list(text)
        replaced = 0
        for i, c in enumerate(chars):
            if c in HOMOGLYPH_MAP and random.random() < 0.25:
                chars[i] = random.choice(HOMOGLYPH_MAP[c])
                replaced += 1
        if replaced > 0:
            result.append(MutationVariant(
                text=''.join(chars),
                mutation_type="homoglyph_25",
                description=f"同形异义字替换(25%): {replaced}/{len(text)} 字符被替换"
            ))

        # 50% 替换率
        chars = list(text)
        replaced = 0
        for i, c in enumerate(chars):
            if c in HOMOGLYPH_MAP and random.random() < 0.50:
                chars[i] = random.choice(HOMOGLYPH_MAP[c])
                replaced += 1
        if replaced > 0:
            result.append(MutationVariant(
                text=''.join(chars),
                mutation_type="homoglyph_50",
                description=f"同形异义字替换(50%): {replaced}/{len(text)} 字符被替换"
            ))
        return result

    def _zerowidth_mutate(self, text: str) -> List[MutationVariant]:
        """零宽字符插入"""
        result = []

        # 策略1: 在关键词之间插入零宽字符
        zw = random.choice(ZERO_WIDTH_CHARS)
        words = text.split()
        if len(words) > 1:
            zinsert = zw.join(words)
            result.append(MutationVariant(
                text=zinsert,
                mutation_type="zerowidth_between",
                description=f"零宽字符插入(词间): {len(words)-1} 个零宽字符"
            ))

        # 策略2: 在每个字符后插入（仅对字母数字）
        chars = list(text)
        zw2 = random.choice(ZERO_WIDTH_CHARS)
        zinsert2 = []
        for c in chars:
            zinsert2.append(c)
            if c.isalnum():
                zinsert2.append(zw2)
        result.append(MutationVariant(
            text=''.join(zinsert2),
            mutation_type="zerowidth_per_char",
            description="零宽字符插入(每字符后)"
        ))

        return result

    def _space_insert_mutate(self, text: str) -> List[MutationVariant]:
        """空格变体插入"""
        result = []

        # 使用非标准空格替换普通空格
        for sv in SPACE_VARIANTS[1:4]:  # 取几种变体
            modified = text.replace(' ', sv)
            if modified != text:
                result.append(MutationVariant(
                    text=modified,
                    mutation_type="space_variant",
                    description=f"空格变体替换: U+{ord(sv):04X}"
                ))

        return result

    def _case_variation(self, text: str) -> List[MutationVariant]:
        """大小写混淆"""
        result = []
        # 随机大小写
        random_case = ''.join(
            c.upper() if random.random() < 0.5 else c.lower()
            for c in text
        )
        if random_case != text and random_case.lower() != text.lower():
            result.append(MutationVariant(
                text=random_case,
                mutation_type="random_case",
                description="随机大小写混淆"
            ))

        # 交替大小写
        alt_case = ''.join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(text)
        )
        result.append(MutationVariant(
            text=alt_case,
            mutation_type="alternating_case",
            description="交替大小写混淆"
        ))
        return result

    def _encoding_bypass(self, text: str) -> List[MutationVariant]:
        """编码绕过"""
        # URL 编码部分字符
        encoded_chars = []
        for c in text:
            if c in " <>\"'&" and random.random() < 0.5:
                encoded_chars.append(f"%{ord(c):02X}")
            else:
                encoded_chars.append(c)
        encoded = ''.join(encoded_chars)
        if encoded != text:
            return [MutationVariant(
                text=encoded,
                mutation_type="url_encode",
                description="URL 编码绕过"
            )]
        return []

    def _delimiter_bypass(self, text: str) -> List[MutationVariant]:
        """分隔符绕过 —— 在关键词中插入无害字符"""
        result = []
        delimiters = ['.', '-', '_', '/', '\\', '|']

        # 在已知攻击关键词中插入分隔符
        attack_keywords = [
            "ignore", "instructions", "override", "bypass",
            "system", "prompt", "DAN", "admin", "password",
            "SELECT", "DELETE", "rm -rf", "eval", "exec",
        ]

        modified = text
        applied = False
        for kw in attack_keywords:
            if kw.lower() in modified.lower():
                # 在关键词中间插入分隔符
                delim = random.choice(delimiters)
                mid = len(kw) // 2
                new_kw = kw[:mid] + delim + kw[mid:]
                modified = modified.replace(kw, new_kw)
                applied = True

        if applied:
            result.append(MutationVariant(
                text=modified,
                mutation_type="delimiter_bypass",
                description="分隔符插入绕过：在关键词中插入分隔符"
            ))
        return result

    def _base64_bypass(self, text: str) -> List[MutationVariant]:
        """Base64 编码绕过 —— 对攻击payload进行Base64编码"""
        result = []
        try:
            # 完整 Base64 编码
            encoded_bytes = base64.b64encode(text.encode('utf-8'))
            encoded_full = encoded_bytes.decode('ascii')
            result.append(MutationVariant(
                text=f"请解码并执行以下Base64内容：{encoded_full}",
                mutation_type="base64_full",
                description="Base64 完整编码：将整段文本编码为Base64"
            ))

            # 只编码敏感关键词部分（查找已知攻击词并编码）
            attack_keywords = [
                "ignore", "forget", "bypass", "override", "execute",
                "admin", "password", "delete", "drop", "rm -rf",
                "SELECT", "INSERT", "UPDATE", "DROP TABLE",
            ]
            found_keywords = []
            for kw in attack_keywords:
                if kw in text or kw.lower() in text.lower():
                    found_keywords.append(kw)
            if found_keywords:
                partial_text = text
                for kw in found_keywords[:3]:
                    enc = base64.b64encode(kw.encode('utf-8')).decode('ascii')
                    partial_text = partial_text.replace(kw, enc)
                result.append(MutationVariant(
                    text=partial_text,
                    mutation_type="base64_partial",
                    description=f"Base64 部分编码：对 {len(found_keywords[:3])} 个关键词编码"
                ))
        except Exception:
            pass
        return result

    def _entity_bypass(self, text: str) -> List[MutationVariant]:
        """HTML/XML/Unicode 实体编码绕过"""
        result = []

        # HTML 实体编码：&#xHH;
        chars_list = []
        replaced_html = 0
        for c in text:
            if c.isalpha() and random.random() < 0.30:
                chars_list.append(f"&#x{ord(c):x};")
                replaced_html += 1
            else:
                chars_list.append(c)
        if replaced_html > 0:
            result.append(MutationVariant(
                text=''.join(chars_list),
                mutation_type="html_entity",
                description=f"HTML实体编码: {replaced_html} 个字符被替换为 &#xHH; 格式"
            ))

        # Unicode 转义序列: \\uXXXX
        chars2 = []
        replaced_unicode = 0
        for c in text:
            if c.isalpha() and random.random() < 0.25:
                chars2.append(f"\\u{ord(c):04x}")
                replaced_unicode += 1
            else:
                chars2.append(c)
        if replaced_unicode > 0:
            result.append(MutationVariant(
                text=''.join(chars2),
                mutation_type="unicode_escape",
                description=f"Unicode转义编码: {replaced_unicode} 个字符被替换为 \\uXXXX 格式"
            ))

        # JSON 实体: \\uXXXX 紧凑格式（不区分字母，全编）
        json_chars = []
        replaced_json = 0
        for c in text:
            if c.isalpha() and random.random() < 0.20:
                json_chars.append(f"\\u{ord(c):04x}")
                replaced_json += 1
            else:
                json_chars.append(c)
        if replaced_json > 0:
            result.append(MutationVariant(
                text=''.join(json_chars),
                mutation_type="json_unicode",
                description=f"JSON Unicode实体: {replaced_json} 个字符被替换为紧凑 \\uXXXX"
            ))

        return result

    def _multilang_bypass(self, text: str) -> List[MutationVariant]:
        """多语言混合注入 —— 用中英日韩字符替换英文关键词"""

        # 多语言字符映射：英文关键词 → 混合语言变体
        multilingual_subst = {
            # 中文同义
            'ignore': ['忽略', '无视', 'わすれろ'],
            'bypass': ['绕过', '回避', 'かいひ'],
            'execute': ['执行', '実行', '실행'],
            'admin': ['管理员', '管理者', '관리자'],
            'password': ['密码', 'パスワード', '비밀번호'],
            'system': ['系统', 'システム', '시스템'],
            'delete': ['删除', '削除', '삭제'],
            'user': ['用户', 'ユーザー', '사용자'],
            'security': ['安全', 'セキュリティ', '보안'],
            'access': ['访问', 'アクセス', '접근'],
            # 混合大小写变体
            'select': ['sElEcT', 'ＳＥＬＥＣＴ'],
            'insert': ['iNsErT', 'ＩＮＳＥＲＴ'],
            'drop': ['dRoP', 'ＤＲＯＰ'],
            'union': ['uNiOn', 'ＵＮＩＯＮ'],
        }

        result = []

        # 策略1: 混合中英日韩关键词替换
        words = text.split()
        mixed_words = []
        replaced_count = 0
        for word in words:
            lower = word.lower().strip('.,;:!?()[]{}"\'')
            if lower in multilingual_subst and random.random() < 0.50:
                subst = random.choice(multilingual_subst[lower])
                # 保留原始标点
                prefix = ''
                suffix = ''
                for c in word:
                    if c in '.,;:!?()[]{}"\'':
                        if word.index(c) < len(word) // 2:
                            prefix += c
                        else:
                            suffix += c
                mixed_words.append(prefix + subst + suffix)
                replaced_count += 1
            else:
                mixed_words.append(word)
        if replaced_count > 0:
            result.append(MutationVariant(
                text=' '.join(mixed_words),
                mutation_type="multilang_subst",
                description=f"多语言混合替换: {replaced_count} 个关键词被替换为中日韩文字"
            ))

        # 策略2: 在英文字母间插入全角空格/中文标点（打散模式匹配）
        import re
        # 找到英文单词并插入中文标点
        def scramble_english(match):
            word = match.group(0)
            if len(word) <= 2:
                return word
            # 在单词中间随机插入中文句号
            mid = len(word) // 2
            return word[:mid] + '。' + word[mid:]

        scrambled = re.sub(r'[a-zA-Z]{3,}', scramble_english, text)
        if scrambled != text:
            result.append(MutationVariant(
                text=scrambled,
                mutation_type="multilang_scramble",
                description="多语言打散: 在英文单词中插入中文标点"
            ))

        return result


class BypassTester:
    """Bypass 测试器 —— 运行变异样本过检测器并计算绕过率"""

    def __init__(self, detector_func):
        """
        Args:
            detector_func: 检测函数，签名为 (text, source) -> DetectionResult
        """
        self.detector = detector_func
        self.mutator = AdversarialMutator()

    def test_sample(self, text: str, source: str = "user_input",
                    strategy: str = None) -> BypassTestResult:
        """测试单个样本的绕过能力"""
        # 原始检测
        original_result = self.detector(text, source)
        original_risk = original_result.risk_level.value if hasattr(original_result, 'risk_level') else 'none'
        original_conf = original_result.confidence if hasattr(original_result, 'confidence') else 0.0

        result = BypassTestResult(
            original_text=text[:200],
            original_risk=original_risk,
            original_confidence=round(original_conf, 2),
        )

        if original_risk in ('none', 'low'):
            result.bypass_rate = 1.0  # 原始就检测不到，不需要绕过
            result.resistance_score = 0.0
            return result

        # 生成变异样本
        variants = self.mutator.mutate(text, strategy)

        bypassed = 0
        for var in variants:
            try:
                det_result = self.detector(var.text, source)
                var_risk = det_result.risk_level.value if hasattr(det_result, 'risk_level') else 'none'
                var_conf = det_result.confidence if hasattr(det_result, 'confidence') else 0.0

                # 判断是否绕过（风险降级）
                risk_order = {'none': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                bypassed_flag = risk_order.get(var_risk, 0) < risk_order.get(original_risk, 0)

                if bypassed_flag:
                    bypassed += 1

                result.variants.append({
                    "mutation_type": var.mutation_type,
                    "description": var.description,
                    "variant_text": var.text[:100],
                    "risk_level": var_risk,
                    "confidence": round(var_conf, 2),
                    "bypassed": bypassed_flag,
                })
            except Exception as e:
                result.variants.append({
                    "mutation_type": var.mutation_type,
                    "description": var.description,
                    "error": str(e),
                })

        total = len(variants)
        if total > 0:
            result.bypass_rate = round(bypassed / total, 2)
            result.resistance_score = round(1.0 - result.bypass_rate, 2)

        return result

    def batch_test(self, samples: List[Dict], strategy: str = None) -> List[Dict]:
        """
        批量测试多组样本

        Args:
            samples: [{"text": "...", "source": "..."}, ...]
            strategy: 指定策略

        Returns:
            [{"original": ..., "bypass_rate": ..., "variants": [...]}, ...]
        """
        results = []
        for sample in samples:
            text = sample.get("text", "")
            source = sample.get("source", "user_input")
            test_result = self.test_sample(text, source, strategy)
            results.append({
                "original_text": test_result.original_text,
                "original_risk": test_result.original_risk,
                "original_confidence": test_result.original_confidence,
                "bypass_rate": test_result.bypass_rate,
                "resistance_score": test_result.resistance_score,
                "total_variants": len(test_result.variants),
                "bypassed_variants": sum(1 for v in test_result.variants if v.get("bypassed")),
                "variants": test_result.variants,
            })
        return results


# 全局单例
adversarial_mutator = AdversarialMutator()
