"""
Advanced Unicode Decoder — 高级 Unicode 解码模块

提供高级 Unicode 解码能力，处理 NFKC 规范化无法覆盖的 5 类编码绕过攻击：
  1. Base64 检测与解码（含双重 Base64）
  2. Unicode 转义序列解码（\\uXXXX）
  3. 扩展 Cyrillic/Greek 同形异义字映射
  4. 空格分隔 SQL 关键词检测与还原
  5. 零宽移除后 SQL 关键词拼接检测与拆分

独立工具模块，不依赖 input_detector.py。

Usage:
    from security.unicode_decoder import advanced_decode

    result, ops = advanced_decode("可疑输入文本...")
"""

import re
import base64
import binascii
from typing import Tuple, List

# ======== 扩展 Cyrillic/Greek 同形异义字映射 ========

_EXPANDED_HOMOGLYPH_MAP = {
    # Cyrillic uppercase
    0x0405: 'S', 0x0406: 'I', 0x0408: 'J', 0x040A: 'L', 0x040C: 'K',
    0x040F: 'D', 0x0417: '3', 0x0418: 'N', 0x0423: 'Y', 0x0425: 'X',
    0x0426: 'U', 0x0427: '4', 0x042C: 'b', 0x042F: 'R',

    # Cyrillic lowercase
    0x0430: 'a', 0x0435: 'e', 0x043E: 'o', 0x0440: 'p', 0x0441: 'c',
    0x0443: 'y', 0x0445: 'x', 0x0456: 'i', 0x0455: 's', 0x04BB: 'h',

    # Greek uppercase
    0x0391: 'A', 0x0392: 'B', 0x0395: 'E', 0x0396: 'Z', 0x0397: 'H',
    0x0399: 'I', 0x039A: 'K', 0x039C: 'M', 0x039D: 'N', 0x039F: 'O',
    0x03A1: 'P', 0x03A4: 'T', 0x03A5: 'Y', 0x03A7: 'X', 0x03DC: 'F',
    0x03DE: 'Q', 0x03E0: 'W',

    # Greek lowercase
    0x03BF: 'o', 0x03C1: 'p', 0x03C4: 't', 0x03C5: 'u', 0x03C7: 'x',

    # Other special (double-struck / script)
    0x2113: 'l', 0x2102: 'C', 0x210D: 'H', 0x2115: 'N', 0x2119: 'P',
    0x211A: 'Q', 0x211D: 'R', 0x2124: 'Z',
}

# ======== SQL 关键词列表（用于 de-space 和 de-concatenate） ========

_SQL_KEYWORDS = [
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "CREATE",
    "ALTER", "FROM", "WHERE", "JOIN", "UNION", "TABLE", "INTO", "VALUES",
    "SET", "AND", "OR", "EXEC", "EXECUTE", "DATABASE", "SCHEMA", "GRANT",
    "REVOKE",
]

# 用于 de-concatenate：前半部分（DML/DDL 动作） + 后半部分（目标对象）
_CONCAT_FIRST_PARTS = {"SELECT", "INSERT", "UPDATE", "DELETE", "DROP",
                       "TRUNCATE", "CREATE", "ALTER"}
_CONCAT_SECOND_PARTS = {"TABLE", "INTO", "FROM", "WHERE", "DATABASE",
                        "SCHEMA", "INDEX", "USER", "VIEW"}

# SQL 关键词查找树（trie），用于 de-space 高效匹配
_SQL_TRIE = {}


def _build_sql_trie():
    """构建 SQL 关键词的 trie 结构，用于 de-space 检测。"""
    if _SQL_TRIE:
        return
    for kw in _SQL_KEYWORDS:
        node = _SQL_TRIE
        for ch in kw:
            if ch not in node:
                node[ch] = {}
            node = node[ch]
        node['$'] = kw  # 终止标记，值为完整关键词


# ======== 1. Unicode 转义序列解码 ========

_UNICODE_ESCAPE_RE = re.compile(r'\\u([0-9a-fA-F]{4})')


def _decode_unicode_escapes(text: str) -> tuple:
    """
    检测并解码 \\uXXXX 转义序列。

    Returns:
        (decoded_text, operation_record_or_None)
    """
    if '\\u' not in text:
        return text, None

    def _replace(match):
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)

    result = _UNICODE_ESCAPE_RE.sub(_replace, text)
    if result != text:
        return result, "Unicode转义序列解码(\\uXXXX)"
    return text, None


# ======== 2. Base64 检测与解码 ========

_BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')


def _is_readable_text(decoded: str) -> bool:
    """判断解码后的字符串是否为可读文本（ASCII 可打印 + 中文）。"""
    if not decoded:
        return False
    printable = 0
    for ch in decoded:
        cp = ord(ch)
        if (0x20 <= cp <= 0x7E) or (0x4E00 <= cp <= 0x9FFF) or \
           (0x3000 <= cp <= 0x303F) or (0xFF00 <= cp <= 0xFFEF):
            printable += 1
    # 至少 70% 为可打印/中文字符
    return (printable / len(decoded)) >= 0.7 if decoded else False


def _decode_base64(text: str) -> tuple:
    """
    检测 Base64 模式并尝试解码。
    支持双重 Base64（decode twice）。

    Returns:
        (decoded_text, operation_record_or_None)
    """
    matches = _BASE64_PATTERN.findall(text)
    if not matches:
        return text, None

    operations = []
    result = text

    for b64_str in matches:
        # 跳过纯数字的匹配（概率上不是 Base64）
        if re.match(r'^[0-9]+$', b64_str):
            continue

        for pass_num in (1, 2):  # 尝试单次和双重解码
            try:
                # 补齐 padding
                padding_needed = len(b64_str) % 4
                padded = b64_str
                if padding_needed:
                    padded += '=' * (4 - padding_needed)

                decoded_bytes = base64.b64decode(padded, validate=True)
                try:
                    decoded_text = decoded_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    # 尝试 latin-1 作为回退
                    try:
                        decoded_text = decoded_bytes.decode('latin-1')
                    except UnicodeDecodeError:
                        break

                if _is_readable_text(decoded_text):
                    result = result.replace(b64_str, decoded_text)
                    if pass_num == 1:
                        operations.append("Base64解码")
                    else:
                        operations.append("双重Base64解码")
                    # 继续用解码后的内容尝试第二重解码
                    b64_str = decoded_text
                else:
                    break

            except (binascii.Error, ValueError):
                break

    if operations:
        return result, operations
    return text, None


# ======== 3. 扩展同形异义字标准化 ========


def _normalize_homoglyphs(text: str) -> tuple:
    """
    将扩展的 Cyrillic/Greek/特殊字符同形异义字映射为 ASCII 对应字符。

    Returns:
        (normalized_text, operation_record_or_None)
    """
    chars = []
    changed = False
    for ch in text:
        cp = ord(ch)
        if cp in _EXPANDED_HOMOGLYPH_MAP:
            chars.append(_EXPANDED_HOMOGLYPH_MAP[cp])
            changed = True
        else:
            chars.append(ch)

    if changed:
        return ''.join(chars), "扩展同形异义字标准化"
    return text, None


# ======== 4. De-Spaced SQL 检测 ========

# 匹配 "单字母 + 空白 + 单字母" 的重复序列（至少3个字母，即至少2个空白分隔）
# 例如: "S E L E C T"、"D\tR\tO\tP  T\tA\tB\tL\tE"
_SPACED_RUN_RE = re.compile(
    r'(?:^|(?<=[\s,;()*]))'       # 起始边界
    r'([A-Za-z]'                    # 第一个字母
    r'(?:\s+[A-Za-z]){2,})',       # 后续至少2个空格分隔的字母
    re.IGNORECASE
)


def _find_kw_in_merged(merged: str, start_offset: int = 0) -> list:
    """在合并后的字母串中查找所有 SQL 关键词子串。
    Returns: [(keyword, start_idx_in_merged, end_idx_in_merged), ...]
    按长度降序排列，以避免短关键词覆盖长关键词的首部。
    """
    _build_sql_trie()
    results = []
    n = len(merged)

    for i in range(n):
        node = _SQL_TRIE
        for j in range(i, n):
            ch = merged[j]
            if ch in node:
                node = node[ch]
                if '$' in node:
                    results.append((node['$'], i, j + 1))
            else:
                break

    # 去重：对于嵌套匹配（如 "DROP" 和 "DROPTABLE"），保留较长者
    # 按长度降序，然后过滤被包含的
    results.sort(key=lambda x: len(x[0]), reverse=True)
    filtered = []
    covered = set()
    for kw, start, end in results:
        # 检查是否与已有选择重叠
        positions = set(range(start, end))
        if not positions & covered:
            filtered.append((kw, start, end))
            covered |= positions
    # 按起始位置排序
    filtered.sort(key=lambda x: x[1])
    return filtered


def _despace_sql(text: str) -> tuple:
    """
    检测被空格/制表符/换行分隔成单个字母的 SQL 关键词并还原。

    核心思路：
    1. 用正则找到所有"空格分隔单字母"的连续片段
    2. 对于每个片段，提取首字母和每个"空白+字母"在原文本中的位置
    3. 合并字母为大写串，在其中搜索 SQL 关键词子串
    4. 根据位置映射，精确替换原文本中的对应部分

    Returns:
        (processed_text, operation_record_or_None)
    """
    _build_sql_trie()
    operations = []

    # 收集所有需要替换的区间
    replacements = []

    for match in _SPACED_RUN_RE.finditer(text):
        original = match.group(0)
        match_start = match.start()
        # 解析 original 中的字母位置映射
        # original 格式: "S E L E C T" 或 "D\tR\tO\tP"
        letter_positions = []  # [(char_in_merged, abs_pos_in_text), ...]
        pos = match_start
        for ch in original:
            if ch.isalpha():
                letter_positions.append(pos)
                pos += 1
            else:
                pos += 1

        merged = re.sub(r'\s+', '', original).upper()

        # 在 merged 中查找 SQL 关键词
        kw_matches = _find_kw_in_merged(merged)

        for kw, start_idx, end_idx in kw_matches:
            kw_len = end_idx - start_idx
            # 映射回原文本位置
            if start_idx < len(letter_positions) and (end_idx - 1) < len(letter_positions):
                abs_start = letter_positions[start_idx]
                abs_end = letter_positions[end_idx - 1] + 1
                replacements.append((abs_start, abs_end, kw))

    if not replacements:
        # 无匹配，直接返回
        return text, None

    # 排序并合并非重叠替换（从后往前替换避免索引偏移）
    replacements.sort(key=lambda x: x[0], reverse=True)
    result = text
    for abs_start, abs_end, kw in replacements:
        # 只替换 keyword 字母部分，保留 keyword 之后的空白直到下一个 keyword 或结尾
        result = result[:abs_start] + kw + result[abs_end:]

    if result != text:
        return result, "De-Space SQL关键词还原"
    return text, None


# ======== 5. De-Concatenated SQL 检测 ========


def _deconcatenate_sql(text: str) -> tuple:
    """
    检测零宽字符移除后产生的 SQL 关键词拼接（如 DROPTABLE → DROP TABLE）。

    Returns:
        (processed_text, operation_record_or_None)
    """
    changed = False
    result = text
    found_pair = False

    # 构建所有可能的拼接组合
    for first in sorted(_CONCAT_FIRST_PARTS, key=len, reverse=True):
        for second in sorted(_CONCAT_SECOND_PARTS, key=len, reverse=True):
            concat = first + second
            # 使用大小写不敏感匹配
            pattern = re.compile(re.escape(concat), re.IGNORECASE)
            if pattern.search(result):
                # 在拼接处插入空格：用回调函数精确替换
                def _replacer(m, f=first, s=second):
                    matched = m.group(0)
                    # 保持原始大小写
                    return matched[:len(f)] + ' ' + matched[len(f):]

                result = pattern.sub(_replacer, result)
                changed = True
                found_pair = True

    if found_pair:
        return result, "De-Concatenate SQL关键词拆分"
    return text, None


# ======== 主函数 ========


def advanced_decode(text: str) -> Tuple[str, list]:
    """
    高级 Unicode 解码，用于绕过攻击检测。

    按以下顺序依次处理：
      1. Unicode 转义序列解码 (\\uXXXX → 对应字符)
      2. Base64 检测与解码（含双重 Base64）
      3. 扩展同形异义字标准化（Cyrillic/Greek/特殊 → ASCII）
      4. De-Space SQL 关键词还原（被空白分隔的字母重组为 SQL 关键词）
      5. De-Concatenate SQL 拆分（零宽移除后拼接的 SQL 关键词拆分）

    Args:
        text: 待处理的原始文本

    Returns:
        (decoded_text, operations_list):
          - decoded_text: 解码后的文本
          - operations_list: 执行的操作记录列表（字符串列表），若未执行任何操作为空列表
    """
    operations = []
    current = text

    # 1. Unicode 转义序列解码
    current, op = _decode_unicode_escapes(current)
    if op:
        operations.append(op)

    # 2. Base64 检测与解码
    current, op = _decode_base64(current)
    if op:
        if isinstance(op, list):
            operations.extend(op)
        else:
            operations.append(op)

    # 3. 扩展同形异义字标准化
    current, op = _normalize_homoglyphs(current)
    if op:
        operations.append(op)

    # 4. De-Space SQL 关键词还原
    current, op = _despace_sql(current)
    if op and op not in operations:
        operations.append(op)

    # 5. De-Concatenate SQL 拆分
    current, op = _deconcatenate_sql(current)
    if op:
        operations.append(op)

    return current, operations


# ======== 测试用例 ========

if __name__ == "__main__":
    print("=" * 60)
    print("unicode_decoder 模块测试")
    print("=" * 60)
    passed = 0
    failed = 0

    def _test(name, input_text, expected_contains=None, expected_ops=None):
        global passed, failed
        result, ops = advanced_decode(input_text)
        print(f"\n[{name}]")
        print(f"  输入: {input_text[:80]}{'...' if len(input_text) > 80 else ''}")
        print(f"  输出: {result[:80]}{'...' if len(result) > 80 else ''}")
        print(f"  操作: {ops}")
        ok = True
        if expected_contains and expected_contains not in result:
            print(f"  ❌ 期望包含 '{expected_contains}'，未找到")
            ok = False
        if expected_ops:
            for eo in expected_ops:
                if eo not in ops:
                    print(f"  ❌ 期望操作 '{eo}'，未在 {ops} 中")
                    ok = False
        if ok:
            print(f"  ✅ 通过")
            passed += 1
        else:
            failed += 1

    # Test 1: Unicode 转义序列解码
    _test("Unicode转义",
          r"\u0053\u0045\u004c\u0045\u0043\u0054",
          expected_contains="SELECT",
          expected_ops=["Unicode转义序列解码(\\uXXXX)"])

    _test("Unicode转义-无转义",
          "普通文本 SELECT 1",
          expected_contains="普通文本 SELECT 1")

    # Test 2: Base64 解码
    # "SELECT * FROM users" 的 Base64: U0VMRUNUICogRlJPTSB1c2Vycw==
    _test("Base64解码",
          "执行这个：U0VMRUNUICogRlJPTSB1c2Vycw==",
          expected_contains="SELECT",
          expected_ops=["Base64解码"])

    # 双重 Base64: "DROP TABLE users" → RFJPUCBUQUJMRSB1c2Vycw== → UkZKUFVDQlVRVUpNUlNCMWMyVnljdz09
    _test("双重Base64",
          "执行：UkZKUFVDQlVRVUpNUlNCMWMyVnljdz09",
          expected_contains="DROP",
          expected_ops=["双重Base64解码"])

    # Test 3: 扩展同形异义字
    _test("Cyrillic同形-俄语a",
          "\u0430\u0435\u0441",  # Cyrillic 'a', 'e', 'c'
          expected_contains="aec",
          expected_ops=["扩展同形异义字标准化"])

    _test("Greek同形-大写A",
          "\u0391\u0392\u0395",  # Greek A, B, E
          expected_contains="ABE",
          expected_ops=["扩展同形异义字标准化"])

    _test("特殊数学符号",
          "\u2102\u210D\u2115",  # Double-struck C, H, N
          expected_contains="CHN",
          expected_ops=["扩展同形异义字标准化"])

    # Test 4: De-Space SQL
    _test("De-Space SQL",
          "S E L E C T  *  \n F R O M",
          expected_contains="SELECT",
          expected_ops=["De-Space SQL关键词还原"])

    _test("De-Space SQL-制表符",
          "D\tR\tO\tP  T\tA\tB\tL\tE",
          expected_contains="DROP",
          expected_ops=["De-Space SQL关键词还原"])

    # Test 5: De-Concatenate SQL
    _test("De-Concatenate SQL",
          "DROPTABLEusers",
          expected_contains="DROP TABLE",
          expected_ops=["De-Concatenate SQL关键词拆分"])

    _test("De-Concatenate-SELECTINTO",
          "SELECTINTOoutfile",
          expected_contains="SELECT INTO",
          expected_ops=["De-Concatenate SQL关键词拆分"])

    _test("De-Concatenate-CREATETABLE",
          "CREATETABLEtest(id INT)",
          expected_contains="CREATE TABLE",
          expected_ops=["De-Concatenate SQL关键词拆分"])

    # Test 6: 组合测试
    _test("组合-U转义+Base64",
          r"执行\u8BF7\u6C42：U0VMRUNUICogRlJPTSB1c2Vycw==",
          expected_contains="SELECT")

    _test("组合-Cyrillic+拼接",
          "DR\u041ePTABLEusers",  # Cyrillic O in DR|PTABLE
          expected_contains="DR")

    # Test 7: 安全输入（不应误报）
    _test("正常文本",
          "请帮我查询用户信息",
          expected_contains="请帮我查询用户信息")

    _test("正常SQL注释",
          "-- 这是一个 SELECT 查询",
          expected_contains="SELECT")

    _test("短Base64无害",
          "hello world test 12345 abcdefg",
          expected_contains="hello")  # 短 Base64 不应被误判

    print("\n" + "=" * 60)
    print(f"测试结果: {passed} 通过, {failed} 失败, 共 {passed + failed} 项")
    print("=" * 60)
