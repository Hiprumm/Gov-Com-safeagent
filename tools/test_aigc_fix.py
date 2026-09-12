# P0-1 工程收敛注入：统一路径引导（原脚本逻辑根目录）
import os as _os, sys as _sys
_BASE_DIR = r"x:\ZuoYe\揭榜挂帅26\Gov-Com-safeagent\ai_service"
_sys.path.insert(0, _BASE_DIR)
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试AIGC标签修复是否生效

运行方式：
    python test_aigc_fix.py
"""

import sys
import os

# 添加路径
sys.path.insert(0, _BASE_DIR)

def test_aigc_label():
    """测试AIGC标签生成"""
    print("=" * 60)
    print("  测试AIGC标签生成")
    print("=" * 60)
    
    try:
        from security.aigc_labeling import (
            build_aigc_metadata,
            apply_aigc_label,
            build_explicit_label,
            EXPLICIT_LABEL_TEMPLATE
        )
        
        # 1. 检查模板
        print("\n1️⃣ 检查EXPLICIT_LABEL_TEMPLATE:")
        print(f"   值: '{EXPLICIT_LABEL_TEMPLATE}'")
        print(f"   长度: {len(EXPLICIT_LABEL_TEMPLATE)}")
        
        if EXPLICIT_LABEL_TEMPLATE == "":
            print("   ✅ 模板为空，不会生成标签")
        else:
            print("   ❌ 模板不为空，仍会生成标签")
            print(f"   内容: {EXPLICIT_LABEL_TEMPLATE}")
        
        # 2. 测试 build_explicit_label
        print("\n2️⃣ 测试 build_explicit_label():")
        metadata = build_aigc_metadata()
        label = build_explicit_label(metadata)
        print(f"   返回值: '{label}'")
        print(f"   长度: {len(label)}")
        
        if label == "":
            print("   ✅ 返回空字符串，不会显示标签")
        else:
            print("   ❌ 返回了内容，会显示标签")
            print(f"   内容: {label}")
        
        # 3. 测试 apply_aigc_label (include_explicit=True)
        print("\n3️⃣ 测试 apply_aigc_label (include_explicit=True):")
        test_content = "这是测试内容"
        result = apply_aigc_label(
            test_content,
            metadata,
            include_implicit=False,
            include_explicit=True
        )
        
        labeled_content = result['labeled_content']
        print(f"   labeled_content: '{labeled_content}'")
        
        if labeled_content == test_content:
            print("   ✅ 内容未添加标签")
        elif "【AI生成" in labeled_content:
            print("   ❌ 内容中包含【AI生成】标签")
        else:
            print("   ⚠️  内容已改变但不包含标签")
        
        # 4. 测试 apply_aigc_label (include_explicit=False)
        print("\n4️⃣ 测试 apply_aigc_label (include_explicit=False):")
        result2 = apply_aigc_label(
            test_content,
            metadata,
            include_implicit=False,
            include_explicit=False
        )
        
        labeled_content2 = result2['labeled_content']
        print(f"   labeled_content: '{labeled_content2}'")
        
        if labeled_content2 == test_content:
            print("   ✅ 内容未添加标签")
        else:
            print("   ❌ 内容被修改了")
        
        # 总结
        print("\n" + "=" * 60)
        print("  总结")
        print("=" * 60)
        
        all_pass = (
            EXPLICIT_LABEL_TEMPLATE == "" and
            label == "" and
            labeled_content == test_content and
            labeled_content2 == test_content
        )
        
        if all_pass:
            print("✅ 所有测试通过！AIGC标签已完全禁用")
            print("\n下一步：")
            print("1. 重启后端服务")
            print("2. 登录前端测试")
            print("3. 确认回复中没有【AI生成内容】标签")
            return True
        else:
            print("❌ 部分测试未通过，请检查代码修改")
            return False
            
    except Exception as e:
        print(f"\n❌ 测试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_aigc_fix()
    sys.exit(0 if success else 1)
