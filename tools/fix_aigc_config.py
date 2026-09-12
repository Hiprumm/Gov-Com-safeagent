# P0-1 工程收敛注入：统一路径引导（原脚本逻辑根目录）
import os as _os, sys as _sys
_BASE_DIR = r"x:\ZuoYe\揭榜挂帅26\Gov-Com-safeagent\ai_service"
_sys.path.insert(0, _BASE_DIR)
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修复AIGC配置脚本 - 关闭显式标签显示

用途：
- 将数据库中的 aigc_explicit_label_enabled 设为 false
- 确保用户看不到【AI生成内容】标签

运行方式：
    python fix_aigc_config.py
"""

import sqlite3
import os
import json

# 数据库路径
DB_PATH = os.path.join(_BASE_DIR, "data", "safeagent.db")

def fix_aigc_config():
    """修复AIGC配置，关闭显式标签"""
    
    if not os.path.exists(DB_PATH):
        print(f"❌ 数据库文件不存在: {DB_PATH}")
        return False
    
    print(f"📊 连接数据库: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # 1. 查看当前配置
        print("\n1️⃣ 查看当前AIGC配置...")
        cursor.execute("SELECT key, value FROM policy_config WHERE key LIKE '%aigc%'")
        rows = cursor.fetchall()
        
        if rows:
            print("当前配置:")
            for key, value in rows:
                print(f"  {key}: {value}")
        else:
            print("  未找到AIGC配置（将使用代码中的默认值）")
        
        # 2. 更新或插入配置
        print("\n2️⃣ 更新AIGC配置...")
        
        # 关闭显式标签
        cursor.execute("""
            INSERT OR REPLACE INTO policy_config (key, value)
            VALUES ('aigc_explicit_label_enabled', 'false')
        """)
        
        # 保留隐式标记
        cursor.execute("""
            INSERT OR REPLACE INTO policy_config (key, value)
            VALUES ('aigc_implicit_marker_enabled', 'true')
        """)
        
        # 更新策略版本
        cursor.execute("SELECT value FROM policy_config WHERE key = '_version'")
        row = cursor.fetchone()
        if row:
            try:
                current_version = json.loads(row[0])
                new_version = current_version + 1
            except:
                new_version = 1
        else:
            new_version = 1
        
        cursor.execute("""
            INSERT OR REPLACE INTO policy_config (key, value)
            VALUES ('_version', ?)
        """, (json.dumps(new_version),))
        
        # 更新时间
        from datetime import datetime
        now = datetime.now().isoformat()
        cursor.execute("""
            INSERT OR REPLACE INTO policy_config (key, value)
            VALUES ('_updated_at', ?)
        """, (json.dumps(now),))
        
        conn.commit()
        
        print("✅ 配置已更新:")
        print("  - aigc_explicit_label_enabled = false （用户看不到标签）")
        print("  - aigc_implicit_marker_enabled = true （保留元数据）")
        print(f"  - 策略版本: {new_version}")
        print(f"  - 更新时间: {now}")
        
        # 3. 验证更新结果
        print("\n3️⃣ 验证更新结果...")
        cursor.execute("SELECT key, value FROM policy_config WHERE key LIKE '%aigc%'")
        rows = cursor.fetchall()
        
        print("更新后配置:")
        for key, value in rows:
            print(f"  {key}: {value}")
        
        print("\n✅ 修复完成！")
        print("\n⚠️  请重启后端服务使配置生效:")
        print("   Ctrl+C 停止服务，然后运行: python -X utf8 main.py")
        
        return True
        
    except Exception as e:
        print(f"❌ 发生错误: {e}")
        conn.rollback()
        return False
        
    finally:
        conn.close()

if __name__ == "__main__":
    print("=" * 60)
    print("  AIGC配置修复脚本")
    print("=" * 60)
    success = fix_aigc_config()
    print("\n" + "=" * 60)
    
    if success:
        print("✅ 脚本执行成功")
    else:
        print("❌ 脚本执行失败，请检查错误信息")
    
    print("=" * 60)
