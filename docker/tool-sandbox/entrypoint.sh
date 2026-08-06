#!/bin/bash
# SafeAgent Tool Sandbox - 工具执行入口
# 从环境变量接收工具名和参数，执行并输出结果

set -e

TOOL_NAME="${TOOL_NAME:-unknown}"
TOOL_ARGS="${TOOL_ARGS:-{}}"

# ======== 工具: read_file ========
if [ "$TOOL_NAME" = "read_file" ]; then
    FILE_PATH=$(echo "$TOOL_ARGS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('path',''))" 2>/dev/null || echo "")
    if [ -n "$FILE_PATH" ] && [ -f "$FILE_PATH" ]; then
        cat "$FILE_PATH"
    else
        echo "[沙箱] 文件不存在或不可读: $FILE_PATH"
        exit 0
    fi
fi

# ======== 工具: search_knowledge ========
if [ "$TOOL_NAME" = "search_knowledge" ]; then
    QUERY=$(echo "$TOOL_ARGS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('query',''))" 2>/dev/null || echo "")
    echo "[沙箱-知识库搜索] 查询: $QUERY"
    echo "结果: 知识库搜索功能已在沙箱中执行，请通过API获取完整结果。"
fi

# ======== 工具: send_email ========
if [ "$TOOL_NAME" = "send_email" ]; then
    TO=$(echo "$TOOL_ARGS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('to',''))" 2>/dev/null || echo "")
    SUBJECT=$(echo "$TOOL_ARGS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('subject',''))" 2>/dev/null || echo "")
    echo "[沙箱-邮件发送] 收件人: $TO"
    echo "主题: $SUBJECT"
    echo "状态: 沙箱模式，邮件未实际发送（仅记录）"
fi

# ======== 工具: query_db ========
if [ "$TOOL_NAME" = "query_db" ]; then
    QUERY=$(echo "$TOOL_ARGS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('query',''))" 2>/dev/null || echo "")
    QUERY_UPPER=$(echo "$QUERY" | tr '[:lower:]' '[:upper:]')
    # 安全检查
    if echo "$QUERY_UPPER" | grep -qE "INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC"; then
        echo "[安全拦截] 沙箱禁止写操作"
        exit 1
    fi
    echo "[沙箱-数据库查询] SQL: $QUERY"
    echo "结果: 只读查询已在沙箱中执行，返回模拟数据集。"
fi

exit 0
