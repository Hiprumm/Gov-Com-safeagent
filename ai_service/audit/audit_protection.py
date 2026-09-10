# -*- coding: utf-8 -*-
"""审计不可篡改（WORM）与留存归档

安全目标（等保 2.0 审计要求）：
- **不可篡改（WORM）**：在数据库层禁止对 `audit_logs` 的 UPDATE / DELETE——
  SQLite 用触发器 `RAISE(ABORT, ...)`；PostgreSQL 用 plpgsql 触发器 `RAISE EXCEPTION`。
  即使绕过应用层直接改库也会被拒绝，与哈希链 + 签名形成"逻辑校验 + 物理约束"双保险；
- **留存归档**：超过留存期的日志先**归档导出（JSONL，含哈希链字段）**再清理，
  避免"到期直接删除"导致历史证据丢失；归档与清理在维护窗口内临时移除 DELETE 保护后执行。

架构：本模块通过 `get_storage().is_file_backed` 感知后端（SQLite / PostgreSQL），
分别使用对应的 WORM 实现与维护窗口方式，对外 API 保持一致。
"""
import json
import os
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Optional

from storage import get_storage

# 默认归档目录：ai_service/data/audit_archive
ARCHIVE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "audit_archive"
)

_UPDATE_TRIGGER = "trg_audit_worm_no_update"
_DELETE_TRIGGER = "trg_audit_worm_no_delete"
_PG_FUNC = "audit_logs_worm_guard"
_PG_TRIG_UPDATE = "trg_audit_worm_no_update"
_PG_TRIG_DELETE = "trg_audit_worm_no_delete"

_SQL_CREATE_UPDATE = f"""
CREATE TRIGGER IF NOT EXISTS {_UPDATE_TRIGGER}
BEFORE UPDATE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'audit_logs is append-only (WORM): UPDATE denied');
END;
"""

_SQL_CREATE_DELETE = f"""
CREATE TRIGGER IF NOT EXISTS {_DELETE_TRIGGER}
BEFORE DELETE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'audit_logs is append-only (WORM): DELETE denied');
END;
"""

# PostgreSQL：触发器函数 + 两个触发器（幂等：先 DROP 再建）
_PG_INSTALL_STATEMENTS = [
    f"""CREATE OR REPLACE FUNCTION {_PG_FUNC}() RETURNS trigger AS $$
        BEGIN
          RAISE EXCEPTION 'audit_logs is append-only (WORM): % denied', TG_OP;
        END;
        $$ LANGUAGE plpgsql""",
    f"DROP TRIGGER IF EXISTS {_PG_TRIG_UPDATE} ON audit_logs",
    f"DROP TRIGGER IF EXISTS {_PG_TRIG_DELETE} ON audit_logs",
    f"CREATE TRIGGER {_PG_TRIG_UPDATE} BEFORE UPDATE ON audit_logs FOR EACH ROW EXECUTE FUNCTION {_PG_FUNC}()",
    f"CREATE TRIGGER {_PG_TRIG_DELETE} BEFORE DELETE ON audit_logs FOR EACH ROW EXECUTE FUNCTION {_PG_FUNC}()",
]


def _is_file_backed() -> bool:
    try:
        return bool(get_storage().is_file_backed)
    except Exception:
        return True


# ==================================================================
# 安装 / 状态
# ==================================================================
def install_audit_protection(db_path: Optional[str] = None) -> Dict:
    """安装 WORM 保护（幂等）。返回安装后状态。"""
    if _is_file_backed():
        db = db_path or get_storage().db_path
        conn = sqlite3.connect(db)
        try:
            conn.executescript(_SQL_CREATE_UPDATE + _SQL_CREATE_DELETE)
            conn.commit()
        finally:
            conn.close()
        return protection_status(db)
    # PostgreSQL
    st = get_storage()
    with st._get_conn() as conn:  # type: ignore[attr-defined]
        for stmt in _PG_INSTALL_STATEMENTS:
            conn.execute(stmt)
    return protection_status()


def protection_status(db_path: Optional[str] = None) -> Dict:
    """查看 WORM 保护状态。"""
    if _is_file_backed():
        db = db_path or get_storage().db_path
        conn = sqlite3.connect(db)
        try:
            rows = conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall()
        finally:
            conn.close()
        names = {r[0] for r in rows}
        return {
            "installed": _UPDATE_TRIGGER in names and _DELETE_TRIGGER in names,
            "update_blocked": _UPDATE_TRIGGER in names,
            "delete_blocked": _DELETE_TRIGGER in names,
            "backend": "sqlite",
        }
    # PostgreSQL
    st = get_storage()
    try:
        with st._get_conn() as conn:  # type: ignore[attr-defined]
            rows = conn.execute(
                "SELECT tgname FROM pg_trigger WHERE tgrelid = 'audit_logs'::regclass AND NOT tgisinternal"
            ).fetchall()
        names = {r["tgname"] for r in rows}
    except Exception:
        names = set()
    return {
        "installed": _PG_TRIG_UPDATE in names and _PG_TRIG_DELETE in names,
        "update_blocked": _PG_TRIG_UPDATE in names,
        "delete_blocked": _PG_TRIG_DELETE in names,
        "backend": "postgres",
    }


# ==================================================================
# 归档
# ==================================================================
def archive_logs_before(cutoff_iso: str, archive_dir: Optional[str] = None) -> Dict:
    """把早于 cutoff 的审计日志归档为 JSONL（保留哈希链字段），返回归档信息。"""
    rows = get_storage().get_audit_logs_before(cutoff_iso)
    if not rows:
        return {"archived": 0, "path": None, "cutoff": cutoff_iso}
    out_dir = archive_dir or ARCHIVE_DIR
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out_dir, f"audit_archive_{stamp}.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")
    return {"archived": len(rows), "path": path, "cutoff": cutoff_iso}


def list_archives(archive_dir: Optional[str] = None) -> list:
    """列出归档文件（名/大小/时间），按时间倒序。"""
    out_dir = archive_dir or ARCHIVE_DIR
    if not os.path.isdir(out_dir):
        return []
    items = []
    for name in os.listdir(out_dir):
        if not name.endswith(".jsonl"):
            continue
        p = os.path.join(out_dir, name)
        try:
            stt = os.stat(p)
            items.append({"name": name, "size": stt.st_size,
                          "mtime": datetime.fromtimestamp(stt.st_mtime).isoformat()})
        except OSError:
            continue
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return items


def resolve_archive(name: str, archive_dir: Optional[str] = None) -> Optional[str]:
    """安全解析归档文件名 → 绝对路径（防目录穿越）。非法/不存在返回 None。"""
    if not name or "/" in name or "\\" in name or ".." in name or not name.endswith(".jsonl"):
        return None
    out_dir = os.path.abspath(archive_dir or ARCHIVE_DIR)
    path = os.path.abspath(os.path.join(out_dir, name))
    if not path.startswith(out_dir + os.sep) or not os.path.isfile(path):
        return None
    return path


# ==================================================================
# 留存：先归档，再在维护窗口内清理
# ==================================================================
def retention_archive_and_purge(days: int, archive_dir: Optional[str] = None) -> Dict:
    """留存策略：先归档超期日志，再临时移除 DELETE 保护后清理，随后恢复 WORM。

    返回 {"archived", "deleted", "path", "cutoff"}。
    """
    st = get_storage()
    cutoff = (datetime.now() - timedelta(days=int(days))).isoformat()
    arch = archive_logs_before(cutoff, archive_dir)
    if arch["archived"] == 0:
        return {"archived": 0, "deleted": 0, "path": None, "cutoff": cutoff}

    deleted = 0
    if _is_file_backed():
        db = st.db_path
        conn = sqlite3.connect(db)
        try:
            conn.execute(f"DROP TRIGGER IF EXISTS {_DELETE_TRIGGER}")
            cur = conn.execute("DELETE FROM audit_logs WHERE timestamp < ?", (cutoff,))
            deleted = cur.rowcount
            conn.executescript(_SQL_CREATE_DELETE)   # 恢复 WORM
            conn.commit()
        finally:
            conn.close()
    else:
        with st._get_conn() as conn:  # type: ignore[attr-defined]
            conn.execute(f"DROP TRIGGER IF EXISTS {_PG_TRIG_DELETE} ON audit_logs")
            cur = conn.execute("DELETE FROM audit_logs WHERE timestamp < %s", (cutoff,))
            deleted = cur.rowcount
            conn.execute(
                f"CREATE TRIGGER {_PG_TRIG_DELETE} BEFORE DELETE ON audit_logs "
                f"FOR EACH ROW EXECUTE FUNCTION {_PG_FUNC}()"
            )
    return {"archived": arch["archived"], "deleted": deleted, "path": arch["path"], "cutoff": cutoff}
