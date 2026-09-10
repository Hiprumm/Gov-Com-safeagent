# -*- coding: utf-8 -*-
"""PostgreSQL 存储后端集成测试（可选）

用途：验证 `PostgresStorage` 与 SQLite 后端行为一致。**无 PG / 无驱动时自动跳过**，不影响 CI。

运行前提（三选一即可）：
1) 在 .env 配置 `POSTGRES_DSN`（推荐），例如：
   POSTGRES_DSN=postgresql://safeagent:pwd@localhost:5432/safeagent
2) 或配置 POSTGRES_HOST/PORT/DB/USER/PASSWORD；
3) 并安装驱动： pip install "psycopg[binary]"

运行： python test_postgres_backend.py
测试会在目标实例上**创建一个临时库 safeagent_selftest**（需 CREATEDB 权限），
跑完自动 DROP，保持环境干净；若权限不足则跳过并提示。
"""
import os
import sys
import traceback

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.getcwd())

TEST_DB = "safeagent_selftest"


def _skip(msg: str) -> None:
    print(f"[SKIP] {msg}")
    sys.exit(0)


def main() -> None:
    try:
        import psycopg
    except Exception:
        _skip("未安装 psycopg（pip install 'psycopg[binary]'）")

    from postgres_storage import _build_dsn
    from config import settings

    base_dsn = _build_dsn()
    if not base_dsn.strip():
        _skip("未配置 PostgreSQL 连接（POSTGRES_DSN / POSTGRES_*）")

    # 连接到维护库（postgres）以创建/删除测试库
    import psycopg as _pg
    from psycopg.rows import dict_row

    parts = {
        "user": getattr(settings, "POSTGRES_USER", "safeagent"),
        "password": getattr(settings, "POSTGRES_PASSWORD", ""),
        "host": getattr(settings, "POSTGRES_HOST", "localhost"),
        "port": int(getattr(settings, "POSTGRES_PORT", 5432) or 5432),
    }
    try:
        admin = _pg.connect(dbname="postgres", connect_timeout=4, **parts)
    except Exception as e:
        _skip(f"无法连接 PostgreSQL：{type(e).__name__}: {str(e)[:120]}")

    created = False
    try:
        admin.autocommit = True
        with admin.cursor() as cur:
            cur.execute(f"DROP DATABASE IF EXISTS {TEST_DB}")
            cur.execute(f"CREATE DATABASE {TEST_DB}")
        created = True
    except Exception as e:
        print(f"[SKIP] 无权限创建测试库（需 CREATEDB）：{type(e).__name__}: {str(e)[:120]}")
        admin.close()
        sys.exit(0)
    finally:
        if not created:
            try:
                admin.close()
            except Exception:
                pass

    test_dsn = (
        f"host={parts['host']} port={parts['port']} dbname={TEST_DB} "
        f"user={parts['user']} password={parts['password']}"
    )

    ok = True
    try:
        from postgres_storage import PostgresStorage
        st = PostgresStorage(dsn=test_dsn)
        assert st.is_file_backed is False

        # 会话幂等
        sid = st.ensure_session("pg-sess-1")
        assert st.get_session(sid) is not None
        st.ensure_session("pg-sess-1")

        # 审计追加 + WORM
        st.save_audit_log({"log_id": "pg-log-1", "timestamp": __import__("datetime").datetime.now().isoformat(),
                           "user_id": "tester", "user_role": "user", "agent_id": "pgtest",
                           "action_type": "pg_probe", "action_details": {"k": 1}, "risk_level": "low",
                           "is_blocked": True, "extra_data": {"log_hash": "h"}})
        last = st.get_last_audit_log()
        assert last["user_id"] == "tester" and last["is_blocked"] is True and last["action_details"]["k"] == 1
        assert st.count_audit_logs() == 1

        # 用户/部门/设置/审批/通知
        st.add_department("PG自测部门")
        assert "PG自测部门" in st.list_departments()
        st.upsert_user("pg_user", "h", "s", "PG用户", "user", "PG自测部门", "", "active", "")
        assert st.user_exists("pg_user") and st.get_user("pg_user")["role"] == "user"
        # MFA TOTP 密钥：加密入库 + 透明解密（PG 分支）
        from security.secret_box import is_encrypted
        st.set_user_mfa("pg_user", "JBSWY3DPEHPK3PXP", True)
        with st._get_conn() as conn:
            _row = conn.execute(
                "SELECT totp_secret FROM sys_users WHERE username = %s", ("pg_user",)
            ).fetchone()
        raw_secret = _row["totp_secret"] if hasattr(_row, "keys") else _row[0]
        assert is_encrypted(raw_secret), f"TOTP 未加密入库: {str(raw_secret)[:24]}"
        mfa = st.get_user_mfa("pg_user")
        assert mfa["totp_secret"] == "JBSWY3DPEHPK3PXP" and mfa["mfa_enabled"] is True
        st.set_setting("pg_kv", {"a": 1})
        assert st.get_setting("pg_kv") == {"a": 1}
        now = __import__("datetime").datetime.now().isoformat()
        st.create_approval({"request_id": "APR_PG", "tool_name": "t", "tool_args": {"x": 1},
                            "risk_level": "medium", "requester_id": "pg_user", "requester_role": "user",
                            "required_role": "manager", "status": "pending", "reason": "",
                            "created_at": now, "updated_at": now})
        assert st.get_approval("APR_PG")["tool_args"] == {"x": 1}
        st.update_approval("APR_PG", "approved", "admin", "admin", "ok")
        assert st.get_approval("APR_PG")["status"] == "approved"
        nid = st.add_notification("info", "t", "m", "info")
        assert nid is not None and st.count_unread_notifications() == 1
        st.mark_notifications_read(nid)
        assert st.count_unread_notifications() == 0

        print("[PASS] PostgreSQL 后端核心功能验证通过")
    except AssertionError as e:
        ok = False
        print(f"[FAIL] 断言失败: {e}")
    except Exception:
        ok = False
        print("[FAIL] 异常:\n" + traceback.format_exc())
    finally:
        try:
            admin = _pg.connect(dbname="postgres", connect_timeout=4, **parts)
            admin.autocommit = True
            with admin.cursor() as cur:
                cur.execute(f"DROP DATABASE IF EXISTS {TEST_DB}")
            admin.close()
            print(f"[CLEAN] 已删除测试库 {TEST_DB}")
        except Exception as e:
            print(f"[WARN] 清理测试库失败：{str(e)[:120]}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
