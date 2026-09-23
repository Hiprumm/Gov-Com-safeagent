#!/bin/sh
# ============================================================
# PostgreSQL 每日备份（pg-backup 容器入口）
#
# 由 deploy/docker-compose.yml 的 pg-backup 服务调用：
#   - 每 BACKUP_INTERVAL_SECONDS（默认 86400=每日）pg_dump 一次；
#   - 备份落 /backups 卷（宿主挂载 deploy/backups/）；
#   - 保留周期对齐审计留存 AUDIT_RETENTION_DAYS（默认 180 天），
#     到期自动清理，防磁盘涨满。
# 恢复示例：
#   gunzip -c /backups/safeagent-20260923-030000.sql.gz | \
#     docker exec -i safeagent-pg psql -U safeagent -d safeagent
# ============================================================
set -eu

PGHOST="${POSTGRES_HOST:-postgres}"
PGPORT="${POSTGRES_PORT:-5432}"
PGUSER="${POSTGRES_USER:-safeagent}"
PGDATABASE="${POSTGRES_DB:-safeagent}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-180}"
INTERVAL="${BACKUP_INTERVAL_SECONDS:-86400}"
BACKUP_DIR="/backups"

echo "[backup] started: db=${PGDATABASE} interval=${INTERVAL}s retention=${RETENTION_DAYS}d"

while true; do
    TS="$(date +%Y%m%d-%H%M%S)"
    FILE="${BACKUP_DIR}/${PGDATABASE}-${TS}.sql.gz"
    if pg_dump -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
        | gzip > "$FILE"; then
        SIZE="$(du -h "$FILE" | cut -f1)"
        echo "[backup] OK ${FILE} (${SIZE})"
        # 清理过期备份
        find "$BACKUP_DIR" -name "${PGDATABASE}-*.sql.gz" -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true
    else
        echo "[backup] FAILED at ${TS}（pg_dump 非零退出）" >&2
        rm -f "$FILE"
    fi
    sleep "$INTERVAL"
done
