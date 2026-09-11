#!/bin/sh
# ============================================================
# nginx 容器入口：若未提供正式证书，则自动生成自签证书，
# 保证 HTTPS(443) 开箱即用；有正式证书(server.crt/server.key)时跳过。
# 放到 deploy/certs/ 覆盖即换正式证书。
# ============================================================
set -e

CERTS_DIR=/etc/nginx/certs
if [ ! -f "$CERTS_DIR/server.crt" ] || [ ! -f "$CERTS_DIR/server.key" ]; then
  mkdir -p "$CERTS_DIR"
  echo "[nginx] 未找到正式证书，自动生成自签证书(仅限内网/测试，正式环境请替换)"
  openssl req -x509 -nodes -days 365 \
    -newkey rsa:2048 \
    -keyout "$CERTS_DIR/server.key" \
    -out "$CERTS_DIR/server.crt" \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=SafeAgent/OU=Ops/CN=localhost" >/dev/null 2>&1
fi

exec nginx -g 'daemon off;'