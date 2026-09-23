# ============================================================
# 业务治理服务 biz-service（Spring Boot）镜像 —— 阶段8 一键部署
# 构建: docker build -t safeagent-biz -f deploy/biz-service.Dockerfile .
#
# 免 Docker 内 Maven：jar 在宿主机构作（./mvnw -DskipTests package），
# 镜像仅含 JRE 运行时，构建快、攻击面小。
# ============================================================

FROM eclipse-temurin:17-jre

# healthcheck 需要 HTTP 客户端（基础镜像不含 curl/wget）
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 宿主机预构建的 jar（start.sh 会先执行 ./mvnw -DskipTests package）
COPY biz-service/target/biz-service-0.1.0.jar app.jar

# 生产随机口令/密钥文件落此目录（挂载 biz_data 卷导出）
RUN mkdir -p /app/data

EXPOSE 8300

ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
