package cn.safeagent.biz.common.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 应用配置：数据库类型/路径（sqlite 文件或 postgres 连接）、JWT 签名密钥文件、认证参数。
 */
@Component
@ConfigurationProperties(prefix = "app")
public class AppProperties {

    private final Db db = new Db();
    private final Jwt jwt = new Jwt();
    private final Security security = new Security();

    public Db getDb() { return db; }
    public Jwt getJwt() { return jwt; }
    public Security getSecurity() { return security; }

    public static class Db {
        /** 数据库类型：sqlite（默认，共享 .db 文件）| postgres（生产 compose，与 ai_service STORAGE_BACKEND=postgres 对齐） */
        private String type = "sqlite";
        private String path;
        private final Pg pg = new Pg();

        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        public Pg getPg() { return pg; }

        /** PostgreSQL 连接参数（仅 type=postgres 时生效），默认值对齐 deploy compose */
        public static class Pg {
            private String host = "postgres";
            private int port = 5432;
            private String db = "safeagent";
            private String user = "safeagent";
            private String password = "safeagent";

            public String getHost() { return host; }
            public void setHost(String host) { this.host = host; }
            public int getPort() { return port; }
            public void setPort(int port) { this.port = port; }
            public String getDb() { return db; }
            public void setDb(String db) { this.db = db; }
            public String getUser() { return user; }
            public void setUser(String user) { this.user = user; }
            public String getPassword() { return password; }
            public void setPassword(String password) { this.password = password; }
        }
    }

    public static class Jwt {
        private String secretFile;
        private int ttlSeconds = 28800;
        private int maxLoginFails = 5;
        private int loginLockSeconds = 300;

        public String getSecretFile() { return secretFile; }
        public void setSecretFile(String secretFile) { this.secretFile = secretFile; }
        public int getTtlSeconds() { return ttlSeconds; }
        public void setTtlSeconds(int ttlSeconds) { this.ttlSeconds = ttlSeconds; }
        public int getMaxLoginFails() { return maxLoginFails; }
        public void setMaxLoginFails(int maxLoginFails) { this.maxLoginFails = maxLoginFails; }
        public int getLoginLockSeconds() { return loginLockSeconds; }
        public void setLoginLockSeconds(int loginLockSeconds) { this.loginLockSeconds = loginLockSeconds; }
    }

    /** 登录口令 RSA 传输加密密钥 */
    public static class Security {
        private String loginRsaFile = "";
        public String getLoginRsaFile() { return loginRsaFile; }
        public void setLoginRsaFile(String loginRsaFile) { this.loginRsaFile = loginRsaFile; }
    }
}