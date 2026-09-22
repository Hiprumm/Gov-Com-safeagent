package cn.safeagent.biz.common.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 应用配置：共享库路径、JWT 签名密钥文件、认证参数。
 */
@Component
@ConfigurationProperties(prefix = "app")
public class AppProperties {

    private final Db db = new Db();
    private final Jwt jwt = new Jwt();

    public Db getDb() { return db; }
    public Jwt getJwt() { return jwt; }

    public static class Db {
        private String path;
        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
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
}