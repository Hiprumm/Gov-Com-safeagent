package cn.safeagent.biz;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 业务治理服务（Spring Boot）入口。
 * 与 FastAPI AI 服务共享同一 SQLite 数据库，承接 auth/admin → governance/audit/config 业务域。
 */
@SpringBootApplication
public class BizServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(BizServiceApplication.class, args);
    }
}