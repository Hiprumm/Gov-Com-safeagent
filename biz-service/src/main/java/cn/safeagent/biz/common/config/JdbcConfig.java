package cn.safeagent.biz.common.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import javax.sql.DataSource;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 共享库数据访问：HikariCP 连接池 → JdbcTemplate。
 * 按 app.db.type 双数据源：sqlite 指向与 FastAPI (ai_service/storage.py) 同一个 .db 文件；
 * postgres 连接生产容器（与 ai_service STORAGE_BACKEND=postgres 同库，避免数据分裂）。
 */
@Configuration
public class JdbcConfig {

    @Bean
    public DataSource dataSource(AppProperties props) throws Exception {
        HikariConfig cfg = new HikariConfig();
        cfg.setMaximumPoolSize(5);
        cfg.setMinimumIdle(1);

        if (isPostgres(props)) {
            AppProperties.Db.Pg pg = props.getDb().getPg();
            cfg.setDriverClassName("org.postgresql.Driver");
            cfg.setJdbcUrl("jdbc:postgresql://" + pg.getHost() + ":" + pg.getPort() + "/" + pg.getDb());
            cfg.setUsername(pg.getUser());
            cfg.setPassword(pg.getPassword());
            // PG 长连接可能被服务端/防火墙静默回收：借出前探活，避免空闲后拿到死链
            cfg.setConnectionTestQuery("SELECT 1");
        } else {
            String dbPath = props.getDb().getPath();
            Path dir = Paths.get(dbPath).toAbsolutePath().getParent();
            if (dir != null) Files.createDirectories(dir);
            cfg.setDriverClassName("org.sqlite.JDBC");
            cfg.setJdbcUrl("jdbc:sqlite:" + dbPath);
            // SQLite 单写者：连接池内复用 + PRAGMA busy_timeout 规避瞬时 SQLITE_BUSY
            cfg.setConnectionInitSql("PRAGMA busy_timeout=10000; PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;");
        }
        return new HikariDataSource(cfg);
    }

    @Bean
    public JdbcTemplate jdbcTemplate(DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }

    @Bean
    public NamedParameterJdbcTemplate namedParameterJdbcTemplate(DataSource dataSource) {
        return new NamedParameterJdbcTemplate(dataSource);
    }

    /** 是否使用 PostgreSQL 数据源（app.db.type=postgres） */
    public static boolean isPostgres(AppProperties props) {
        return "postgres".equalsIgnoreCase(props.getDb().getType());
    }
}
