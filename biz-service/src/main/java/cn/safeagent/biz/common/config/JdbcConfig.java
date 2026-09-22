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
 * 共享库数据访问：sqlite-jdbc → HikariCP 连接池 → JdbcTemplate。
 * 与 FastAPI (ai_service/storage.py) 指向同一个 .db 文件。
 */
@Configuration
public class JdbcConfig {

    @Bean
    public DataSource dataSource(AppProperties props) throws Exception {
        String dbPath = props.getDb().getPath();
        Path dir = Paths.get(dbPath).toAbsolutePath().getParent();
        if (dir != null) Files.createDirectories(dir);

        HikariConfig cfg = new HikariConfig();
        cfg.setDriverClassName("org.sqlite.JDBC");
        cfg.setJdbcUrl("jdbc:sqlite:" + dbPath);
        cfg.setMaximumPoolSize(5);
        cfg.setMinimumIdle(1);
        // SQLite 单写者：连接池内复用 + PRAGMA busy_timeout 规避瞬时 SQLITE_BUSY
        cfg.setConnectionInitSql("PRAGMA busy_timeout=10000; PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;");
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
}