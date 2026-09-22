package cn.safeagent.biz.audit;

import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 审计域服务：治理动作写审计（表归属 Spring）+ 读取端的 ABAC 数据范围收敛。
 * 对齐 Python permission_engine 的 DATA_SCOPE_BY_ROLE 与 row_visible。
 */
@Service
public class AuditService {

    private final AuditRepository repo;

    public AuditService(AuditRepository repo) {
        this.repo = repo;
    }

    /** 治理动作落审计 */
    public void record(String actionType, String operator, String details) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("detail", details);
        repo.append(actionType, operator, "high", d);
    }

    /** ABAC：登录身份的数据范围 all / dept / self（与 DATA_SCOPE_BY_ROLE 一致） */
    public String dataScope(Map<String, Object> identity) {
        if (identity == null) return "self";
        String role = String.valueOf(identity.get("role") == null ? "" : identity.get("role")).trim().toLowerCase();
        return switch (role) {
            case "admin", "operator", "auditor" -> "all";
            case "manager" -> "dept";
            default -> "self";
        };
    }

    /** 逐行可见性判定（对齐 row_visible） */
    public boolean rowVisible(String scope, Map<String, Object> subject, Map<String, Object> row) {
        if ("all".equals(scope)) return true;
        String rowUser = String.valueOf(row.get("user_id") == null ? "" : row.get("user_id"));
        String subjectUser = subject == null ? "" : String.valueOf(subject.get("username") == null ? "" : subject.get("username"));
        if ("self".equals(scope)) {
            return !rowUser.isEmpty() && rowUser.equals(subjectUser);
        }
        if ("dept".equals(scope)) {
            String dept = subject == null ? "" : String.valueOf(subject.get("department") == null ? "" : subject.get("department"));
            return !dept.isEmpty() && !rowUser.isEmpty();
        }
        return false;
    }

    public List<Map<String, Object>> filterByScope(String scope, Map<String, Object> subject, List<Map<String, Object>> rows) {
        if ("all".equals(scope)) return rows;
        return rows.stream().filter(r -> rowVisible(scope, subject, r)).toList();
    }
}