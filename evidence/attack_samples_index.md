# 攻击样例库索引（供评测复现与材料核验）

> 共 335 条（攻击 275 / 正常 60），
> 覆盖 OWASP ASI 风险与政企场景，主文件位于 `ai_service/audit/attack_samples.json`。

## 按输入来源分布

| 输入来源 | 数量 |
|------|------|
| user_input | 254 |
| uploaded_doc | 30 |
| knowledge_retrieval | 24 |
| agent_memory | 14 |
| web_scrape | 13 |

## 按攻击类型分布

| 攻击类型 | 数量 |
|------|------|
| prompt_injection | 58 |
| None | 42 |
| data_leakage | 40 |
| command_injection | 38 |
| memory_poisoning | 21 |
| normal | 18 |
| content_injection | 17 |
| data_poisoning | 12 |
| skill_tampering | 12 |
| combined_attack | 12 |
| jailbreak | 11 |
| data_exfiltration | 9 |
| tool_descriptor_poisoning | 7 |
| content_safety | 6 |
| indirect_injection | 4 |
| mcp_poisoning | 4 |
| document_embedded_injection | 3 |
| unauthorized_access | 3 |
| privilege_escalation | 3 |
| network_attack | 2 |
| web_content_injection | 2 |
| hidden_text_steganography | 2 |
| excessive_agency | 2 |
| sql_injection | 2 |
| macro_injection | 1 |
| dde_injection | 1 |
| markdown_injection | 1 |
| data_destruction | 1 |
| gradual_escalation | 1 |

## 关键攻击类型示例 ID

- **combined_attack**：PL-018, PL-019, PL-023, PL-030, PL-031, PL-036, PL-040, RT-015
- **data_exfiltration**：CMD-004, RT-002, RT-004, RT-007, RT-013, CF-001, CF-005, CF-007
- **jailbreak**：PI-007, PI-009, BO-001, S-050, S-056, S-058, AV-008, MC-008
- **prompt_injection**：PI-001, PI-002, PI-003, PI-004, PI-005, PI-006, PI-008, PI-010