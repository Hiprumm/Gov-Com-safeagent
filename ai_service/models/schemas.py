from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    DATA_LEAKAGE = "data_leakage"
    JAILBREAK = "jailbreak"
    DATA_POISONING = "data_poisoning"
    INDIRECT_INJECTION = "indirect_injection"
    STEGANOGRAPHY = "steganography"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_EXECUTION = "command_execution"
    PATH_TRAVERSAL = "path_traversal"
    CRLF_INJECTION = "crlf_injection"
    JSON_INJECTION = "json_injection"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    CONTENT_INJECTION = "content_injection"
    NETWORK_ATTACK = "network_attack"
    DATA_EXFILTRATION = "data_exfiltration"
    MEMORY_POISONING = "memory_poisoning"
    CONTEXT_POISONING = "context_poisoning"
    MCP_POISONING = "mcp_poisoning"
    SKILL_TAMPERING = "skill_tampering"
    TOOL_DESCRIPTOR_POISONING = "tool_descriptor_poisoning"
    COMBINED_ATTACK = "combined_attack"
    WEB_CONTENT_INJECTION = "web_content_injection"
    DOCUMENT_EMBEDDED_INJECTION = "document_embedded_injection"
    HIDDEN_TEXT_STEGANOGRAPHY = "hidden_text_steganography"
    MACRO_INJECTION = "macro_injection"
    DDE_INJECTION = "dde_injection"
    MARKDOWN_INJECTION = "markdown_injection"


class InputSource(str, Enum):
    USER_INPUT = "user_input"
    UPLOADED_DOC = "uploaded_doc"
    WEB_SCRAPE = "web_scrape"
    KNOWLEDGE_RETRIEVAL = "knowledge_retrieval"
    AGENT_MEMORY = "agent_memory"
    PLUGIN_OUTPUT = "plugin_output"


class DetectionResult(BaseModel):
    risk_level: RiskLevel
    attack_type: Optional[AttackType] = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: List[str] = []
    source: InputSource
    processed_text: Optional[str] = None


class BatchDetectionRequest(BaseModel):
    inputs: List[Dict[str, Any]] = Field(
        ...,
        description="List of inputs to detect, each with 'text' and 'source' fields"
    )


class BatchDetectionResponse(BaseModel):
    results: List[DetectionResult]
    timestamp: datetime = Field(default_factory=datetime.now)


class FileDetectionRequest(BaseModel):
    file_data: str
    file_type: str
    filename: str


class FileUploadRequest(BaseModel):
    # 兼容单文件上传（历史调用：如编辑图片重传走 file_upload 单文件）
    file_data: Optional[str] = None
    file_type: Optional[str] = None
    filename: Optional[str] = None
    # 多文件上传：优先使用 files 列表（智能问答多附件）
    files: Optional[List[FileDetectionRequest]] = None
    session_id: Optional[str] = None
    user_text: Optional[str] = None


class ToolCallRequest(BaseModel):
    tool_name: str
    tool_args: Dict[str, Any]
    user_role: str
    agent_id: str
    context: Optional[str] = None


class ToolRiskResult(BaseModel):
    tool_name: str = ""
    risk_level: RiskLevel
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_details: List[str] = []
    requires_approval: bool = False
    approval_level: Optional[str] = None


class PluginScanRequest(BaseModel):
    plugin_name: Optional[str] = None
    plugin_version: Optional[str] = None
    filename: Optional[str] = None
    file_type: Optional[str] = None
    code_content: Optional[str] = None


class PluginVulnerability(BaseModel):
    vulnerability_id: str
    severity: RiskLevel
    description: str
    location: str
    line_number: Optional[int] = None


class PluginScanResult(BaseModel):
    plugin_name: str
    plugin_version: str
    safety_score: int = Field(ge=0, le=100)
    safety_grade: str = "A"
    vulnerabilities: List[PluginVulnerability] = []
    is_safe: bool
    scan_details: Dict[str, Any] = {}


class AuditLog(BaseModel):
    log_id: str
    timestamp: datetime = Field(default_factory=datetime.now)
    user_id: str
    user_role: str
    agent_id: str
    action_type: str
    action_details: Dict[str, Any] = {}
    risk_level: RiskLevel
    detection_result: Optional[DetectionResult] = None
    tool_call_result: Optional[ToolRiskResult] = None
    plugin_scan_result: Optional[PluginScanResult] = None
    approval_status: Optional[str] = None
    is_blocked: bool = False
    blocking_reason: Optional[str] = None
    # 审计完整性扩展：会话ID、Think原文、返回值（不丢失推理阶段内容）
    session_id: str = ""
    think_text: str = ""
    return_value: str = ""
    # 等保2.0审计要素：操作主体/客体/时间/结果/来源IP
    source_ip: str = ""
    operation_subject: str = ""    # 操作主体（用户/角色）
    operation_object: str = ""     # 操作客体（工具/资源）
    operation_result: str = ""     # 操作结果（success/blocked/approved/timeout）
    # 日志防篡改：哈希链 + 签名
    log_hash: str = ""             # 当前日志哈希
    prev_hash: str = ""            # 前一条日志哈希
    signature: str = ""            # HMAC签名


class EvaluationMetrics(BaseModel):
    attack_detection_accuracy: float = Field(ge=0.0, le=1.0)
    false_positive_rate: float = Field(ge=0.0, le=1.0)
    false_negative_rate: float = Field(ge=0.0, le=1.0)
    tool_block_success_rate: float = Field(ge=0.0, le=1.0)
    plugin_vulnerability_detection_rate: float = Field(ge=0.0, le=1.0)
    risk_level_match_accuracy: float = Field(ge=0.0, le=1.0)
    total_samples: int
    detected_attacks: int
    blocked_tool_calls: int
    detected_vulnerabilities: int


class ApprovalRequest(BaseModel):
    request_id: str
    user_id: str
    user_role: str
    agent_id: str
    action_type: str
    action_details: Dict[str, Any] = {}
    risk_level: RiskLevel
    requested_at: datetime = Field(default_factory=datetime.now)
    status: str = "pending"


class ApprovalResponse(BaseModel):
    request_id: str
    status: str
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    comments: Optional[str] = None