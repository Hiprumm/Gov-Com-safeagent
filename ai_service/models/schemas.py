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
    file_data: str
    file_type: str
    filename: str
    session_id: Optional[str] = None


class ToolCallRequest(BaseModel):
    tool_name: str
    tool_args: Dict[str, Any]
    user_role: str
    agent_id: str
    context: Optional[str] = None


class ToolRiskResult(BaseModel):
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