"""
分级审计签名器 + 批量 TSA 客户端（创新点3升级版）

升级优化（相对原 audit_logger 全量 HMAC 方案）：
1. 分级签名：仅对高敏感动作（写操作/命令执行/网络外发）生成 ZKP 证明
   读操作仅用 HMAC + TSA，降低 ZKP 计算开销
2. 批量 TSA：按时间窗口（T 秒）或条数（N 条）合并请求第三方时间戳
   降低网络往返开销，同时保留第三方不可抵赖性
3. Agent 身份签名：每个 Agent 实例启动时生成密钥对，动作以私钥签名

参考：
- AffixIO WP-015 (2026) — ZKP 链用于 Agent 治理
- RFC 3161 — 时间戳协议
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List
from datetime import datetime


class SensitivityLevel(str, Enum):
    """动作敏感度分级 — 决定签名强度"""
    LOW = "low"          # 只读操作 → 仅 HMAC + TSA
    MEDIUM = "medium"   # 本地写入 → HMAC + TSA + Agent 签名
    HIGH = "high"       # 命令执行/网络外发/DB写入 → HMAC + TSA + Agent 签名 + ZKP 证明


class AuditActionType(str, Enum):
    READ = "read"
    WRITE_LOCAL = "write_local"
    WRITE_REMOTE = "write_remote"
    EXECUTE = "execute"
    NETWORK = "network"
    APPROVAL = "approval"


# 动作类型 → 敏感度映射
SENSITIVITY_MAP = {
    AuditActionType.READ: SensitivityLevel.LOW,
    AuditActionType.WRITE_LOCAL: SensitivityLevel.MEDIUM,
    AuditActionType.WRITE_REMOTE: SensitivityLevel.HIGH,
    AuditActionType.EXECUTE: SensitivityLevel.HIGH,
    AuditActionType.NETWORK: SensitivityLevel.HIGH,
    AuditActionType.APPROVAL: SensitivityLevel.MEDIUM,
}


@dataclass
class SignedAuditRecord:
    """分级签名的审计记录"""
    log_id: str
    timestamp: str
    sensitivity: SensitivityLevel
    content_hash: str          # SHA-256 内容哈希
    prev_hash: str             # 哈希链前驱
    hmac_signature: str        # HMAC-SHA256 签名（所有级别）
    agent_signature: str = ""  # Agent 私钥签名（MEDIUM/HIGH）
    zkp_proof: str = ""        # 零知识证明（仅 HIGH）
    tsa_token: str = ""        # RFC 3161 时间戳令牌（批量获取后填充）
    tsa_requested_at: str = ""


class AgentIdentity:
    """Agent 身份密钥对管理 — 启动时生成，动作以私钥签名"""

    def __init__(self, agent_id: str, key_store_path: Optional[str] = None):
        self.agent_id = agent_id
        self._key_store_path = key_store_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", f"agent_identity_{agent_id}.key"
        )
        self._private_key, self._public_key = self._load_or_create_keys()

    def _load_or_create_keys(self):
        """加载或生成 Ed25519 密钥对（轻量级，适合 Agent 启动）"""
        key_dir = os.path.dirname(self._key_store_path)
        if not os.path.isdir(key_dir):
            os.makedirs(key_dir, exist_ok=True)

        if os.path.isfile(self._key_store_path):
            with open(self._key_store_path, "r") as f:
                data = json.load(f)
                return data["private"], data["public"]

        # 生成密钥对（模拟 Ed25519 — 实际生产应使用 cryptography 库）
        private_key = secrets.token_hex(32)
        public_key = hashlib.sha256(private_key.encode()).hexdigest()
        with open(self._key_store_path, "w") as f:
            json.dump({"private": private_key, "public": public_key,
                       "created_at": datetime.now().isoformat()}, f)
        return private_key, public_key

    def sign(self, message: str) -> str:
        """用私钥签名消息（HMAC 模拟 Ed25519 签名）"""
        return hmac.new(self._private_key.encode(), message.encode(), hashlib.sha256).hexdigest()

    def public_key(self) -> str:
        return self._public_key

    def verify(self, message: str, signature: str) -> bool:
        expected = self.sign(message)
        return hmac.compare_digest(expected, signature)


# 方向A-6：持久化密钥文件（多 AuditLogger 实例共享同一套密钥，保证 sign/verify 一致）
_GRADED_HMAC_KEY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "graded_hmac.key",
)
_ZKP_PROVING_KEY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "zkp_proving.key",
)


def _load_or_create_hex_key(path: str) -> str:
    """从文件加载或生成 hex 密钥（多实例共享，保证 sign/verify 一致）"""
    key_dir = os.path.dirname(path)
    if not os.path.isdir(key_dir):
        os.makedirs(key_dir, exist_ok=True)
    if not os.path.isfile(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path, "r") as f:
        return f.read().strip()


class ZKPProver:
    """零知识证明生成器（轻量级模拟实现）

    生产环境应使用 snarkjs + zk-SNARK 电路。此处用"承诺+响应"机制模拟，
    验证方可在不知具体内容的情况下确认动作合规性。

    仅对 HIGH 敏感度动作生成证明，降低计算开销。
    """

    def __init__(self, proving_key: Optional[str] = None):
        # 方向A-6：未显式传入则从文件加载持久化密钥（多实例共享）
        self._proving_key = proving_key or _load_or_create_hex_key(_ZKP_PROVING_KEY_FILE)
        self._proof_count = 0

    def prove(self, content_hash: str, agent_signature: str,
              policy_id: str = "default_policy") -> str:
        """生成 ZKP 证明 — 绑定内容哈希、Agent 签名、策略范围

        证明语义：在某策略下，某 Agent 对某内容进行了授权签名，
        但不暴露具体内容或 Agent 私钥。
        """
        self._proof_count += 1
        # 承诺：哈希(content_hash || agent_signature || policy_id || proving_key)
        commitment = hashlib.sha256(
            f"{content_hash}|{agent_signature}|{policy_id}|{self._proving_key}".encode()
        ).hexdigest()
        # 响应：HMAC(proving_key, commitment)
        response = hmac.new(
            self._proving_key.encode(), commitment.encode(), hashlib.sha256
        ).hexdigest()
        # 证明 = 承诺前16位 + 响应前32位（轻量级，可验证）
        return f"zkp:{commitment[:16]}:{response[:32]}"

    def verify(self, proof: str, content_hash: str, agent_signature: str,
               policy_id: str = "default_policy") -> bool:
        """验证 ZKP 证明"""
        try:
            parts = proof.split(":")
            if len(parts) != 3 or parts[0] != "zkp":
                return False
            expected = self.prove(content_hash, agent_signature, policy_id)
            return hmac.compare_digest(expected, proof)
        except Exception:
            return False

    def stats(self) -> Dict[str, int]:
        return {"proofs_generated": self._proof_count}


class BatchTsaClient:
    """批量 TSA 客户端 — 按时间窗口或条数合并请求第三方时间戳

    升级优化：原方案每条日志请求一次 TSA（N 条 = N 次网络往返）
    批量方案：每 T 秒或 N 条合并一次，网络往返降至 1 次

    生产环境应对接 DigiCert/Sectigo 等符合 RFC 3161 的 TSA。
    此处提供离线回退（本地时间 + 校验和），保证无网络时仍可用。
    """

    def __init__(self, tsa_url: Optional[str] = None,
                 batch_size: int = 10, batch_window_s: float = 2.0):
        self.tsa_url = tsa_url
        self.batch_size = batch_size
        self.batch_window_s = batch_window_s
        self._pending: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._last_flush = time.time()
        self._request_count = 0  # 网络请求次数（性能指标）
        self._records_count = 0  # 处理记录数

    def submit(self, log_id: str, content_hash: str) -> None:
        """提交记录等待批量时间戳"""
        with self._lock:
            self._pending.append({
                "log_id": log_id,
                "content_hash": content_hash,
                "submitted_at": datetime.now().isoformat(),
            })
            self._records_count += 1

    def flush_if_ready(self) -> int:
        """若达到批量条件则请求时间戳，返回处理条数"""
        with self._lock:
            should_flush = (
                len(self._pending) >= self.batch_size or
                (self._pending and time.time() - self._last_flush >= self.batch_window_s)
            )
            if not should_flush:
                return 0
            # 仅取 batch_size 条，剩余留在 pending（符合批量语义）
            batch = self._pending[:self.batch_size]
            self._pending = self._pending[self.batch_size:]
            self._last_flush = time.time()

        if not batch:
            return 0

        # 批量请求（实际环境应调用 TSA API）
        tokens = self._request_tsa_batch(batch)
        return len(tokens)

    def _request_tsa_batch(self, batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """批量请求 TSA — 一次网络往返处理 N 条"""
        self._request_count += 1  # 仅 1 次网络请求
        results = []
        for item in batch:
            if self.tsa_url:
                # 生产环境：requests.post(self.tsa_url, data=...) 获取真实令牌
                token = f"tsa:{hashlib.sha256(item['content_hash'].encode()).hexdigest()[:24]}"
            else:
                # 离线回退：本地时间 + 内容哈希（弱保证，仅在无 TSA 时用）
                token = f"local-ts:{datetime.now().isoformat()}:{item['content_hash'][:16]}"
            results.append({"log_id": item["log_id"], "tsa_token": token})
        return results

    def stats(self) -> Dict[str, Any]:
        return {
            "network_requests": self._request_count,
            "records_processed": self._records_count,
            "avg_batch_size": round(self._records_count / max(1, self._request_count), 2),
            "pending": len(self._pending),
        }


class GradedAuditSigner:
    """分级审计签名器 — 整合 HMAC / Agent 签名 / ZKP / 批量 TSA"""

    def __init__(self, agent_identity: AgentIdentity,
                 zkp_prover: Optional[ZKPProver] = None,
                 tsa_client: Optional[BatchTsaClient] = None,
                 hmac_key: Optional[bytes] = None):
        self.agent = agent_identity
        self.zkp = zkp_prover or ZKPProver()
        self.tsa = tsa_client or BatchTsaClient()
        # 方向A-6：未显式传入则从文件加载持久化密钥（多实例共享，保证 sign/verify 一致）
        if hmac_key is None:
            self._hmac_key = _load_or_create_hex_key(_GRADED_HMAC_KEY_FILE).encode()
        else:
            self._hmac_key = hmac_key

    def get_sensitivity(self, action_type: AuditActionType) -> SensitivityLevel:
        return SENSITIVITY_MAP.get(action_type, SensitivityLevel.LOW)

    def sign_record(self, log_id: str, timestamp: str, prev_hash: str,
                    content: Dict[str, Any],
                    action_type: AuditActionType) -> SignedAuditRecord:
        """根据敏感度分级签名"""
        content_str = json.dumps(content, sort_keys=True, ensure_ascii=False, default=str)
        content_hash = hashlib.sha256(content_str.encode("utf-8")).hexdigest()
        sensitivity = self.get_sensitivity(action_type)

        # 1. HMAC 签名（所有级别）
        hmac_sig = hmac.new(
            self._hmac_key, content_hash.encode(), hashlib.sha256
        ).hexdigest()

        # 2. Agent 签名（MEDIUM/HIGH）
        agent_sig = ""
        if sensitivity in (SensitivityLevel.MEDIUM, SensitivityLevel.HIGH):
            agent_sig = self.agent.sign(content_hash)

        # 3. ZKP 证明（仅 HIGH）
        zkp_proof = ""
        if sensitivity == SensitivityLevel.HIGH:
            zkp_proof = self.zkp.prove(content_hash, agent_sig)

        # 4. TSA 提交（批量，异步）
        self.tsa.submit(log_id, content_hash)
        tsa_requested_at = datetime.now().isoformat()

        return SignedAuditRecord(
            log_id=log_id,
            timestamp=timestamp,
            sensitivity=sensitivity,
            content_hash=content_hash,
            prev_hash=prev_hash,
            hmac_signature=hmac_sig,
            agent_signature=agent_sig,
            zkp_proof=zkp_proof,
            tsa_requested_at=tsa_requested_at,
        )

    def verify_record(self, record: SignedAuditRecord,
                      content: Dict[str, Any]) -> bool:
        """验证分级签名记录完整性"""
        content_str = json.dumps(content, sort_keys=True, ensure_ascii=False, default=str)
        content_hash = hashlib.sha256(content_str.encode("utf-8")).hexdigest()

        # 1. 内容哈希校验
        if content_hash != record.content_hash:
            return False

        # 2. HMAC 签名校验
        expected_hmac = hmac.new(
            self._hmac_key, content_hash.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected_hmac, record.hmac_signature):
            return False

        # 3. Agent 签名校验（MEDIUM/HIGH）
        if record.sensitivity in (SensitivityLevel.MEDIUM, SensitivityLevel.HIGH):
            if not record.agent_signature:
                return False
            if not self.agent.verify(content_hash, record.agent_signature):
                return False

        # 4. ZKP 校验（仅 HIGH）
        if record.sensitivity == SensitivityLevel.HIGH:
            if not record.zkp_proof:
                return False
            if not self.zkp.verify(record.zkp_proof, content_hash, record.agent_signature):
                return False

        return True

    def stats(self) -> Dict[str, Any]:
        return {
            "zkp": self.zkp.stats(),
            "tsa": self.tsa.stats(),
        }
