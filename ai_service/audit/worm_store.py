# -*- coding: utf-8 -*-
"""WORM（Write Once Read Many）审计锚定存储 —— 阶段5 审计链生产化

解决的问题：数据库内哈希链能防"内容篡改"，但持有库写权限者仍可能整体重写。
WORM 存储把审计记录摘要锚定到独立 append-only 介质，形成第二重不可篡改证据链：

- LocalHashChainWormStore：本地 append-only 哈希链文件 data/worm_anchor.jsonl
  （相对 ai_service/）。每行一条 JSON 记录，line_hash = sha256(seq|ts|log_id|digest|prev_hash)，
  genesis（首条）prev_hash = "0"*64；文件以追加模式打开，**绝不在中间插入/改写**。
- S3ObjectLockWormStore：S3 Object Lock（合规保留模式）生产接入点（预留）。

并发安全：双平台文件锁（Windows msvcrt.locking / POSIX fcntl.flock）+ 进程内互斥锁，
保证多进程/多线程并发 anchor 时 seq 与 prev_hash 严格递增、链不断裂。

后端选择：模块级单例 get_worm_store()，优先读环境变量 WORM_BACKEND（local|s3，默认 local）。
"""
import hashlib
import json
import os
import threading
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional

try:  # 双平台文件锁：Windows 用 msvcrt，POSIX 用 fcntl（参考常见跨平台写法）
    import msvcrt
    _HAS_MSVCRT = True
except ImportError:  # pragma: no cover - 非 Windows 平台
    import fcntl
    _HAS_MSVCRT = False

# WORM 锚定文件路径（相对 ai_service/，与其他审计数据同住 data/ 目录）
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORM_FILE = os.path.join(_BASE_DIR, "data", "worm_anchor.jsonl")

# 创世块（首条记录）的 prev_hash：全零占位，锚定链起点
GENESIS_PREV_HASH = "0" * 64


def _compute_line_hash(seq: int, ts: str, log_id: str, digest: str, prev_hash: str) -> str:
    """行哈希：sha256(seq|ts|log_id|digest|prev_hash) —— 与文件逐行格式严格对应"""
    raw = f"{seq}|{ts}|{log_id}|{digest}|{prev_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _lock_file(f) -> None:
    """跨进程排他锁：Windows 锁文件头 1 字节区域；POSIX flock 整文件排他。"""
    if _HAS_MSVCRT:
        f.seek(0)  # msvcrt.locking 作用于当前文件指针位置，锁定/解锁前须先归零
        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
    else:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)


def _unlock_file(f) -> None:
    """释放跨进程锁（与 _lock_file 对应）。"""
    if _HAS_MSVCRT:
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)


class WormStore(ABC):
    """WORM 存储抽象基类：锚定审计记录摘要并验证锚定链完整性。"""

    @abstractmethod
    def anchor(self, log_id: str, digest: str) -> bool:
        """锚定一条审计记录（写入即不可改写），成功返回 True。"""

    @abstractmethod
    def verify_chain(self) -> Dict:
        """验证锚定链完整性，返回 {valid, checked, first_bad_seq}。"""

    @abstractmethod
    def size(self) -> int:
        """返回已锚定记录条数。"""


class LocalHashChainWormStore(WormStore):
    """本地 append-only 哈希链 WORM 存储（data/worm_anchor.jsonl）。

    每行 JSON：{"seq": n, "ts": iso, "log_id": "...", "digest": "...",
                "prev_hash": "...", "line_hash": "sha256(seq|ts|log_id|digest|prev_hash)"}
    - genesis prev_hash = "0"*64；
    - 写入只以追加模式（"a"/"a+"）进行，绝不中间插入/改写；
    - 锁内"读末条 → 推导 seq/prev_hash → 追加"，跨进程用文件锁、进程内用线程锁。
    """

    def __init__(self, path: str = WORM_FILE):
        self._path = path
        self._io_lock = threading.Lock()  # 进程内互斥（跨进程靠文件锁）

    # ------------------------------------------------------------------
    # 锚定（append-only 写入）
    # ------------------------------------------------------------------
    def anchor(self, log_id: str, digest: str) -> bool:
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            with self._io_lock:
                # "a+"：写恒在文件末尾（append 语义），锁内先读末条再追加
                with open(self._path, "a+", encoding="utf-8") as f:
                    _lock_file(f)
                    try:
                        f.seek(0)
                        last = None
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                rec = json.loads(line)
                                if isinstance(rec, dict) and "seq" in rec:
                                    last = rec
                            except (ValueError, TypeError):
                                continue  # 坏行不阻断追加（verify_chain 会标记）
                        seq = int(last["seq"]) + 1 if last else 1
                        prev_hash = (last or {}).get("line_hash") or GENESIS_PREV_HASH
                        ts = datetime.now().isoformat()
                        record = {
                            "seq": seq,
                            "ts": ts,
                            "log_id": str(log_id),
                            "digest": str(digest),
                            "prev_hash": prev_hash,
                            "line_hash": _compute_line_hash(seq, ts, str(log_id), str(digest), prev_hash),
                        }
                        f.seek(0, os.SEEK_END)  # 确保写在末尾（append 语义）
                        f.write(json.dumps(record, ensure_ascii=False) + "\n")
                        f.flush()
                        return True
                    finally:
                        _unlock_file(f)
        except OSError as e:
            print(f"[WORM][WARN] 本地哈希链锚定失败（文件锁/IO 异常）：{e}")
            return False
        except Exception as e:  # noqa: BLE001 - 锚定失败不得影响审计主流程
            print(f"[WORM][WARN] 本地哈希链锚定失败：{e}")
            return False

    # ------------------------------------------------------------------
    # 完整性验证（逐行重算 line_hash + prev_hash 链校验）
    # ------------------------------------------------------------------
    def verify_chain(self) -> Dict:
        checked = 0
        first_bad_seq = None
        prev_hash = GENESIS_PREV_HASH
        try:
            with self._io_lock:
                if not os.path.isfile(self._path):
                    return {"valid": True, "checked": 0, "first_bad_seq": None}
                with open(self._path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except (ValueError, TypeError):
                            first_bad_seq = checked + 1  # 坏行无法解析，按位置推断序号
                            break
                        if not isinstance(rec, dict) or "seq" not in rec:
                            first_bad_seq = checked + 1
                            break
                        # 1) 重算行哈希；2) 校验 prev_hash 与上一条 line_hash 链接
                        recomputed = _compute_line_hash(
                            rec.get("seq"), rec.get("ts", ""),
                            rec.get("log_id", ""), rec.get("digest", ""),
                            rec.get("prev_hash", ""),
                        )
                        if recomputed != rec.get("line_hash") or rec.get("prev_hash") != prev_hash:
                            first_bad_seq = rec.get("seq")
                            break
                        prev_hash = rec["line_hash"]
                        checked += 1
        except OSError as e:
            return {"valid": False, "checked": checked, "first_bad_seq": first_bad_seq, "error": str(e)[:200]}
        return {"valid": first_bad_seq is None, "checked": checked, "first_bad_seq": first_bad_seq}

    def size(self) -> int:
        try:
            with self._io_lock:
                if not os.path.isfile(self._path):
                    return 0
                count = 0
                with open(self._path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except (ValueError, TypeError):
                            continue
                        if isinstance(rec, dict) and "seq" in rec:
                            count += 1
                return count
        except OSError:
            return 0


class S3ObjectLockWormStore(WormStore):
    """S3 Object Lock（合规保留模式）WORM 存储 —— 生产接入点预留。

    TODO 生产接入步骤：
    1. bucket 开启 Object Lock（Compliance 模式），默认保留期对齐 AUDIT_RETENTION_DAYS；
    2. anchor：boto3 client("s3", endpoint_url=...).put_object(
           Bucket=..., Key=f"worm/{log_id}.json", Body=json.dumps({...seq/digest/prev_hash...}))
       —— Object Lock 保证对象版本一经写入不可删改（防持有库权限者整体重写）；
    3. verify_chain：list_objects_v2 按 seq 排序后逐条重算/比对 digest 与 prev_hash 链；
    4. 建议对 WORM 对象另做周期性 TSA 锚点（与 audit.tsa 联动）强化时间可信。
    """

    def __init__(self, endpoint: Optional[str] = None, bucket: Optional[str] = None):
        self._endpoint = endpoint or os.getenv("WORM_S3_ENDPOINT", "")
        self._bucket = bucket or os.getenv("WORM_S3_BUCKET", "")
        try:
            import boto3  # noqa: F401
            import botocore  # noqa: F401
            self._sdk_ready = True
        except ImportError:
            self._sdk_ready = False

    def _unconfigured(self) -> bool:
        """boto3/botocore 缺失或 endpoint/bucket 未配置时视为未就绪。"""
        if not self._sdk_ready or not self._endpoint or not self._bucket:
            print("[WORM][WARN] S3 Object Lock 未配置，降级本地哈希链（设置 WORM_BACKEND=local 或补齐 WORM_S3_ENDPOINT/WORM_S3_BUCKET）")
            return True
        return False

    def anchor(self, log_id: str, digest: str) -> bool:
        if self._unconfigured():
            return False
        # TODO 生产接入点：见类 docstring 第 2 步（put_object 到 Object Lock bucket）
        print(f"[WORM][WARN] S3 Object Lock 生产接入未实现，跳过锚定：log_id={log_id}")
        return False

    def verify_chain(self) -> Dict:
        if self._unconfigured():
            return {"valid": False, "checked": 0, "first_bad_seq": None, "backend": "s3", "configured": False}
        # TODO 生产接入点：见类 docstring 第 3 步（list + 逐条比对）
        return {"valid": False, "checked": 0, "first_bad_seq": None, "backend": "s3", "configured": True,
                "note": "S3 Object Lock 生产接入未实现"}

    def size(self) -> int:
        # TODO 生产接入点：list_objects_v2 计数（含分页）
        return 0


# ==================================================================
# 模块级单例
# ==================================================================
_worm_store_instance: Optional[WormStore] = None
_worm_store_lock = threading.Lock()


def get_worm_store() -> WormStore:
    """获取 WORM 存储单例：优先环境变量 WORM_BACKEND（local|s3，默认 local）。"""
    global _worm_store_instance
    with _worm_store_lock:
        if _worm_store_instance is None:
            backend = (os.getenv("WORM_BACKEND", "local") or "local").strip().lower()
            if backend == "s3":
                _worm_store_instance = S3ObjectLockWormStore()
            else:
                _worm_store_instance = LocalHashChainWormStore()
        return _worm_store_instance
