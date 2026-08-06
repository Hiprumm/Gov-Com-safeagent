"""
WebSocket 连接管理器

支持事件类型：
- approval_update: 审批状态变更（新创建/通过/驳回）
- risk_alert: 实时风险告警
- detection_event: 检测事件通知
"""
import asyncio
import json
from typing import Dict, Set, Optional
from fastapi import WebSocket, WebSocketDisconnect
from datetime import datetime


class ConnectionManager:
    """WebSocket 连接管理 — 支持多频道订阅"""

    def __init__(self):
        # channel_name -> set of WebSocket connections
        self._channels: Dict[str, Set[WebSocket]] = {}
        # websocket -> set of subscribed channels
        self._ws_channels: Dict[WebSocket, Set[str]] = {}

    async def connect(self, websocket: WebSocket):
        """接受 WebSocket 连接"""
        await websocket.accept()
        self._ws_channels[websocket] = set()

    def disconnect(self, websocket: WebSocket):
        """断开连接并清理"""
        channels = self._ws_channels.pop(websocket, set())
        for ch in channels:
            if ch in self._channels:
                self._channels[ch].discard(websocket)
                if not self._channels[ch]:
                    del self._channels[ch]

    def subscribe(self, websocket: WebSocket, channel: str):
        """订阅频道"""
        if channel not in self._channels:
            self._channels[channel] = set()
        self._channels[channel].add(websocket)
        if websocket in self._ws_channels:
            self._ws_channels[websocket].add(channel)

    def unsubscribe(self, websocket: WebSocket, channel: str):
        """取消订阅频道"""
        if channel in self._channels:
            self._channels[channel].discard(websocket)
            if not self._channels[channel]:
                del self._channels[channel]
        if websocket in self._ws_channels:
            self._ws_channels[websocket].discard(channel)

    async def broadcast_to_channel(self, channel: str, event: dict):
        """向频道的所有订阅者广播事件"""
        if channel not in self._channels:
            return
        dead = set()
        for ws in self._channels[channel]:
            try:
                await ws.send_json(event)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.disconnect(ws)

    async def send_to(self, websocket: WebSocket, event: dict):
        """向单个连接发送事件"""
        try:
            await websocket.send_json(event)
        except Exception:
            self.disconnect(websocket)

    @property
    def active_connections(self) -> int:
        return len(self._ws_channels)

    @property
    def channel_count(self) -> int:
        return len(self._channels)


# ==================== 全局单例 ====================
ws_manager = ConnectionManager()


# ==================== 便捷推送函数 ====================

async def push_approval_update(request_id: str, action: str, risk_level: str = "unknown",
                                detail: dict = None):
    """
    推送审批状态变更事件

    Args:
        request_id: 审批请求ID
        action: 'created' | 'approved' | 'rejected' | 'auto_approved'
        risk_level: 风险等级
        detail: 额外详情
    """
    event = {
        "type": "approval_update",
        "timestamp": datetime.now().isoformat(),
        "data": {
            "request_id": request_id,
            "action": action,
            "risk_level": risk_level,
            "detail": detail or {},
        }
    }
    await ws_manager.broadcast_to_channel("approvals", event)


async def push_risk_alert(session_id: str, risk_level: str, message: str,
                           confidence: float = 0.0, attack_type: str = None):
    """
    推送实时风险告警

    Args:
        session_id: 会话ID
        risk_level: 风险等级 (low/medium/high/critical)
        message: 告警消息
        confidence: 置信度
        attack_type: 攻击类型
    """
    event = {
        "type": "risk_alert",
        "timestamp": datetime.now().isoformat(),
        "data": {
            "session_id": session_id,
            "risk_level": risk_level,
            "message": message,
            "confidence": confidence,
            "attack_type": attack_type,
        }
    }
    await ws_manager.broadcast_to_channel("risk_alerts", event)


async def push_detection_event(source: str, risk_level: str, attack_type: str = None,
                                confidence: float = 0.0, evidence: str = ""):
    """
    推送检测事件

    Args:
        source: 检测来源
        risk_level: 风险等级
        attack_type: 攻击类型
        confidence: 置信度
        evidence: 证据摘要
    """
    event = {
        "type": "detection_event",
        "timestamp": datetime.now().isoformat(),
        "data": {
            "source": source,
            "risk_level": risk_level,
            "attack_type": attack_type,
            "confidence": confidence,
            "evidence": evidence[:200] if evidence else "",
        }
    }
    await ws_manager.broadcast_to_channel("detections", event)


# ==================== WebSocket 路由处理 ====================

async def handle_ws_events(websocket: WebSocket):
    """
    WebSocket 事件路由 — 客户端可订阅/取消订阅频道

    客户端发送消息格式：
        {"action": "subscribe", "channel": "approvals"}
        {"action": "unsubscribe", "channel": "risk_alerts"}

    服务端推送格式：
        {"type": "approval_update", "timestamp": "...", "data": {...}}
    """
    await ws_manager.connect(websocket)
    # 默认订阅所有事件频道
    ws_manager.subscribe(websocket, "approvals")
    ws_manager.subscribe(websocket, "risk_alerts")
    ws_manager.subscribe(websocket, "detections")

    try:
        while True:
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=60)
                msg = json.loads(raw)
                action = msg.get("action")
                channel = msg.get("channel")

                if action == "subscribe" and channel:
                    ws_manager.subscribe(websocket, channel)
                    await ws_manager.send_to(websocket, {
                        "type": "system",
                        "timestamp": datetime.now().isoformat(),
                        "data": {"message": f"Subscribed to {channel}"},
                    })
                elif action == "unsubscribe" and channel:
                    ws_manager.unsubscribe(websocket, channel)
                    await ws_manager.send_to(websocket, {
                        "type": "system",
                        "timestamp": datetime.now().isoformat(),
                        "data": {"message": f"Unsubscribed from {channel}"},
                    })
                elif action == "ping":
                    await ws_manager.send_to(websocket, {
                        "type": "pong",
                        "timestamp": datetime.now().isoformat(),
                    })
                else:
                    await ws_manager.send_to(websocket, {
                        "type": "error",
                        "timestamp": datetime.now().isoformat(),
                        "data": {"message": f"Unknown action: {action}"},
                    })
            except asyncio.TimeoutError:
                # 发送心跳
                pass
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        ws_manager.disconnect(websocket)
