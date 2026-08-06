import sys
import os
import uuid
import base64
import json
from datetime import datetime
from typing import Dict, Any, List, Callable, Optional
from langgraph.graph import StateGraph, END

from models.state import AgentState
from models.schemas import RiskLevel
from gov_agent_graph.security_layer import SecurityLayer
from config import settings
from storage import get_storage


class ConversationManager:
    def __init__(self):
        self.storage = get_storage()

    def create_session(self) -> str:
        return self.storage.create_session()

    def add_message(self, session_id: str, role: str, content: str, message_type: str = 'text'):
        self.storage.add_message(session_id, role, content, message_type)

    def get_history(self, session_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        return self.storage.get_history(session_id, limit)

    def clear_session(self, session_id: str):
        self.storage.clear_session(session_id)

    def list_sessions(self) -> List[Dict[str, Any]]:
        return self.storage.list_sessions()


class FileProcessor:
    def __init__(self):
        pass
    
    def process_file(self, file_data: str, file_type: str, filename: str) -> Dict[str, Any]:
        result = {
            "success": False,
            "content": "",
            "summary": "",
            "detection_required": False,
            "file_type": file_type,
            "filename": filename
        }
        
        try:
            if file_type.startswith('image/'):
                result.update(self._process_image(file_data, file_type))
            elif file_type.startswith('text/') or filename.endswith('.txt'):
                result.update(self._process_text(file_data))
            elif filename.endswith('.json'):
                result.update(self._process_json(file_data))
            else:
                result["content"] = f"文件类型 {file_type} 暂不支持直接解析，文件名: {filename}"
                result["success"] = True
            
            return result
        except Exception as e:
            result["content"] = f"文件处理失败: {str(e)}"
            return result
    
    def _process_image(self, file_data: str, file_type: str) -> Dict[str, Any]:
        try:
            decoded = base64.b64decode(file_data)
            file_size_mb = len(decoded) / (1024 * 1024)
            
            try:
                import pytesseract
                from PIL import Image
                from io import BytesIO
                
                # 设置Tesseract路径（Windows）
                tesseract_paths = [
                    r'C:\Program Files\Tesseract-OCR\tesseract.exe',
                    r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe',
                    r'D:\Program Files\Tesseract-OCR\tesseract.exe',
                ]
                for path in tesseract_paths:
                    if os.path.exists(path):
                        pytesseract.pytesseract.tesseract_cmd = path
                        break
                
                img = Image.open(BytesIO(decoded))
                # 转换为RGB模式以提高兼容性
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # 尝试识别中文和英文
                # 检查中文语言包是否存在
                tessdata_dir = os.path.dirname(pytesseract.pytesseract.tesseract_cmd)
                chi_sim_path = os.path.join(tessdata_dir, 'tessdata', 'chi_sim.traineddata')
                
                if os.path.exists(chi_sim_path):
                    text = pytesseract.image_to_string(img, lang='chi_sim+eng')
                else:
                    # 中文语言包缺失，仅识别英文
                    text = pytesseract.image_to_string(img)
                
                if text.strip():
                    return {
                        "success": True,
                        "content": text,
                        "summary": f"图片识别成功，提取文本 {len(text)} 字符",
                        "detection_required": True
                    }
                else:
                    return {
                        "success": True,
                        "content": "图片中未识别到文字内容",
                        "summary": "图片识别完成，无文本内容",
                        "detection_required": False
                    }
            except ImportError:
                return {
                    "success": True,
                    "content": f"图片数据已接收，文件名: {file_type}\n大小: {file_size_mb:.2f} MB\n\n(OCR模块未安装，请安装 pytesseract 和 Pillow)",
                    "summary": "图片已上传，等待OCR识别",
                    "detection_required": False
                }
            except pytesseract.pytesseract.TesseractNotFoundError:
                return {
                    "success": True,
                    "content": f"图片数据已接收，文件名: {file_type}\n大小: {file_size_mb:.2f} MB\n\n(Tesseract OCR引擎未安装或未配置路径，请下载安装Tesseract-OCR并配置环境变量)",
                    "summary": "图片已上传，Tesseract引擎未安装",
                    "detection_required": False
                }
        except Exception as e:
            return {
                "success": False,
                "content": f"图片处理失败: {str(e)}",
                "summary": "图片处理失败"
            }
    
    def _process_text(self, file_data: str) -> Dict[str, Any]:
        try:
            content = base64.b64decode(file_data).decode('utf-8', errors='replace')
            lines = content.split('\n')
            summary = f"文本文件，共 {len(lines)} 行，{len(content)} 字符"
            
            return {
                "success": True,
                "content": content,
                "summary": summary,
                "detection_required": True
            }
        except Exception as e:
            return {
                "success": False,
                "content": f"文本解析失败: {str(e)}",
                "summary": "文本解析失败"
            }
    
    def _process_json(self, file_data: str) -> Dict[str, Any]:
        try:
            content = base64.b64decode(file_data).decode('utf-8')
            data = json.loads(content)
            summary = f"JSON文件，包含 {len(data.keys())} 个键"
            
            return {
                "success": True,
                "content": json.dumps(data, indent=2, ensure_ascii=False),
                "summary": summary,
                "detection_required": True
            }
        except Exception as e:
            return {
                "success": False,
                "content": f"JSON解析失败: {str(e)}",
                "summary": "JSON解析失败"
            }


class GovAgent:
    def __init__(self):
        self.security_layer = SecurityLayer()
        self.conversation_manager = ConversationManager()
        self.file_processor = FileProcessor()
        self.llm_available = False
        
        try:
            from langchain_core.prompts import ChatPromptTemplate
            from langchain_core.output_parsers import JsonOutputParser
            
            api_key = settings.ZHIPU_API_KEY or os.environ.get("ZHIPUAI_API_KEY") or os.environ.get("ZHIPU_API_KEY")
            if api_key:
                from langchain_community.chat_models import ChatZhipuAI
                self.llm = ChatZhipuAI(model="glm-4", temperature=0, zhipuai_api_key=api_key)
                self.llm_available = True
                
                self.prompt_template = ChatPromptTemplate.from_messages([
                    ("system", """你是一个面向政企场景的安全智能体。你的职责是：
1. 分析用户输入，决定是否需要调用工具
2. 如果需要工具，输出工具调用列表
3. 如果不需要工具，直接生成回答

可用工具：
- read_file: 读取文件内容，参数: file_path
- write_file: 写入文件，参数: file_path, content
- execute_command: 执行系统命令，参数: command
- export_data: 导出数据，参数: format, query
- search_knowledge: 搜索知识库，参数: query

输出格式：必须是JSON格式，包含 tool_calls 数组和 reasoning 字段。
如果不需要工具，tool_calls 为空数组。
{{"tool_calls": [], "reasoning": "直接回答用户问题"}}
{{"tool_calls": [{{"name": "read_file", "args": {{"file_path": "/path/to/file"}}}}], "reasoning": "需要读取文件"}}
"""),
                    ("human", "{user_input}")
                ])
                
                self.response_template = ChatPromptTemplate.from_messages([
                    ("system", """你是一个面向政企场景的安全智能体。请根据对话历史和工具执行结果，给出友好、专业的回答。
注意：回答必须符合政务安全规范，不泄露敏感信息。

对话历史：
{conversation_history}
"""),
                    ("human", "用户问题: {user_input}\n工具结果: {tool_results}")
                ])
                
                self.parser = JsonOutputParser()
                print("[INFO] LLM initialized with Zhipu API")
            else:
                print("[INFO] ZHIPU_API_KEY not set, using rule-based fallback")
        except Exception as e:
            print(f"[INFO] LLM initialization failed: {str(e)}, using rule-based fallback")
        
        self.graph = self._build_graph()
    
    def _build_graph(self) -> StateGraph:
        workflow = StateGraph(AgentState)
        
        workflow.add_node("input_detection", self.security_layer.detect_input)
        workflow.add_node("risk_assessment", self.risk_assessment)
        workflow.add_node("decision_making", self.decision_making)
        workflow.add_node("tool_selection", self.tool_selection)
        workflow.add_node("tool_evaluation", self.security_layer.evaluate_tool_call)
        workflow.add_node("approval_check", self.security_layer.check_approval)
        workflow.add_node("tool_execution", self.tool_execution)
        workflow.add_node("response_generation", self.response_generation)
        workflow.add_node("block_response", self.block_response)
        
        workflow.set_entry_point("input_detection")
        
        workflow.add_conditional_edges(
            "input_detection",
            self._route_after_detection,
            {"block": "block_response", "proceed": "risk_assessment"}
        )
        
        workflow.add_edge("risk_assessment", "decision_making")
        
        workflow.add_conditional_edges(
            "decision_making",
            self._route_after_decision,
            {"tool": "tool_selection", "direct": "response_generation"}
        )
        
        workflow.add_edge("tool_selection", "tool_evaluation")
        
        workflow.add_conditional_edges(
            "tool_evaluation",
            self._route_after_tool_evaluation,
            {"block": "block_response", "approval": "approval_check", "execute": "tool_execution"}
        )
        
        workflow.add_conditional_edges(
            "approval_check",
            self._route_after_approval,
            {"approved": "tool_execution", "rejected": "block_response"}
        )
        
        workflow.add_edge("tool_execution", "response_generation")
        
        workflow.add_edge("response_generation", END)
        workflow.add_edge("block_response", END)
        
        return workflow.compile()
    
    def _route_after_detection(self, state: AgentState) -> str:
        if state["risk_level"] in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            return "block"
        return "proceed"
    
    def _route_after_decision(self, state: AgentState) -> str:
        tool_calls = state.get("tool_calls", [])
        if tool_calls:
            return "tool"
        return "direct"
    
    def _route_after_tool_evaluation(self, state: AgentState) -> str:
        if state["risk_level"] == RiskLevel.CRITICAL:
            return "block"
        approval_requests = state.get("approval_requests", [])
        if approval_requests:
            return "approval"
        return "execute"
    
    def _route_after_approval(self, state: AgentState) -> str:
        if state["can_proceed"]:
            return "approved"
        return "rejected"
    
    def risk_assessment(self, state: AgentState) -> AgentState:
        detection_results = state["detection_results"]
        
        risk_summary = {
            "total_detections": len(detection_results),
            "highest_risk": state["risk_level"].value,
            "attack_types": [r.attack_type.value for r in detection_results if r.attack_type],
            "confidence_scores": [r.confidence for r in detection_results],
        }
        
        return {
            **state,
            "risk_summary": risk_summary,
            "current_step": "risk_assessment_completed",
        }
    
    def decision_making(self, state: AgentState) -> AgentState:
        user_input = state["user_input"]
        
        if self.llm_available:
            try:
                chain = self.prompt_template | self.llm | self.parser
                result = chain.invoke({"user_input": user_input})
                
                tool_calls = result.get("tool_calls", [])
                reasoning = result.get("reasoning", "")
                return {
                    **state,
                    "tool_calls": tool_calls,
                    "llm_response": reasoning,
                    "current_step": "decision_making_completed",
                }
            except Exception as e:
                print(f"[WARN] LLM decision failed: {e}, falling back to rule-based selection")
        
        tool_calls = self._fallback_tool_selection(user_input)
        reasoning = "使用规则匹配进行决策"
        
        return {
            **state,
            "tool_calls": tool_calls,
            "llm_response": reasoning,
            "current_step": "decision_making_completed",
        }
    
    def _fallback_tool_selection(self, user_input: str) -> List[Dict[str, Any]]:
        tool_calls = []
        
        if any(keyword in user_input for keyword in ["查询", "查找", "搜索", "获取", "读取"]):
            tool_calls.append({
                "name": "read_file",
                "args": {"file_path": "/data/docs/gov_doc.txt"}
            })
        
        if any(keyword in user_input for keyword in ["执行", "运行", "启动", "操作"]):
            tool_calls.append({
                "name": "execute_command",
                "args": {"command": "ls -la"}
            })
        
        if any(keyword in user_input for keyword in ["写入", "保存", "修改", "更新"]):
            tool_calls.append({
                "name": "write_file",
                "args": {"file_path": "/data/output/result.txt", "content": user_input}
            })
        
        if any(keyword in user_input for keyword in ["导出", "下载", "备份"]):
            tool_calls.append({
                "name": "export_data",
                "args": {"format": "csv", "query": "SELECT * FROM users"}
            })
        
        return tool_calls
    
    def tool_selection(self, state: AgentState) -> AgentState:
        tool_calls = state["tool_calls"]
        selected_tools = []
        
        for tool_call in tool_calls:
            tool_name = tool_call.get("name", "")
            
            if tool_name in ["read_file", "search_knowledge"]:
                selected_tools.append(tool_call)
            elif tool_name in ["write_file", "execute_command"]:
                selected_tools.append(tool_call)
            elif tool_name == "export_data":
                selected_tools.append(tool_call)
        
        return {
            **state,
            "tool_calls": selected_tools,
            "current_step": "tool_selection_completed",
        }
    
    def tool_execution(self, state: AgentState) -> AgentState:
        tool_calls = state["tool_calls"]
        execution_results = []
        
        for tool_call in tool_calls:
            tool_name = tool_call.get("name", "")
            tool_args = tool_call.get("args", {})
            
            result = {
                "tool_name": tool_name,
                "args": tool_args,
                "result": f"模拟执行工具 [{tool_name}] 成功",
                "status": "success",
                "timestamp": "2024-01-01 12:00:00",
            }
            
            execution_results.append(result)
        
        return {
            **state,
            "tool_execution_results": execution_results,
            "current_step": "tool_execution_completed",
        }
    
    def response_generation(self, state: AgentState) -> AgentState:
        user_input = state["user_input"]
        tool_results = state.get("tool_execution_results", [])
        conversation_history = state.get("conversation_history", [])
        
        history_str = "\n".join([f"{msg['role']}: {msg['content'][:100]}..." for msg in conversation_history[-5:]])
        
        if self.llm_available:
            try:
                tool_results_str = "\n".join([f"{r['tool_name']}: {r['result']}" for r in tool_results])
                chain = self.response_template | self.llm
                llm_response = chain.invoke({
                    "user_input": user_input,
                    "tool_results": tool_results_str,
                    "conversation_history": history_str
                })
                final_response = llm_response.content
                
                self.security_layer.audit_logger.create_log(
                    user_id="user",
                    user_role="user",
                    agent_id="gov_agent",
                    action_type="response_generation",
                    action_details={"response_length": len(final_response)},
                    risk_level=RiskLevel.NONE,
                )
                
                return {
                    **state,
                    "final_response": final_response,
                    "current_step": "completed",
                }
            except Exception as e:
                print(f"[WARN] LLM response generation failed: {e}, falling back to rule-based response")
        
        final_response = self._fallback_response(user_input, tool_results)
        
        self.security_layer.audit_logger.create_log(
            user_id="user",
            user_role="user",
            agent_id="gov_agent",
            action_type="response_generation",
            action_details={"response_length": len(final_response)},
            risk_level=RiskLevel.NONE,
        )
        
        return {
            **state,
            "final_response": final_response,
            "current_step": "completed",
        }
    
    def _fallback_response(self, user_input: str, tool_results: List[Dict[str, Any]]) -> str:
        """当LLM不可用时，使用规则模板生成有意义的回复"""
        input_lower = user_input.strip().lower()
        
        # 问候类
        greetings = ["你好", "您好", "hi", "hello", "嗨", "早上好", "下午好", "晚上好"]
        if any(g in input_lower for g in greetings) and len(user_input) < 15:
            return (
                "您好！我是面向政企场景的大模型智能体安全平台。\n\n"
                "我可以帮您：\n"
                "1. **智能问答** — 回答政务、政策、管理等相关问题\n"
                "2. **安全检测** — 对输入文本进行多层安全扫描（注入攻击、越狱、数据泄露等）\n"
                "3. **插件扫描** — 检测第三方插件/代码的安全风险\n"
                "4. **知识库投毒检测** — 识别PDF文档中的隐藏恶意指令\n"
                "5. **审批管理** — 对高风险操作进行审批控制\n\n"
                "请问有什么可以帮您的？"
            )
        
        # 功能询问类
        capability_keywords = ["干什么", "能做什么", "功能", "作用", "是什么", "你是"]
        if any(k in input_lower for k in capability_keywords):
            return (
                "我是面向政企场景的大模型智能体安全平台（ASP），专门为政务和企业场景设计的安全防护系统。\n\n"
                "**核心能力：**\n"
                "- 多源输入攻击检测（提示注入、越狱、SQL注入、命令注入等）\n"
                "- 三层安全引擎（规则引擎 + AI检测 + 向量投毒检测）\n"
                "- 供应链安全扫描（插件/脚本代码审计）\n"
                "- 知识库投毒检测（PDF隐藏文本识别）\n"
                "- Session级风险累积评估\n"
                "- 审批工作流与操作审计\n\n"
                "请在顶部切换到「安全检测」标签体验安全扫描功能。"
            )
        
        # 安全相关
        security_keywords = ["安全", "攻击", "注入", "漏洞", "检测", "防护", "扫描", "审计"]
        if any(k in input_lower for k in security_keywords):
            return (
                "关于安全检测，本平台提供以下防护能力：\n\n"
                "**输入层防护：**\n"
                "- 150+ 正则规则覆盖12类攻击模式\n"
                "- AI语义检测识别变种攻击\n"
                "- 向量投毒检测防止知识库污染\n\n"
                "**执行层防护：**\n"
                "- 工具调用风险分级（A-E五级）\n"
                "- 异常行为链分析（数据窃取、权限提升等复合攻击）\n"
                "- 高危操作审批控制\n\n"
                "**评测数据（基线50条样本）：**\n"
                "- 精确率 95.8%，F1 80.7%\n"
                "- 命令注入/内容注入检测率 100%\n\n"
                "请在「安全检测」标签页中体验具体功能。"
            )
        
        # 政务/政策类
        gov_keywords = ["政务", "政策", "政府", "国企", "审批", "合规", "监管"]
        if any(k in input_lower for k in gov_keywords):
            return (
                "本平台专为政企场景设计，遵循以下安全原则：\n\n"
                "1. **安全左移** — 在智能体感知和决策阶段就进行安全检测\n"
                "2. **纵深防御** — 规则引擎→AI检测→向量投毒检测 三层叠加\n"
                "3. **默认拒绝** — HIGH/CRITICAL风险操作默认阻断，需审批放行\n"
                "4. **全程审计** — 所有关键操作留痕，支持多维检索\n"
                "5. **合规优先** — 权限模型、审批流程、日志格式满足等保要求\n\n"
                "如需了解具体的合规方案或部署细节，请详细描述您的需求。"
            )
        
        # 有工具结果时
        if tool_results:
            response_parts = ["已处理您的请求，工具执行结果如下："]
            for result in tool_results:
                response_parts.append(f"- {result.get('tool_name', '工具')}: {result.get('result', '完成')}")
            response_parts.append("\n注意：当前运行在演示模式（LLM未配置），上述为规则引擎响应。")
            return "\n".join(response_parts)
        
        # 默认回复
        return (
            f"关于「{user_input[:30]}{'...' if len(user_input) > 30 else ''}」，以下是相关信息：\n\n"
            f"本平台已对您的输入完成了多层安全检测（规则引擎+AI检测+向量投毒检测），未发现安全风险。\n\n"
            f"由于当前LLM未配置，我无法生成更详细的自然语言回复。如需完整的智能问答能力，请配置智谱AI API Key。\n\n"
            f"您可以：\n"
            f"1. 在「安全检测」标签页体验安全扫描功能\n"
            f"2. 在「插件扫描」标签页测试供应链安全检测\n"
            f"3. 在 ai_service 目录下创建 .env 文件配置 ZHIPU_API_KEY 启用LLM"
        )
    
    def block_response(self, state: AgentState) -> AgentState:
        risk_level = state["risk_level"]
        detection_results = state.get("detection_results", [])
        
        evidence = []
        for result in detection_results:
            evidence.extend(result.evidence[:3])
        
        block_message = f"""
您的请求已被安全系统拦截！

风险等级: {risk_level.value.upper()}

风险原因:
{chr(10).join(f"- {e}" for e in evidence)}

建议:
- 请检查您的输入内容是否包含敏感信息
- 如果这是正常请求，请联系管理员审批
- 请勿尝试绕过安全检测机制
"""
        
        return {
            **state,
            "final_response": block_message,
            "can_proceed": False,
            "current_step": "blocked",
        }
    
    def run_with_history(self, session_id: str, user_input: str, input_source: str = "user_input") -> Dict[str, Any]:
        conversation_history = self.conversation_manager.get_history(session_id)
        
        initial_state: AgentState = {
            "user_input": user_input,
            "input_source": input_source,
            "session_id": session_id,
            "detection_results": [],
            "risk_level": RiskLevel.NONE,
            "risk_summary": None,
            "can_proceed": True,
            "tool_calls": [],
            "tool_risk_results": [],
            "tool_execution_results": [],
            "approval_requests": [],
            "approval_status": {},
            "plugin_scan_results": [],
            "conversation_history": conversation_history,
            "current_step": "start",
            "final_response": None,
            "audit_logs": [],
            "llm_response": None,
        }
        
        result = self.graph.invoke(initial_state)
        
        final_response = result.get("final_response", "")
        self.conversation_manager.add_message(session_id, "user", user_input)
        self.conversation_manager.add_message(session_id, "assistant", final_response)
        
        return {
            "final_response": final_response,
            "risk_level": result.get("risk_level", RiskLevel.NONE).value,
            "can_proceed": result.get("can_proceed", False),
            "current_step": result.get("current_step"),
            "detection_results": [r.dict() for r in result.get("detection_results", [])],
            "tool_risk_results": [r.dict() for r in result.get("tool_risk_results", [])],
            "llm_response": result.get("llm_response"),
            "session_id": session_id,
            "conversation_history": self.conversation_manager.get_history(session_id),
        }
    
    def run(self, user_input: str, input_source: str = "user_input", session_id: Optional[str] = None) -> Dict[str, Any]:
        if not session_id:
            session_id = self.conversation_manager.create_session()
        
        return self.run_with_history(session_id, user_input, input_source)
    
    def process_file_message(self, session_id: str, file_data: str, file_type: str, filename: str) -> Dict[str, Any]:
        processed = self.file_processor.process_file(file_data, file_type, filename)
        
        if processed["detection_required"] and processed["content"]:
            detection_result = self.security_layer.input_detector.detect_single_input(
                processed["content"],
                source="uploaded_doc"
            )
            
            if detection_result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                self.conversation_manager.add_message(session_id, "user", f"[文件上传] {filename}")
                self.conversation_manager.add_message(session_id, "assistant", 
                    f"文件 {filename} 包含安全风险内容，已被拦截！\n风险等级: {detection_result.risk_level.value}")
                
                return {
                    "success": False,
                    "message": f"文件内容检测到安全风险，已被拦截",
                    "risk_level": detection_result.risk_level.value,
                    "session_id": session_id,
                    "conversation_history": self.conversation_manager.get_history(session_id),
                }
        
        user_input = f"请分析以下文件内容：\n文件名: {filename}\n类型: {file_type}\n内容:\n{processed['content'][:2000]}"
        
        self.conversation_manager.add_message(session_id, "user", f"[文件上传] {filename}")
        
        return self.run_with_history(session_id, user_input, "uploaded_doc")
    
    def get_conversation_history(self, session_id: str) -> Dict[str, Any]:
        history = self.conversation_manager.get_history(session_id)
        return {
            "session_id": session_id,
            "messages": history,
            "count": len(history)
        }
    
    def create_new_session(self) -> Dict[str, Any]:
        session_id = self.conversation_manager.create_session()
        return {
            "session_id": session_id,
            "message": "新会话已创建"
        }
    
    def clear_conversation(self, session_id: str) -> Dict[str, Any]:
        self.conversation_manager.clear_session(session_id)
        return {
            "session_id": session_id,
            "message": "会话历史已清除"
        }
    
    def list_sessions(self) -> Dict[str, Any]:
        sessions = self.conversation_manager.list_sessions()
        return {
            "sessions": sessions,
            "count": len(sessions)
        }