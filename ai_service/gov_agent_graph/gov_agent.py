import sys
import os
import re
import uuid
import base64
import json
from datetime import datetime
import queue
import threading
from typing import Dict, Any, List, Callable, Optional
from langgraph.graph import StateGraph, END

from models.state import AgentState
from models.schemas import RiskLevel
from gov_agent_graph.security_layer import SecurityLayer
from config import settings
from storage import get_storage
# 方向A：创新点接入 graph
from security.plan_ir import PlanIRBuilder, InterventionAction
from security.sequence_risk_evaluator import SequenceRiskEvaluator
from security.operation_guard import OperationGuard, OperationIntent
# 方向A-5：输出过滤——response_generation 后对 final_response 做敏感数据脱敏
from security.output_filter import OutputFilter
# 方向A-4：受限真执行——tool_execution 调用沙箱执行器（白名单路径 + 子进程超时）
from tools.docker_executor import docker_executor

# PaddleOCR 惰性单例：模型初始化/下载较重，跨请求复用（线程安全）
_PADDLE_INSTANCE = None
_PADDLE_LOCK = threading.Lock()
# 模型缓存目录固定到项目侧（X 盘），避免写入用户目录（C 盘）
_PADDLE_MODEL_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.paddleocr')


class ConversationManager:
    def __init__(self):
        self.storage = get_storage()

    def create_session(self, user_id: str = None) -> str:
        return self.storage.create_session(user_id)

    def ensure_session(self, session_id: str, user_id: str = None) -> str:
        """确保 session_id 存在，不存在则创建（保留外部传入 ID）。

        走存储后端的统一幂等方法，兼容 SQLite / PostgreSQL。
        新会话绑定 user_id（账户会话隔离）。
        """
        if not session_id:
            return self.storage.create_session(user_id)
        return self.storage.ensure_session(session_id, user_id)

    def add_message(self, session_id: str, role: str, content: str, message_type: str = 'text',
                    metadata: Optional[str] = None):
        self.storage.add_message(session_id, role, content, message_type, metadata)

    def get_history(self, session_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        return self.storage.get_history(session_id, limit)

    def clear_session(self, session_id: str):
        self.storage.clear_session(session_id)

    def list_sessions(self, user_id: str = None) -> List[Dict[str, Any]]:
        return self.storage.list_sessions(user_id)

    def delete_session(self, session_id: str):
        self.storage.delete_session(session_id)

    def rename_session(self, session_id: str, title: str) -> bool:
        return self.storage.rename_session(session_id, title)


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

        # 获取文件扩展名（小写）
        ext = ""
        if "." in filename:
            ext = filename.rsplit(".", 1)[-1].lower()

        try:
            if file_type.startswith('image/'):
                result.update(self._process_image(file_data, file_type))
            elif file_type.startswith('text/') or ext in ("txt", "md", "markdown", "csv", "log",
                                                            "py", "js", "ts", "java", "c", "cpp", "h",
                                                            "go", "rs", "rb", "php", "sh", "bat", "ps1",
                                                            "yml", "yaml", "toml", "ini", "cfg", "conf",
                                                            "xml", "html", "htm", "css", "scss", "sql",
                                                            "vue", "jsx", "tsx", "swift", "kt", "scala",
                                                            "lua", "r", "dart", "gradle", "dockerfile",
                                                            "makefile", "gitignore", "env"):
                result.update(self._process_text(file_data))
            elif ext == "json" or file_type == "application/json":
                result.update(self._process_json(file_data))
            elif ext == "pdf":
                result.update(self._process_pdf(file_data))
            elif ext in ("doc", "docx"):
                result.update(self._process_doc(file_data, ext))
            elif ext in ("xls", "xlsx"):
                result.update(self._process_excel(file_data, ext))
            elif ext in ("zip", "rar", "7z", "tar", "gz", "bz2"):
                result.update(self._process_archive(file_data, ext, filename))
            else:
                # 兜底：尝试按文本解码，失败则返回二进制信息
                result.update(self._process_unknown(file_data, file_type, filename))

            return result
        except Exception as e:
            result["content"] = f"文件处理失败: {str(e)}"
            return result
    
    def _process_image(self, file_data: str, file_type: str) -> Dict[str, Any]:
        try:
            decoded = base64.b64decode(file_data)
            file_size_mb = len(decoded) / (1024 * 1024)

            text = ""
            detail = ""
            img = None
            # 1) 首选 PaddleOCR（中英文精度最高，含方向矫正）——先预处理再识别
            try:
                from PIL import Image
                from io import BytesIO

                img = Image.open(BytesIO(decoded))
                text = self._paddle_ocr(self._preprocess_for_ocr(img))
                text = self._clean_ocr_text(text)
                if text:
                    detail = ""
            except ImportError:
                detail = "PaddleOCR未安装"
            except Exception as e:  # noqa: BLE001
                detail = f"PaddleOCR识别失败: {e}"

            # 2) PaddleOCR 不可用 / 结果过少视为质量不达标 → 本地 Tesseract OCR
            if not self._ocr_quality_ok(text, img):
                try:
                    import pytesseract
                    from PIL import Image as _PILImage  # noqa: F401 - 复用下方 Image 导入
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

                    img = img or Image.open(BytesIO(decoded))
                    # 预处理：放大过小图片 + 灰度 + 对比度增强
                    pre = self._preprocess_for_ocr(img)

                    # 尝试识别中文和英文
                    # 检查中文语言包是否存在
                    tessdata_dir = os.path.dirname(pytesseract.pytesseract.tesseract_cmd)
                    chi_sim_path = os.path.join(tessdata_dir, 'tessdata', 'chi_sim.traineddata')

                    if os.path.exists(chi_sim_path):
                        text = pytesseract.image_to_string(pre, lang='chi_sim+eng')
                    else:
                        # 中文语言包缺失，仅识别英文
                        text = pytesseract.image_to_string(pre)
                    text = self._clean_ocr_text(text)
                    if text:
                        detail = ""
                except ImportError:
                    detail = "OCR本地模块(pytesseract/Pillow)未安装"
                except pytesseract.pytesseract.TesseractNotFoundError:
                    detail = "Tesseract OCR引擎未安装"
                except Exception as e:  # noqa: BLE001
                    detail = f"本地OCR识别失败: {e}"

            # 3) 本地识别（PaddleOCR + Tesseract）仍未达标 → 回退 LLM 视觉识别
            if not self._ocr_quality_ok(text, img):
                try:
                    llm_text = self._vision_ocr(decoded, file_type)
                    if llm_text and llm_text.strip():
                        text = llm_text
                        detail = ""
                    elif llm_text is not None:
                        # LLM 成功返回但无文字
                        text = llm_text
                        detail = ""
                except Exception as e:  # noqa: BLE001
                    detail = (detail + f"；视觉识别失败: {e}").strip("；")

            if text and text.strip():
                return {
                    "success": True,
                    "content": text,
                    "summary": f"图片识别成功，提取文本 {len(text)} 字符",
                    "detection_required": True
                }
            else:
                return {
                    "success": True,
                    "content": f"图片数据已接收，文件名: {file_type}\n大小: {file_size_mb:.2f} MB\n\n(未识别到文字内容" + (f"；{detail}" if detail else "") + ")",
                    "summary": "图片识别完成，无文本内容",
                    "detection_required": False
                }
        except Exception as e:
            return {
                "success": False,
                "content": f"图片处理失败: {str(e)}",
                "summary": "图片处理失败"
            }

    # ---- OCR 精度优化辅助方法 ----
    def _preprocess_for_ocr(self, img):
        """OCR 前图像预处理：放大过小图片、灰度化、增强对比度，显著提升识别率。"""
        from PIL import Image, ImageOps, ImageEnhance

        img = img.convert("RGB")
        w, h = img.size
        min_side = min(w, h)
        if min_side < 1200:  # Tesseract 对高分辨率文本识别更准，小图先放大（最多 3 倍）
            scale = min(3.0, max(1.0, 1200 / min_side))
            img = img.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
        gray = ImageOps.grayscale(img)
        gray = ImageEnhance.Contrast(gray).enhance(2.0)
        return ImageOps.autocontrast(gray)

    @staticmethod
    def _clean_ocr_text(text: str) -> str:
        """整理 OCR 输出：去噪行、合并连续空行，避免噪声被当作正文。"""
        if not text:
            return ""
        lines = []
        prev_blank = False
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln:
                if not prev_blank:
                    lines.append("")
                prev_blank = True
            else:
                prev_blank = False
                lines.append(ln)
        return "\n".join(lines).strip()

    @staticmethod
    def _strip_code_fence(text: str) -> str:
        """去除 LLM 返回时可能包裹的 ``` 代码块围栏。"""
        if text.startswith("```"):
            text = text.split("\n", 1)[-1] if "\n" in text else text.lstrip("`")
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        return text.strip()

    def _ocr_quality_ok(self, text: str, img) -> bool:
        """启发式质量门：本地 OCR 为空、或大图却几乎没识别出内容时判为不达标，
        从而触发 LLM 视觉模型回退（提高整体识别精度）。"""
        t = (text or "").strip()
        if not t:
            return False
        if img is None:
            return True
        try:
            w, h = img.size
        except Exception:  # noqa: BLE001
            return True
        if max(w, h) >= 800 and len(t.replace(" ", "").replace("\n", "")) < 4:
            return False
        return True

    def _paddle_ocr(self, img) -> str:
        """PaddleOCR 文字识别（中英文精度显著优于 Tesseract，含方向矫正）。

        惰性加载模型并跨请求复用（首次初始化/下载模型较慢，之后秒级）；
        兼容 paddleocr 2.7 旧 API（ocr.ocr）与 3.x 新 API（ocr.predict）。
        识别失败抛异常，由调用方兜底降级到 Tesseract / LLM 视觉。
        """
        import numpy as np  # noqa: F401 - paddleocr 强依赖 numpy
        import paddleocr as _paddleocr_pkg
        from paddleocr import PaddleOCR

        global _PADDLE_INSTANCE
        if _PADDLE_INSTANCE is None:
            with _PADDLE_LOCK:
                if _PADDLE_INSTANCE is None:
                    _ver = tuple(int(x) for x in
                                 _paddleocr_pkg.__version__.split('.')[:2])
                    if _ver >= (3, 0):
                        # paddleocr 3.x：关闭文档方向/矫正等重型子模型，仅保留文本行方向
                        _PADDLE_INSTANCE = PaddleOCR(
                            lang='ch',
                            use_doc_orientation_classify=False,
                            use_doc_unwarping=False,
                            use_textline_orientation=True,
                        )
                    else:
                        # paddleocr 2.x：含方向分类；模型显式落到项目目录（X 盘），
                        # 避免默认写入用户目录 ~/.paddleocr（C 盘）
                        _PADDLE_INSTANCE = PaddleOCR(
                            lang='ch', use_angle_cls=True, show_log=False,
                            det_model_dir=os.path.join(_PADDLE_MODEL_DIR, 'det'),
                            rec_model_dir=os.path.join(_PADDLE_MODEL_DIR, 'rec'),
                            cls_model_dir=os.path.join(_PADDLE_MODEL_DIR, 'cls'),
                        )
        ocr = _PADDLE_INSTANCE

        arr = np.array(img)
        if arr.ndim == 2:  # 灰度图补成三通道，PaddleX 3.x 要求 RGB
            arr = np.stack([arr] * 3, axis=-1)
        try:
            result = ocr.predict(arr)  # paddleocr 3.x API
        except AttributeError:
            result = ocr.ocr(arr, cls=True)  # paddleocr 2.7 API
        return "\n".join(self._paddle_text_lines(result))

    @staticmethod
    def _paddle_text_lines(result) -> List[str]:
        """从 PaddleOCR 结果中提取文本行（兼容 2.7 旧格式与 3.x OCRResult）。"""
        lines = []
        pages = result if isinstance(result, (list, tuple)) else [result]
        for page in pages:
            if hasattr(page, 'json'):  # paddleocr 3.x OCRResult
                j = page.json or {}
                res = j.get('res', j) if isinstance(j, dict) else {}
                found = []
                for key in ('rec_texts', 'texts'):
                    if isinstance(res.get(key), list):
                        found = [t for t in res[key] if isinstance(t, str)]
                        break
                if not found:
                    td = res.get('text_detection')
                    if isinstance(td, dict):
                        found = [t for t in td.get('texts', []) if isinstance(t, str)]
                lines.extend(found)
            elif isinstance(page, (list, tuple)):  # paddleocr 2.7 旧格式
                for item in page:
                    if (isinstance(item, (list, tuple)) and len(item) >= 2
                            and isinstance(item[1], (list, tuple))
                            and item[1] and isinstance(item[1][0], str)):
                        lines.append(item[1][0])
        return lines

    def _vision_ocr(self, file_bytes: bytes, file_type: str) -> str:
        """通过 LLM 视觉能力识别图片文字（Tesseract 缺失/失败时的回退路径）。

        走 llm_runtime 的开放配置（provider/api_key/base_url/model），
        以 OpenAI 兼容多模态格式把 base64 图片交给大模型提取文字。
        返回识别出的文字；模型不可用/失败时返回空字符串（由调用方兜底）。
        """
        try:
            import json
            import urllib.error
            import urllib.request

            from llm_runtime import load_config, completions_url
        except Exception:  # noqa: BLE001
            return ""

        cfg = load_config()
        if not cfg.get("api_key"):
            return ""

        # 构造 data URI：超大图先本地压缩到 2048 内，避免接口二次缩放失真/超限
        mime = file_type if "/" in file_type else "image/png"
        try:
            from PIL import Image as PILImage
            from io import BytesIO
            im = PILImage.open(BytesIO(file_bytes))
            im.thumbnail((2048, 2048), PILImage.LANCZOS)
            buf = BytesIO()
            im.convert("RGB").save(buf, format="JPEG", quality=92)
            b64 = base64.b64encode(buf.getvalue()).decode("ascii")
            mime = "image/jpeg"
        except Exception:  # noqa: BLE001 - 压缩失败直接用原图
            b64 = base64.b64encode(file_bytes).decode("ascii")
        image_url = f"data:{mime};base64,{b64}"

        # 候选模型：先试当前配置模型，若其不支持视觉(400/报错)则回退到已知视觉模型
        configured = cfg.get("model") or "glm-4-flash"
        candidate_models = list(dict.fromkeys([configured, "glm-4v-flash"]))
        prompt = ("请识别并提取图片中的全部文字，逐字准确转录，保留原有段落与换行结构；"
                  "只返回识别到的文字本身，不要加任何解释、不要用代码块包裹；"
                  "若图片中没有文字，请直接返回：无文字。")

        for model in candidate_models:
            payload = json.dumps({
                "model": model,
                "messages": [{
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {"type": "image_url", "image_url": {"url": image_url}},
                    ],
                }],
                "max_tokens": 2048,
                "stream": False,
            }).encode("utf-8")

            req = urllib.request.Request(
                completions_url(cfg["base_url"]),
                data=payload,
                method="POST",
                headers={"Content-Type": "application/json",
                         "Authorization": f"Bearer {cfg['api_key']}"},
            )
            try:
                with urllib.request.urlopen(req, timeout=90) as resp:
                    body = json.loads(resp.read().decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001 - 换下一个候选模型
                continue
            try:
                raw = body["choices"][0]["message"]["content"] or ""
                return self._clean_ocr_text(self._strip_code_fence(raw))
            except Exception:  # noqa: BLE001
                return ""
        return ""
    
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

    def _process_pdf(self, file_data: str) -> Dict[str, Any]:
        try:
            decoded = base64.b64decode(file_data)
            file_size_mb = len(decoded) / (1024 * 1024)

            try:
                import fitz  # PyMuPDF
                from io import BytesIO
                doc = fitz.open(stream=BytesIO(decoded), filetype="pdf")
                text_parts = []
                for page in doc:
                    text_parts.append(page.get_text())
                doc.close()
                content = "\n".join(text_parts).strip()

                if content:
                    return {
                        "success": True,
                        "content": content,
                        "summary": f"PDF文件，共 {len(text_parts)} 页，{len(content)} 字符",
                        "detection_required": True
                    }
                else:
                    return {
                        "success": True,
                        "content": f"PDF文件已接收，大小: {file_size_mb:.2f} MB\n\n(未提取到文本内容，可能是扫描件图片)",
                        "summary": "PDF无文本层",
                        "detection_required": False
                    }
            except ImportError:
                return {
                    "success": True,
                    "content": f"PDF文件已接收，大小: {file_size_mb:.2f} MB\n\n(未安装 PyMuPDF，请 pip install PyMuPDF)",
                    "summary": "PDF已上传，PyMuPDF未安装",
                    "detection_required": False
                }
        except Exception as e:
            return {
                "success": False,
                "content": f"PDF解析失败: {str(e)}",
                "summary": "PDF解析失败"
            }

    def _process_doc(self, file_data: str, ext: str) -> Dict[str, Any]:
        try:
            decoded = base64.b64decode(file_data)
            file_size_mb = len(decoded) / (1024 * 1024)

            try:
                from io import BytesIO

                if ext == "docx":
                    from docx import Document
                    doc = Document(BytesIO(decoded))
                    paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
                    content = "\n".join(paragraphs)
                    return {
                        "success": True,
                        "content": content or f"Word文档(.docx)，大小: {file_size_mb:.2f} MB\n\n(文档无文本段落)",
                        "summary": f"Word文档(.docx)，{len(paragraphs)} 个段落，{len(content)} 字符",
                        "detection_required": True
                    }
                else:
                    # .doc 旧格式，python-docx 不支持，尝试按二进制提取
                    return {
                        "success": True,
                        "content": f"Word文档(.doc)，大小: {file_size_mb:.2f} MB\n\n(旧版.doc格式需安装 antiword 或 LibreOffice 转换)",
                        "summary": "Word(.doc)旧格式",
                        "detection_required": False
                    }
            except ImportError:
                return {
                    "success": True,
                    "content": f"Word文档已接收，大小: {file_size_mb:.2f} MB\n\n(未安装 python-docx，请 pip install python-docx)",
                    "summary": "Word已上传，python-docx未安装",
                    "detection_required": False
                }
        except Exception as e:
            return {
                "success": False,
                "content": f"Word解析失败: {str(e)}",
                "summary": "Word解析失败"
            }

    def _process_excel(self, file_data: str, ext: str) -> Dict[str, Any]:
        try:
            decoded = base64.b64decode(file_data)
            file_size_mb = len(decoded) / (1024 * 1024)

            try:
                from io import BytesIO
                import openpyxl

                if ext == "xlsx":
                    wb = openpyxl.load_workbook(BytesIO(decoded), read_only=True, data_only=True)
                else:
                    # .xls 旧格式，openpyxl 不支持
                    return {
                        "success": True,
                        "content": f"Excel文件(.xls)，大小: {file_size_mb:.2f} MB\n\n(旧版.xls格式需安装 xlrd 库)",
                        "summary": "Excel(.xls)旧格式",
                        "detection_required": False
                    }

                sheets_info = []
                all_content = []
                for sheet_name in wb.sheetnames:
                    ws = wb[sheet_name]
                    rows = list(ws.iter_rows(values_only=True))
                    sheet_text = "\n".join([
                        "\t".join(str(c) if c is not None else "" for c in row)
                        for row in rows
                    ])
                    all_content.append(f"=== Sheet: {sheet_name} ({len(rows)} 行) ===\n{sheet_text}")
                    sheets_info.append(f"{sheet_name}({len(rows)}行)")

                wb.close()
                content = "\n\n".join(all_content)
                return {
                    "success": True,
                    "content": content,
                    "summary": f"Excel文件(.xlsx)，工作表: {', '.join(sheets_info)}",
                    "detection_required": True
                }
            except ImportError:
                return {
                    "success": True,
                    "content": f"Excel文件已接收，大小: {file_size_mb:.2f} MB\n\n(未安装 openpyxl，请 pip install openpyxl)",
                    "summary": "Excel已上传，openpyxl未安装",
                    "detection_required": False
                }
        except Exception as e:
            return {
                "success": False,
                "content": f"Excel解析失败: {str(e)}",
                "summary": "Excel解析失败"
            }

    def _process_archive(self, file_data: str, ext: str, filename: str) -> Dict[str, Any]:
        """压缩包：列出文件清单，不解压内容（安全考虑）"""
        try:
            decoded = base64.b64decode(file_data)
            file_size_mb = len(decoded) / (1024 * 1024)

            file_list = []
            try:
                import zipfile
                from io import BytesIO

                if ext in ("zip",):
                    with zipfile.ZipFile(BytesIO(decoded)) as zf:
                        file_list = zf.namelist()
                elif ext in ("tar", "gz", "bz2"):
                    import tarfile
                    with tarfile.open(fileobj=BytesIO(decoded), mode="r:*") as tf:
                        file_list = tf.getnames()
                else:
                    return {
                        "success": True,
                        "content": f"压缩包文件({ext})，大小: {file_size_mb:.2f} MB\n\n(格式 {ext} 暂不支持列出内容)",
                        "summary": f"压缩包({ext})",
                        "detection_required": False
                    }

                content = f"压缩包: {filename}\n大小: {file_size_mb:.2f} MB\n包含 {len(file_list)} 个文件:\n\n"
                content += "\n".join(f"  - {f}" for f in file_list[:200])
                if len(file_list) > 200:
                    content += f"\n  ... 共 {len(file_list)} 个文件"

                return {
                    "success": True,
                    "content": content,
                    "summary": f"压缩包({ext})，{len(file_list)} 个文件",
                    "detection_required": True
                }
            except Exception as e:
                return {
                    "success": True,
                    "content": f"压缩包文件已接收，大小: {file_size_mb:.2f} MB\n\n(解析失败: {str(e)})",
                    "summary": f"压缩包({ext})解析失败",
                    "detection_required": False
                }
        except Exception as e:
            return {
                "success": False,
                "content": f"压缩包处理失败: {str(e)}",
                "summary": "压缩包处理失败"
            }

    def _process_unknown(self, file_data: str, file_type: str, filename: str) -> Dict[str, Any]:
        """兜底：尝试按文本解码，失败则返回二进制信息"""
        try:
            decoded = base64.b64decode(file_data)
            file_size_mb = len(decoded) / (1024 * 1024)

            # 尝试按 UTF-8 解码
            try:
                content = decoded.decode('utf-8')
                lines = content.split('\n')
                return {
                    "success": True,
                    "content": content,
                    "summary": f"文件({file_type})，{len(lines)} 行，{len(content)} 字符",
                    "detection_required": True
                }
            except UnicodeDecodeError:
                # 二进制文件，无法按文本解析
                return {
                    "success": True,
                    "content": (
                        f"二进制文件已接收\n"
                        f"文件名: {filename}\n"
                        f"类型: {file_type}\n"
                        f"大小: {file_size_mb:.2f} MB\n\n"
                        f"(该文件类型不支持文本解析，已记录文件信息)"
                    ),
                    "summary": f"二进制文件({file_type})，{file_size_mb:.2f} MB",
                    "detection_required": False
                }
        except Exception as e:
            return {
                "success": False,
                "content": f"文件处理失败: {str(e)}",
                "summary": "文件处理失败"
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
            
            from llm_runtime import load_config
            from llm_providers import build_chat_model
            self.llm = build_chat_model(load_config())
            self.llm_available = self.llm is not None
            # 链模板始终构建：模型接入可在「系统状态-模型接入」中配置并热启用（refresh_llm）
            if True:
                
                self.prompt_template = ChatPromptTemplate.from_messages([
                    ("system", """你是一个面向政企场景的安全智能体。请结合对话历史和之前的工具执行结果，分析用户输入，判断是否需要调用工具。

规则：
1. 仅在用户明确需要执行操作（如读取文件、写入、执行命令、导出数据、搜索知识库、联网搜索）时才调用工具
2. 对于普通问答、闲聊、问候等，不需要调用工具，直接回答
3. 如果之前的工具执行结果已经足够回答用户问题，请返回空的 tool_calls 列表
4. 每次只返回本轮需要执行的工具调用，后续步骤在下一轮迭代中决定
5. 输出必须是合法JSON格式
6. 当用户询问最新/实时/近期/热点/动态类外部信息（如最新新闻、近期政策、天气、行情、热点话题、行业动态）时，**必须调用 web_search 联网检索**；这类提问绝不能使用 read_file 或 search_knowledge 代替

可用工具：
- read_file: 读取工作区内本地文件内容（仅用于读取本地文件，不得用于联网查资料），参数: file_path
- write_file: 写入文件，参数: file_path, content
- execute_command: 执行系统命令，参数: command
- export_data: 导出数据，参数: format, query
- search_knowledge: 搜索本地知识库（政务制度/流程类提问），参数: query
- web_search: 联网搜索外部实时信息（当用户需要查询最新新闻、实时政策、天气、行情、热点话题、行业动态、最新进展等外部信息时使用，这是获取网上实时资讯的唯一工具），参数: query
- draft_document: 起草公文/通知/请示/报告等（拟稿助手），参数: document_type(文种), subject(标题主题), outline(可选要点)
- generate_report: 生成结构化报表（报表/汇总/台账/月报），参数: report_name(报表名), report_type(类型), columns(表头), rows(数据记录), note(口径说明)

输出格式：
{{"tool_calls": [], "reasoning": "直接回答用户问题"}}
{{"tool_calls": [{{"name": "read_file", "args": {{"file_path": "/path/to/file"}}}}], "reasoning": "需要读取文件"}}

之前的工具执行结果：
{tool_results}

对话历史：
{conversation_history}
"""),
                    ("human", "用户当前输入: {user_input}")
                ])
                
                self.response_template = ChatPromptTemplate.from_messages([
                    ("system", """你是一个面向政企场景的安全智能体。请根据对话历史和当前问题，直接、准确地回答用户的问题。

要求：
1. 结合对话历史理解上下文，直接回答用户的具体问题
2. 如果用户引用之前的对话内容（如"上面"、"之前"等），请根据对话历史进行关联回答
3. 如果用户问"你好"，请友好回应并询问具体需求
4. 如果用户问"你是谁"或"你叫什么"，简短介绍自己是政企安全智能体
5. 回答必须符合政务安全规范，不泄露敏感信息
6. 回答要具体、有针对性，不要空泛
7. 使用 Markdown 排版输出（用户界面支持 Markdown 渲染），使回答结构清晰易读：
   - 关键结论或重要事项用 **加粗** 突出
   - 分点说明用 - 无序列表或 1. 有序列表
   - 内容较多时可用 ## 小节标题分层；涉及多字段对照用表格
   - 命令、代码、接口、字段名用反引号 `代码` 包裹，多行代码用 ``` 代码块
   - 不要过度使用标题与列表，保持政务表达的正式、简洁

对话历史：
{conversation_history}
"""),
                    ("human", "用户当前问题: {user_input}\n工具执行结果: {tool_results}")
                ])
                
                self.parser = JsonOutputParser()
            # 流式回答专用通道：run_stream 启动前注入 queue.Queue，response_generation 用它推送 token 增量
            self._stream_sink: Optional["queue.Queue"] = None
            if self.llm_available:
                print("[INFO] LLM 对话主链已启用（可在 系统状态-模型接入 中热更新）")
            else:
                print("[INFO] 未配置模型接入：对话主链使用规则回退（可到 系统状态-模型接入 配置内网模型）")
        except Exception as e:
            print(f"[INFO] LLM initialization failed: {str(e)}, using rule-based fallback")
        
        # 方向A：创新点接入 graph —— 实例化 Plan IR 构建器 + 序列评估器 + 操作守卫
        self.plan_ir_builder = PlanIRBuilder()
        self.sequence_risk_evaluator = SequenceRiskEvaluator()
        self.operation_guard = OperationGuard()
        # 方向A-5：输出过滤器（response_generation 后对响应做敏感数据脱敏）
        self.output_filter = OutputFilter()
        self.graph = self._build_graph()

    def refresh_llm(self, cfg: dict = None) -> bool:
        """模型接入配置保存后热刷新对话主链模型（无需重启），返回是否可用"""
        try:
            from llm_runtime import load_config
            from llm_providers import build_chat_model
            llm = build_chat_model(cfg or load_config())
            self.llm = llm
            self.llm_available = llm is not None
            return self.llm_available
        except Exception:  # noqa: BLE001
            self.llm_available = False
            return False
    
    def _build_graph(self) -> StateGraph:
        workflow = StateGraph(AgentState)
        
        workflow.add_node("input_detection", self.security_layer.detect_input)
        workflow.add_node("risk_assessment", self.risk_assessment)
        workflow.add_node("decision_making", self.decision_making)
        workflow.add_node("tool_selection", self.tool_selection)
        workflow.add_node("plan_ir_build", self._build_plan_ir)
        workflow.add_node("sequence_risk_eval", self._sequence_risk_eval)
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
        
        # 方向A：tool_selection → plan_ir_build → sequence_risk_eval → (route) → tool_evaluation
        workflow.add_edge("tool_selection", "plan_ir_build")
        workflow.add_edge("plan_ir_build", "sequence_risk_eval")
        workflow.add_conditional_edges(
            "sequence_risk_eval",
            self._route_after_sequence_risk,
            {"block": "block_response", "proceed": "tool_evaluation"}
        )
        
        workflow.add_conditional_edges(
            "tool_evaluation",
            self._route_after_tool_evaluation,
            {"block": "block_response", "approval": "approval_check", "execute": "tool_execution"}
        )
        
        workflow.add_conditional_edges(
            "approval_check",
            self._route_after_approval,
            # pending → block_response（生成"待人工审批"提示，非拦截语义）
            {"approved": "tool_execution", "rejected": "block_response", "pending": "block_response"}
        )
        
        # T4: ReAct 循环——tool_execution 后可回到 decision_making 做下一轮迭代
        workflow.add_conditional_edges(
            "tool_execution",
            self._route_after_execution,
            {"block": "block_response", "continue": "decision_making", "end": "response_generation"}
        )
        
        # 方向A-5：response_generation 后接 output_filter（输出层敏感数据脱敏）
        workflow.add_node("output_filter", self.output_filter_node)
        workflow.add_edge("response_generation", "output_filter")
        workflow.add_edge("output_filter", END)
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
        # 异步审批：有待人工审批的请求 → pending（立即返回提示，不阻塞不拒绝）
        if state.get("pending_human_approval"):
            return "pending"
        return "rejected"

    def _route_after_execution(self, state: AgentState) -> str:
        """T4: ReAct 循环路由——决定是否继续下一轮迭代

        终止条件（优先级从高到低）:
        1. 运行时监控已终止会话 → block
        2. 达到最大迭代次数 → end
        3. LLM 未要求继续 → end
        4. 否则 → continue（回到 decision_making）
        """
        session_id = state.get("session_id", "default")

        # 1. 运行时一键终止检查
        if self.security_layer.runtime_monitor.is_terminated(session_id):
            return "block"

        # 2. 最大迭代次数检查
        iteration = state.get("react_iteration", 0)
        max_iter = state.get("react_max_iterations", 3)
        if iteration >= max_iter:
            return "end"

        # 3. LLM 是否要求继续 ReAct
        if state.get("should_continue_react", False):
            return "continue"

        return "end"
    
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
    
    # 工具关键词——命中这些词才可能需要调用工具（文件操作/联网/搜索/执行/导出/生成文档）
    _TOOL_KEYWORDS = frozenset([
        "文件", "读取", "写", "保存", "下载", "上传", "路径", "内容",
        "执行", "运行", "命令", "shell", "cmd", "powershell",
        "搜索", "查询", "查找", "联网", "最新", "实时", "新闻", "动态", "天气", "行情", "热点", "近期",
        "知识库", "制度", "流程",
        "导出", "生成", "报表", "汇总", "台账",
        "公文", "请示", "报告", "通知", "稿",
    ])

    # 安全问答关键词——命中这些词说明是知识问答（不需要工具），快速跳过决策
    _KNOWLEDGE_KEYWORDS = frozenset([
        "是什么", "什么是", "有哪些", "哪些", "分类", "类型", "种类",
        "定义", "解释", "介绍", "简述", "说明", "如何", "怎么", "怎样",
        "为什么", "原因", "原理", "区别", "对比",
        "标准", "规范", "合规", "等保", "密评",
    ])

    def _fast_decision(self, state: AgentState) -> Optional[Dict[str, Any]]:
        """快路径：安全问答（risk=NONE + 无工具关键词）跳过 LLM 决策调用，
        直接返回空 tool_calls → 路由到 response_generation。
        对简单问题节省 ~800-2700ms 的 LLM 决策开销。"""
        risk_val = state.get("risk_level")
        risk_str = risk_val.value if hasattr(risk_val, "value") else str(risk_val or "")
        user_input = (state.get("user_input") or "").strip()

        # 仅首轮迭代走快路径；后续 ReAct 迭代必须走 LLM 判断是否继续
        if state.get("react_iteration", 0) > 0:
            return None

        # 安全检测层已判定 risk≥LOW：安全相关输入继续走 LLM 决策（可能需要工具调用安全扫描等）
        if risk_str not in ("none", "NONE"):
            return None

        # 来源是文件上传/知识库检索：走正常路径（可能需要工具关联）
        if state.get("input_source") in ("uploaded_doc", "knowledge_retrieval"):
            return None

        # 检测是否含工具关键词——命中则需要 LLM 判断具体工具
        input_lower = user_input.lower()
        if any(kw in input_lower for kw in self._TOOL_KEYWORDS):
            return None

        # 命中知识问答关键词或短文本（≤40字符）：直接判定为"普通问答"
        has_kw = any(kw in user_input for kw in self._KNOWLEDGE_KEYWORDS)
        is_short = len(user_input) <= 40
        if not (has_kw or is_short):
            return None

        # 通过快路径：空 tool_calls，直接进入 response_generation
        return {
            **state,
            "tool_calls": [],
            "llm_response": "安全问答，直接回答（fast-path）",
            "should_continue_react": False,
            "current_step": "decision_making_completed",
            "_fast_path": True,
        }

    def decision_making(self, state: AgentState) -> AgentState:
        # --- 快路径：安全问答跳过 LLM 决策 ---
        fast = self._fast_decision(state)
        if fast is not None:
            # 运行时监控留痕（与 LLM 路径一致）
            session_id = state.get("session_id", "default")
            self.security_layer.runtime_monitor.set_user_input(session_id, state["user_input"])
            self.security_layer.runtime_monitor.record_think(
                session_id=session_id,
                reasoning="安全问答，直接回答（快速路径）",
                proposed_tool_calls=[],
            )
            runtime_trace = self._get_runtime_trace(session_id)
            fast["runtime_trace"] = runtime_trace
            return fast

        user_input = state["user_input"]
        conversation_history = state.get("conversation_history", [])
        session_id = state.get("session_id", "default")
        react_iteration = state.get("react_iteration", 0)
        prev_tool_results = state.get("tool_execution_results", [])

        history_str = "\n".join([
            f"{msg['role']}: {msg['content']}"
            for msg in conversation_history[-10:]
        ])

        # T4: 构建之前工具执行结果摘要（供 LLM 判断是否需要继续迭代）
        if prev_tool_results:
            tool_results_str = "\n".join([
                f"- 迭代{react_iteration} | {r.get('tool_name', '?')}: {r.get('result', '')[:200]}"
                for r in prev_tool_results
            ])
        else:
            tool_results_str = "（无，首轮迭代）"

        if self.llm_available:
            try:
                # 直接调用模型（支持 FailoverChatModel 主备容灾；不走 LCEL 管道，避免
                # 非 Runnable 包装类与 prompt | llm 组合报错）
                prompt_messages = self.prompt_template.format_messages(
                    user_input=user_input,
                    conversation_history=history_str,
                    tool_results=tool_results_str,
                )
                # max_tokens 上限：决策只需结构化 JSON（tool_calls+reasoning，通常 <300 token），
                # 防止模型"话痨"式长输出拉长思考期（保持质量前提下缩短时延）
                llm_response = self.llm.invoke(prompt_messages, max_tokens=512)
                raw_text = getattr(llm_response, "content", None)
                if not isinstance(raw_text, str) or not raw_text.strip():
                    raw_text = str(llm_response)
                parsed = self.parser.parse(raw_text)

                tool_calls = parsed.get("tool_calls", [])

                # 上传内容已内联在 user_input 中：对 uploaded_doc 来源过滤文件读取/检索类工具，
                # 防止模型误调 read_file/search_knowledge 而报"文件不存在"。
                if state.get("input_source") == "uploaded_doc":
                    tool_calls = [
                        c for c in tool_calls
                        if c.get("name") not in ("read_file", "search_knowledge", "draft_document", "generate_report", "web_search")
                    ]
                reasoning = parsed.get("reasoning", "")

                # T4: 运行时监控——记录Think阶段
                self.security_layer.runtime_monitor.set_user_input(session_id, user_input)
                self.security_layer.runtime_monitor.record_think(
                    session_id=session_id,
                    reasoning=reasoning,
                    proposed_tool_calls=tool_calls,
                )

                # T4: 设置 ReAct 循环标志——LLM 返回了工具调用则继续迭代
                should_continue = len(tool_calls) > 0

                # T4: 更新运行时轨迹（即使被拦截也能查看Think记录）
                runtime_trace = self._get_runtime_trace(session_id)

                return {
                    **state,
                    "tool_calls": tool_calls,
                    "llm_response": reasoning,
                    "should_continue_react": should_continue,
                    "runtime_trace": runtime_trace,
                    "current_step": "decision_making_completed",
                }
            except Exception as e:
                print(f"[WARN] LLM decision failed: {e}, falling back to rule-based selection")

        # T4: 回退路径——仅首轮迭代做关键词匹配，后续迭代不再调用工具（防止无限循环）
        if react_iteration == 0:
            tool_calls = self._fallback_tool_selection(user_input)
            reasoning = "使用规则匹配进行决策"
        else:
            tool_calls = []
            reasoning = f"规则回退模式：第{react_iteration}轮迭代，无需更多工具调用"

        # T4: 运行时监控——记录Think阶段
        self.security_layer.runtime_monitor.set_user_input(session_id, user_input)
        self.security_layer.runtime_monitor.record_think(
            session_id=session_id,
            reasoning=reasoning,
            proposed_tool_calls=tool_calls,
        )

        # T4: 更新运行时轨迹
        runtime_trace = self._get_runtime_trace(session_id)

        return {
            **state,
            "tool_calls": tool_calls,
            "llm_response": reasoning,
            "should_continue_react": len(tool_calls) > 0,
            "runtime_trace": runtime_trace,
            "current_step": "decision_making_completed",
        }

    def _get_runtime_trace(self, session_id: str) -> List[Dict[str, Any]]:
        """T4: 获取运行时执行轨迹（Think-Act-Observe 全流程）"""
        trace = self.security_layer.runtime_monitor.get_session_trace(session_id)
        return [
            {
                "step_id": s.step_id,
                "step_type": s.step_type,
                "tool_name": s.tool_name,
                "reasoning": s.reasoning[:200] if s.reasoning else "",
                "risk_level": s.risk_level.value,
                "timestamp": s.timestamp,
            }
            for s in trace
        ]
    
    def _fallback_tool_selection(self, user_input: str) -> List[Dict[str, Any]]:
        tool_calls = []

        # 拟稿类请求 → 触发拟稿助手（内部已依据知识库起草，含 AIGC 标识与人工核定提示）
        draft_hint = re.search(
            r"(起草|草拟|拟稿|代拟|帮我写|请写|写一份|拟一份|代写).{0,40}(通知|请示|报告|函|纪要|简报|汇报|方案|说明|汇报材料|公开信|工作总结)",
            user_input,
        )
        if draft_hint:
            subject = user_input.strip().strip("。！？；;")[:80]
            # 尽力识别文种
            doc_type = "通知"
            for t in ("公开信", "工作总结", "汇报材料", "请示", "纪要", "简报", "报告", "汇报", "函", "方案", "通知"):
                if t in subject:
                    doc_type = t
                    break
            tool_calls.append({
                "name": "draft_document",
                "args": {"document_type": doc_type, "subject": subject},
            })
            return tool_calls

        # 报表/统计类请求 → 触发报表助手（据口径/数据生成结构化报表）
        report_hint = re.search(r"(生成|做|做一份|出一份|汇总|统计|列出).{0,30}(报表|汇总表|台账|月报|统计表|数据表)", user_input)
        if report_hint:
            name = user_input.strip().strip("。！？；;")
            name = re.sub(r"^(请|帮我|帮我用AI|让AI)\s*", "", name)[:60]
            rtype = "汇总表"
            for t in ("台账", "月报", "统计表", "汇总表"):
                if t in name:
                    rtype = t
                    break
            tool_calls.append({
                "name": "generate_report",
                "args": {"report_name": name, "report_type": rtype},
            })
            return tool_calls

        # 政务知识/制度类提问 → 优先走知识库语义检索（本地 RAG，命中政务沙盒语料）
        kb_hint = ["依据知识库", "查一下", "查知识库", "知识库", "参考制度", "按制度",
                   "政策", "办事", "办理", "申请条件", "怎么申请", "如何申请",
                   "报销", "差旅", "标准", "流程", "规定", "规范", "制度", "红线",
                   "公租房", "公积金", "社保", "盖章", "用印", "采购", "公文", "审批流程"]
        is_kb_query = any(k in user_input for k in kb_hint)
        if is_kb_query:
            tool_calls.append({
                "name": "search_knowledge",
                "args": {"query": user_input}
            })

        # 联网搜索类提问（最新/实时/近期/热点/网上信息）→ 触发 web_search（真实联网，博查合规 API）
        web_hint = re.search(
            r"(最新|实时|近日|最近|近期|刚刚|今天|当前|当下|目前).{0,12}"
            r"(新闻|政策|天气|行情|动态|消息|通报|价格|热点|进展|趋势|动向|资讯|情况|新闻资讯|热点新闻)|"
            r"(热点|热闻|新鲜事|新消息|最新消息|最新进展|最新动态|最近动态|最近进展|有什么新|网上说的)|"
            r"(网上|网络上|联网|上网|百度一下|搜一下|搜索一下|查一下|去查|搜一搜).{0,16}(看看|什么|吗|一下|结果|资料)|"
            r"(查|搜).{0,10}(最新|实时|最近|近期|热点).{0,12}(新闻|政策|消息|动态|资讯)",
            user_input,
        )
        if web_hint:
            tool_calls.append({
                "name": "web_search",
                "args": {"query": user_input.strip()[:120]}
            })

        # 明确的"读取/查看本地文件"类提问 → 才走文件读取（避免把"搜索/查找/查询"误判为读文件，
        # 这类关键词应优先命中知识库检索或联网搜索）
        if (any(keyword in user_input for keyword in ["读取文件", "查看文件", "打开文件", "读一下", "看下文件", "文件内容", "看看文件"])
                and not is_kb_query and not web_hint):
            tool_calls.append({
                "name": "read_file",
                # 方向A-4：改为白名单内相对路径（原绝对路径 /data/docs/gov_doc.txt 会被沙箱拦截）
                "args": {"file_path": "welcome.txt"}
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
                # 方向B-3：fallback 不再硬编码危险参数（原 SELECT * FROM users 会导出全部用户）
                "args": {"format": "csv", "query": "SELECT * FROM public_reports LIMIT 10"}
            })
        
        return tool_calls
    
    def tool_selection(self, state: AgentState) -> AgentState:
        tool_calls = state["tool_calls"]
        selected_tools = []
        
        for tool_call in tool_calls:
            tool_name = tool_call.get("name", "")
            
            if tool_name in ["read_file", "search_knowledge", "draft_document", "generate_report", "web_search"]:
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

    def _build_plan_ir(self, state: AgentState) -> AgentState:
        """方向A-1：从工具调用序列构建 Plan IR（创新点接入 graph）"""
        tool_calls = state.get("tool_calls", [])
        if not tool_calls:
            return {**state, "plan_ir": None, "current_step": "plan_ir_skipped"}
        session_id = state.get("session_id") or "default"
        plan_id = f"{session_id}-iter{state.get('react_iteration', 0)}"
        plan = self.plan_ir_builder.build_from_calls(
            plan_id=plan_id,
            user_query=state.get("user_input", ""),
            raw_calls=tool_calls,
        )
        print(f"[方向A-1] Plan IR 构建: plan_id={plan.plan_id}, steps={len(plan.calls)}, "
              f"caps={[sorted(c.capabilities) for c in plan.calls]}")
        return {**state, "plan_ir": plan, "current_step": "plan_ir_built"}

    def _sequence_risk_eval(self, state: AgentState) -> AgentState:
        """方向A-2：序列级风险评估，高危序列（如 read_file→export_data）触发阻断"""
        plan = state.get("plan_ir")
        if plan is None:
            return {**state, "sequence_risk_assessment": None,
                    "current_step": "sequence_risk_skipped"}
        assessment = self.sequence_risk_evaluator.assess(plan)
        assessment_dict = assessment.to_dict()
        print(f"[方向A-2] 序列评估: intervention={assessment.intervention.value}, "
              f"risk={assessment.overall_risk_level.value}, score={assessment.overall_risk_score:.3f}")
        return {**state, "sequence_risk_assessment": assessment_dict,
                "current_step": "sequence_risk_evaluated"}

    def _route_after_sequence_risk(self, state: AgentState) -> str:
        """序列评估后路由：intervention=BLOCK → block_response，否则 → tool_evaluation"""
        assessment = state.get("sequence_risk_assessment")
        if assessment and assessment.get("intervention") == InterventionAction.BLOCK.value:
            return "block"
        return "proceed"

    def tool_execution(self, state: AgentState) -> AgentState:
        tool_calls = state["tool_calls"]
        session_id = state.get("session_id", "default")
        react_iteration = state.get("react_iteration", 0)

        # T4: 执行前检查是否已被运行时监控终止
        if self.security_layer.runtime_monitor.is_terminated(session_id):
            return {
                **state,
                "tool_execution_results": state.get("tool_execution_results", []),
                "current_step": "terminated",
                "final_response": "会话已被安全系统终止：检测到运行时异常行为链",
            }

        # T4: 累积所有迭代的执行结果（不是替换）
        execution_results = list(state.get("tool_execution_results", []))

        # 去重护栏：同一请求内"同名同参数"的工具不再重复执行。
        # 判定口径为"此前是否已尝试过"（成功或失败都算）——失败重试同样无意义，
        # 且会形成重试风暴（如沙箱环境异常时 LLM 反复下发同一调用）把请求拖到迭代上限超时。
        # 一次性生成类工具（拟稿/报表）：同名即视为重复（即使参数微调也禁止重入），
        # 防止 LLM 每轮追加 outline 等参数重跑完整长文生成，把单请求拖到分钟级。
        _ONE_SHOT_TOOLS = {"draft_document", "generate_report"}

        def _tool_sig(name: str, args: dict) -> str:
            if name in _ONE_SHOT_TOOLS:
                return name
            return f"{name}|{json.dumps(args or {}, sort_keys=True, ensure_ascii=False)}"

        _attempted_sigs = {
            _tool_sig(r.get("tool_name", ""), r.get("args", {}) or {})
            for r in execution_results
        }
        _pending_calls = [
            tc for tc in tool_calls
            if _tool_sig(tc.get("name", ""), tc.get("args", {}) or {}) not in _attempted_sigs
        ]
        if not _pending_calls:
            # 本次要调用的工具此前均已尝试过 → 直接结束 ReAct 循环（不再重复执行）
            return {
                **state,
                "tool_execution_results": execution_results,
                "should_continue_react": False,
                "current_step": "tool_execution_completed",
            }
        tool_calls = _pending_calls

        for tool_call in tool_calls:
            tool_name = tool_call.get("name", "")
            tool_args = tool_call.get("args", {})

            # 方向B-2：能力令牌校验 — 默认最小权限，未授权能力一律拒绝。
            # 这是检测层失效时的兜底防线：即使 input_detection 被绕过、
            # 风险评估被误判，能力不足的工具调用仍会被拒绝（默认 deny）。
            token_check = self.security_layer.capability_tokens.check(session_id, tool_name)
            print(f"[方向B-2] capability_token: tool={tool_name}, allowed={token_check.allowed}, "
                  f"missing={sorted(token_check.missing_capabilities) if not token_check.allowed else '-'}, "
                  f"check_ms={token_check.duration_ms:.3f}")
            if not token_check.allowed:
                result = {
                    "tool_name": tool_name,
                    "args": tool_args,
                    "result": f"[capability_token 拒绝] {token_check.reason}",
                    "status": "blocked",
                    "blocked_by": "capability_token",
                    "missing_capabilities": sorted(token_check.missing_capabilities),
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "react_iteration": react_iteration,
                }
                execution_results.append(result)
                continue

            # 方向A-3：operation_guard 参数级校验（执行前最后一道防线）
            intent = OperationIntent(
                tool_name=tool_name,
                parameters=tool_args,
                session_id=session_id,
                user_input=state.get("user_input", ""),
            )
            guard_result = self.operation_guard.check_intent(intent)
            print(f"[方向A-3] operation_guard: tool={tool_name}, allowed={guard_result.allowed}, "
                  f"requires_approval={guard_result.requires_approval}, blocked_by={guard_result.blocked_by}")
            if not guard_result.allowed:
                result = {
                    "tool_name": tool_name,
                    "args": tool_args,
                    "result": f"[operation_guard 拦截] {guard_result.reason}",
                    "status": "blocked",
                    "blocked_by": guard_result.blocked_by,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "react_iteration": react_iteration,
                }
                execution_results.append(result)
                continue

            # 方向A-4：受限真执行（Docker 沙箱可用则 Docker，否则白名单路径本地真执行）
            tool_result = docker_executor.execute(tool_name, tool_args)
            result = {
                "tool_name": tool_name,
                "args": tool_args,
                "result": tool_result.output if tool_result.success else tool_result.error,
                "status": "success" if tool_result.success else "error",
                "sandbox_mode": tool_result.sandbox_mode,
                "duration_ms": round(tool_result.duration_ms, 1),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "react_iteration": react_iteration,
            }

            execution_results.append(result)

            # T4: 运行时监控——记录Observe阶段
            self.security_layer.runtime_monitor.record_observe(
                session_id=session_id,
                tool_name=tool_name,
                result=result,
                success=tool_result.success,
            )

            # 审计：记录工具返回值（审计完整性-返回值）
            try:
                think_text = ""
                for s in reversed(self.security_layer.runtime_monitor.get_session_trace(session_id)):
                    if s.step_type == "think":
                        think_text = s.reasoning
                        break
                self.security_layer.audit_logger.create_log(
                    user_id=state.get("user_id") or "user",
                    user_role=state.get("user_role") or "user",
                    agent_id="gov_agent",
                    action_type="tool_execution",
                    action_details={"tool_name": tool_name, "tool_args": tool_args,
                                    "status": "success",
                                    "department": state.get("department") or "",
                                    "actor_name": state.get("display_name") or state.get("user_id") or "user"},
                    risk_level=RiskLevel.NONE,
                    is_blocked=False,
                    session_id=session_id,
                    think_text=think_text,
                    return_value=str(result.get("result", ""))[:500],
                )
            except Exception:
                pass

        # 获取运行时执行轨迹（包含所有迭代的 Think-Act-Observe）
        runtime_trace = self.security_layer.runtime_monitor.get_session_trace(session_id)
        trace_dicts = [
            {
                "step_id": s.step_id,
                "step_type": s.step_type,
                "tool_name": s.tool_name,
                "reasoning": s.reasoning[:200] if s.reasoning else "",
                "risk_level": s.risk_level.value,
                "timestamp": s.timestamp,
            }
            for s in runtime_trace
        ]

        return {
            **state,
            "tool_execution_results": execution_results,
            "runtime_trace": trace_dicts,
            "react_iteration": react_iteration + 1,
            "current_step": "tool_execution_completed",
        }
    
    def response_generation(self, state: AgentState) -> AgentState:
        user_input = state["user_input"]
        tool_results = state.get("tool_execution_results", [])
        conversation_history = state.get("conversation_history", [])
        session_id = state.get("session_id", "default")

        # AIGC 内容标识：构建元数据（模型信息 + 服务提供者 + 备案号）
        from security.aigc_labeling import build_aigc_metadata, apply_aigc_label
        aigc_metadata = build_aigc_metadata(session_id=session_id)
        
        history_str = "\n".join([
            f"{msg['role']}: {msg['content'][:300]}"
            for msg in conversation_history[-10:]
        ])
        
        if self.llm_available:
            try:
                tool_results_str = "\n".join([f"{r['tool_name']}: {r['result']}" for r in tool_results])
                sink = getattr(self, "_stream_sink", None)
                if sink is not None:
                    # 流式回答：逐 token 推送增量到 SSE 通道
                    # max_tokens 上限：限制最坏生成时长（约 3000+ 中文字符，正常问答足够）
                    prompt_messages = self.response_template.format_messages(
                        user_input=user_input,
                        tool_results=tool_results_str,
                        conversation_history=history_str,
                    )
                    parts: List[str] = []
                    for tok in self.llm.stream(prompt_messages, max_tokens=2048):
                        t = getattr(tok, "content", None)
                        if t == "" or t is None:
                            continue
                        parts.append(str(t))
                        sink.put(("content", {"delta": str(t)}))
                    final_response = "".join(parts)
                    if not final_response:
                        prompt_messages = self.response_template.format_messages(
                            user_input=user_input,
                            tool_results=tool_results_str,
                            conversation_history=history_str,
                        )
                        final_response = self.llm.invoke(prompt_messages, max_tokens=2048).content
                else:
                    prompt_messages = self.response_template.format_messages(
                        user_input=user_input,
                        tool_results=tool_results_str,
                        conversation_history=history_str,
                    )
                    final_response = self.llm.invoke(prompt_messages, max_tokens=2048).content
                
                # AIGC 标识应用：使用策略管理器中的配置
                from security.policy_manager import get_policy_manager
                from security.aigc_labeling import apply_aigc_label
                policy = get_policy_manager()
                
                labeled = apply_aigc_label(
                    final_response, 
                    aigc_metadata,
                    include_implicit=policy.aigc_implicit_marker_enabled,
                    include_explicit=policy.aigc_explicit_label_enabled
                )
                
                self.security_layer.audit_logger.create_log(
                    user_id=state.get("user_id") or "user",
                    user_role=state.get("user_role") or "user",
                    agent_id="gov_agent",
                    action_type="response_generation",
                    action_details={"response_length": len(final_response),
                                    "aigc_labeled": True,
                                    "content_id": aigc_metadata["content_id"],
                                    "department": state.get("department") or "",
                                    "actor_name": state.get("display_name") or state.get("user_id") or "user"},
                    risk_level=RiskLevel.NONE,
                    session_id=session_id,
                )
                
                return {
                    **state,
                    "final_response": labeled["labeled_content"],
                    "aigc_metadata": labeled["metadata"],
                    "current_step": "completed",
                }
            except Exception as e:
                print(f"[WARN] LLM response generation failed: {e}, falling back to rule-based response")
        
        final_response = self._fallback_response(user_input, tool_results,
                                                 llm_configured=self.llm_available)
        
        # AIGC 标识应用：使用策略管理器中的配置
        from security.policy_manager import get_policy_manager
        from security.aigc_labeling import apply_aigc_label
        policy = get_policy_manager()
        
        labeled = apply_aigc_label(
            final_response, 
            aigc_metadata,
            include_implicit=policy.aigc_implicit_marker_enabled,
            include_explicit=policy.aigc_explicit_label_enabled
        )
        
        self.security_layer.audit_logger.create_log(
            user_id=state.get("user_id") or "user",
            user_role=state.get("user_role") or "user",
            agent_id="gov_agent",
            action_type="response_generation",
            action_details={"response_length": len(final_response),
                            "aigc_labeled": True,
                            "content_id": aigc_metadata["content_id"],
                            "department": state.get("department") or "",
                            "actor_name": state.get("display_name") or state.get("user_id") or "user"},
            risk_level=RiskLevel.NONE,
            session_id=session_id,
        )
        
        return {
            **state,
            "final_response": labeled["labeled_content"],
            "aigc_metadata": labeled["metadata"],
            "current_step": "completed",
        }

    # 方向A-5：输出过滤节点——response_generation 后对 final_response 做敏感数据脱敏
    def output_filter_node(self, state: AgentState) -> AgentState:
        """对最终响应做敏感数据脱敏（PII / 密钥 / 银行卡 / JWT / 私网 IP）

        - 默认仅脱敏不阻断（保留前4后4位，中间 *** ）
        - 记审计日志（action_type=output_filter，含脱敏摘要，不含原始敏感值）
        """
        final_response = state.get("final_response", "") or ""
        session_id = state.get("session_id", "default")

        if not final_response:
            return {**state, "output_filter_result": {"filtered_count": 0, "by_type": {}, "has_critical": False}}

        result = self.output_filter.sanitize(final_response)
        audit_summary = result.to_audit_dict()

        # 仅在发生脱敏时记审计，避免无谓日志
        if result.filtered_count > 0:
            risk_level = RiskLevel.HIGH if result.has_critical else RiskLevel.MEDIUM
            self.security_layer.audit_logger.create_log(
                user_id=state.get("user_id") or "user",
                user_role=state.get("user_role") or "user",
                agent_id="gov_agent",
                action_type="output_filter",
                action_details={
                    "filtered_count": audit_summary["filtered_count"],
                    "by_type": audit_summary["by_type"],
                    "has_critical": audit_summary["has_critical"],
                    "original_length": len(final_response),
                    "filtered_length": len(result.filtered),
                    "department": state.get("department") or "",
                    "actor_name": state.get("display_name") or state.get("user_id") or "user",
                },
                risk_level=risk_level,
                session_id=session_id,
            )

        return {
            **state,
            "final_response": result.filtered,
            "output_filter_result": audit_summary,
        }

    def _fallback_response(self, user_input: str, tool_results: List[Dict[str, Any]],
                           llm_configured: bool = False) -> str:
        """当LLM不可用时（未配置 或 调用失败），使用规则模板生成有意义的回复

        Args:
            user_input: 用户输入
            tool_results: 工具执行结果
            llm_configured: True=LLM已配置但调用失败（降级）；False=LLM根本未配置
        """
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
            if llm_configured:
                response_parts.append("\n注意：AI 模型服务暂不可用（连接超时或密钥失效），已使用规则引擎降级回复。请检查模型接入配置。")
            else:
                response_parts.append("\n注意：当前运行在演示模式（LLM未配置），上述为规则引擎响应。")
            return "\n".join(response_parts)
        
        # 默认回复
        if llm_configured:
            hint = (
                "AI 模型服务暂不可用（可能原因：API Key 失效/过期、网络不通、额度耗尽），"
                "已降级为规则引擎回复。请在「系统与运维 → 模型接入配置」中检查并修复。"
            )
        else:
            hint = "由于当前LLM未配置，我无法生成更详细的自然语言回复。如需完整的智能问答能力，请配置 API Key。"
        return (
            f"关于「{user_input[:30]}{'...' if len(user_input) > 30 else ''}」，以下是相关信息：\n\n"
            f"本平台已对您的输入完成了多层安全检测（规则引擎+AI检测+向量投毒检测），未发现安全风险。\n\n"
            f"{hint}\n\n"
            f"您可以：\n"
            f"1. 在「安全检测」标签页体验安全扫描功能\n"
            f"2. 在「插件扫描」标签页测试供应链安全检测\n"
            f"3. 在「系统与运维 → 模型接入配置」中接入大模型"
        )
    
    def block_response(self, state: AgentState) -> AgentState:
        # 异步审批流：待人工审批（非拦截语义）→ 友好提示，请求持久 pending
        pending_approvals = state.get("pending_human_approval") or []
        if pending_approvals:
            lines = []
            for p in pending_approvals:
                lines.append(
                    f"- 工具 {p.get('tool_name', '?')}（风险等级: {p.get('risk_level', '?')}，"
                    f"审批单号: {p.get('request_id', '?')}）"
                )
            pending_message = f"""
您的请求需要人工审批后才能执行。

待审批事项:
{chr(10).join(lines)}

说明:
- 审批请求已提交，管理员可在"安全检测 - 审批管理"页面处理
- 批准后重新发送本请求即可自动执行（同一会话内无需重复审批）
- 如有疑问请联系系统管理员
"""
            return {
                **state,
                "final_response": pending_message,
                "can_proceed": False,
                "current_step": "approval_pending",
            }

        risk_level = state["risk_level"]
        detection_results = state.get("detection_results", [])
        session_id = state.get("session_id", "default")

        # 收集证据，确保记忆安全检测（第6层）证据不被截断丢失
        evidence = []
        memory_evidence = []
        for result in detection_results:
            for e in result.evidence:
                # 第6层证据单独收集，优先展示
                if "记忆安全检测" in e or "记忆写入拦截" in e or "记忆读取拦截" in e \
                        or "持久化注入" in e or "政务篡改" in e or "写入指令" in e \
                        or "跨会话异常" in e or "敏感信息记忆" in e:
                    memory_evidence.append(e)
                else:
                    evidence.append(e)
        # 非记忆证据最多保留前5条，记忆证据全部保留，放在前面突出显示
        evidence = memory_evidence + evidence[:5]
        if memory_evidence and "记忆安全检测" not in evidence:
            evidence.insert(0, "记忆安全检测")

        # T4: 收集运行时异常告警证据
        anomaly_alerts = state.get("anomaly_alerts", [])
        runtime_evidence = []
        if anomaly_alerts:
            runtime_evidence.append("=== 运行时异常检测告警 ===")
            for alert in anomaly_alerts:
                runtime_evidence.append(
                    f"[{alert.get('severity', '?').upper()}] {alert.get('alert_type', '?')}: "
                    f"{alert.get('description', '')}"
                )

        # T4: 运行时终止信息
        if self.security_layer.runtime_monitor.is_terminated(session_id):
            runtime_evidence.insert(0, "=== 会话已被运行时监控终止 ===")

        # T4: guard_results 中的拦截信息
        guard_results = state.get("guard_results", [])
        guard_evidence = []
        for g in guard_results:
            if not g.get("allowed", True):
                guard_evidence.append(
                    f"[操作守卫] {g.get('tool_name', '?')}: {g.get('reason', '')}"
                )

        all_evidence = memory_evidence + evidence[:5] + guard_evidence + runtime_evidence

        block_message = f"""
您的请求已被安全系统拦截！

风险等级: {risk_level.value.upper()}

风险原因:
{chr(10).join(f"- {e}" for e in all_evidence[:20])}

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
    
    def _prepare_initial_state(self, session_id: str, user_input: str, input_source: str,
                               user: Optional[Dict[str, Any]], conversation_history: List[Dict[str, Any]]) -> AgentState:
        """组装 LangGraph 初始状态，供同步 invoke 与流式 stream 复用，保证节点副作用一致。"""
        identity = user or {}
        return {
            "user_input": user_input,
            "input_source": input_source,
            "session_id": session_id,
            # 操作者身份：贯穿 agent 审计/审批到真实登录账号+部门
            "user_id": identity.get("username") or "user",
            "user_role": identity.get("role") or "user",
            "department": identity.get("department") or "",
            "display_name": identity.get("display_name") or identity.get("username") or "user",
            "detection_results": [],
            "risk_level": RiskLevel.NONE,
            "risk_summary": None,
            "can_proceed": True,
            "tool_calls": [],
            "tool_risk_results": [],
            "tool_execution_results": [],
            "approval_requests": [],
            "approval_status": {},
            "pending_human_approval": [],
            "plugin_scan_results": [],
            "conversation_history": conversation_history,
            "current_step": "start",
            "final_response": None,
            "audit_logs": [],
            "llm_response": None,
            "guard_results": [],
            "runtime_trace": [],
            "anomaly_alerts": [],
            # T4: ReAct 循环控制
            "react_iteration": 0,
            # ReAct 最大迭代 3（首轮通常即出结果；限制最坏情况额外 LLM 往返，避免长尾时延）
            "react_max_iterations": 3,
            "should_continue_react": False,
            # T5 合规：AIGC 内容标识元数据
            "aigc_metadata": None,
        }

    # ---------- "思考中"功能：将真实图节点产出整理为对用户可读的推理步骤 ----------
    _THINKING_NODE_MAP = {
        # node -> (phase, title, 详情字段提取函数索引)
        "input_detection": ("analysis", "分析问题与安全检测", "detection"),
        "risk_assessment": ("analysis", "评估风险等级", "risk"),
        "decision_making": ("decision", "判断回答方式", "decision"),
        "tool_selection": ("plan", "规划工具调用", "tool"),
        "plan_ir_build": ("plan", "构建执行计划", "plan"),
        "sequence_risk_eval": ("logic", "校验执行序列风险", "sequence"),
        "tool_evaluation": ("logic", "执行工具安全校验", "toolval"),
        "approval_check": ("logic", "检查权限审批", "approval"),
        "tool_execution": ("retrieval", "检索信息与执行工具", "exec"),
        "response_generation": ("answer", "组织最终答案", "gen"),
        "output_filter": ("answer", "校验并输出结果", "filter"),
    }

    def _build_thinking_step(self, node_name: str, node_update: Dict[str, Any], step_id: int) -> Optional[Dict[str, Any]]:
        """根据单个节点产出生成一条用户友好的推理步骤（不做模拟，仅真实节点数据）。"""
        mapping = self._THINKING_NODE_MAP.get(node_name)
        if not mapping:
            return None
        phase, title, kind = mapping
        detail = self._format_node_detail(kind, node_update, node_name)
        if detail is None:
            return None
        return {
            "step_id": step_id,
            "phase": phase,
            "phase_label": {"analysis": "问题分析", "decision": "意图决策", "plan": "规划",
                            "logic": "推理", "retrieval": "信息检索", "answer": "答案构建"}.get(phase, phase),
            "title": title,
            "detail": detail,
            "node": node_name,
        }

    @staticmethod
    def _safe_text(v: Any, limit: int = 120) -> str:
        s = "".join(str(v)).replace("\n", " ").replace("\r", " ") if v is not None else ""
        return s[:limit] + ("…" if len(s) > limit else "")

    def _format_node_detail(self, kind: str, update: Dict[str, Any], node: str) -> Optional[str]:
        try:
            if kind == "detection":
                rl = getattr(update.get("risk_level"), "value", str(update.get("risk_level") or "none"))
                return f"已对输入完成多层安全检测，当前风险等级：{rl}。确认内容安全后继续处理。"
            if kind == "risk":
                rs = update.get("risk_summary")
                if rs:
                    s = self._safe_text(rs.get("summary") or json.dumps(rs, ensure_ascii=False), 120)
                    return s
                return None
            if kind == "decision":
                tool_calls = update.get("tool_calls") or []
                if tool_calls:
                    names = ", ".join(self._safe_text(t.get("name") or t.get("tool_name") or "工具", 30)
                                      for t in tool_calls[:3])
                    return f"判断需要调用工具来获取更准确的信息，计划使用：{names}。"
                return "判断可直接基于已有知识作答，无需调用外部工具。"
            if kind == "tool":
                calls = update.get("tool_calls") or []
                if calls:
                    names = ", ".join(self._safe_text(t.get("name") or t.get("tool_name") or "工具", 30)
                                      for t in calls[:3])
                    return f"规划本次回答需要使用的工具：{names}。"
                return None
            if kind == "plan":
                pir = update.get("plan_ir")
                if pir is not None:
                    s = self._safe_text(str(pir), 150)
                    return f"已制定执行计划：{s}"
                return None
            if kind == "sequence":
                seq = update.get("sequence_risk_assessment")
                if seq:
                    level = seq.get("overall_risk") or seq.get("risk_level") or "低"
                    return f"对计划的执行序列做了风险校验，整体序列风险：{self._safe_text(level, 30)}。"
                return None
            if kind == "toolval":
                results = update.get("tool_risk_results")
                if results is not None:
                    danger = sum(1 for r in results if getattr(getattr(r, "risk_level", None), "value", "") in ("HIGH", "CRITICAL"))
                    return f"对计划调用的工具逐一做过安全检查，共 {len(results)} 项{('，其中 ' + str(danger) + ' 项命中高危') if danger else ''}。"
                return None
            if kind == "approval":
                pend = update.get("pending_human_approval") or []
                if pend:
                    return f"相关操作需要人工审批后方可执行，共 {len(pend)} 项待审批。"
                can = update.get("can_proceed")
                if can is not None:
                    return "权限校验通过，可安全执行。"
                return None
            if kind == "exec":
                results = update.get("tool_execution_results") or []
                if results:
                    parts = []
                    for r in results[:2]:
                        status = "成功" if r.get("status") in ("success", "ok") else "完成"
                        out = self._safe_text(r.get("output") or r.get("summary") or "", 90)
                        parts.append(f"「{self._safe_text(r.get('tool_name') or '工具', 20)}」{status}" + (f"：{out}" if out else ""))
                    joined = "；".join(parts)
                    if len(results) > 2:
                        joined += f"（另有 {len(results) - 2} 项）"
                    return f"已检索/执行工具获取关键信息：{joined}"
                return None
            if kind == "gen":
                # response_generation 本身产出最终答案，思考区仅提示，不重复展示大段答案
                return "信息已齐备，开始组织并生成最终答案。"
            if kind == "filter":
                fpr = update.get("output_filter_result")
                if fpr:
                    cnt = fpr.get("filtered_count") or 0
                    by = fpr.get("by_type") or {}
                    kinds = "、".join(k for k, c in by.items() if c) if isinstance(by, dict) else ""
                    suffix = f"，已脱敏 {cnt} 处（{kinds}）" if cnt else ""
                    return f"对生成结果做了输出安全校验{suffix}，确认无敏感信息泄露。"
                return None
        except Exception:
            # 个别节点无法格式化时不阻塞流式展示
            return None
        return None

    def run_with_history(self, session_id: str, user_input: str, input_source: str = "user_input",
                         user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        conversation_history = self.conversation_manager.get_history(session_id)
        initial_state = self._prepare_initial_state(session_id, user_input, input_source, user, conversation_history)

        result = self.graph.invoke(initial_state)

        final_response = result.get("final_response", "")
        self.conversation_manager.add_message(session_id, "user", user_input)
        self.conversation_manager.add_message(session_id, "assistant", final_response)

        return {
            "final_response": final_response,
            "risk_level": result.get("risk_level", RiskLevel.NONE).value,
            "can_proceed": result.get("can_proceed", False),
            "current_step": result.get("current_step"),
            # 异步审批：待人工审批事项（current_step=approval_pending 时非空）
            "pending_human_approval": result.get("pending_human_approval", []),
            "detection_results": [r.dict() for r in result.get("detection_results", [])],
            "tool_risk_results": [r.dict() for r in result.get("tool_risk_results", [])],
            # 方向A-4：工具真实执行结果（沙箱执行器的 output/status/sandbox_mode）
            "tool_execution_results": result.get("tool_execution_results", []),
            "llm_response": result.get("llm_response"),
            "session_id": session_id,
            "conversation_history": self.conversation_manager.get_history(session_id),
            # T4: 运行时监控信息
            "runtime_trace": result.get("runtime_trace", []),
            "anomaly_alerts": result.get("anomaly_alerts", []),
            "react_iteration": result.get("react_iteration", 0),
            "guard_results": result.get("guard_results", []),
            # T5 合规：AIGC 内容标识元数据
            "aigc_metadata": result.get("aigc_metadata", None),
        }
    
    def run_stream(self, session_id: str, user_input: str, input_source: str = "user_input",
                   user: Optional[Dict[str, Any]] = None):
        """同步干跑 LangGraph 的全部节点，并以生成器实时产出"思考"步骤、AI 回答 token 增量与最终结果。

        产出事件：
          ("thinking", step)    逐条实时推送的思考步骤
          ("content", {"delta": ...})   AI 回答逐 token 增量（LLM 支持流式时）
          ("done", result)      收尾（含完整 final_response）
          ("error", {"message": ...})  失败兜底
        不改变任何节点的真实执行/审计/审批副作用。
        """
        conversation_history = self.conversation_manager.get_history(session_id)

        def _to_jsonable(v: Any):
            if hasattr(v, "dict"):
                return v.dict()
            if hasattr(v, "model_dump"):
                return v.model_dump(mode="json")
            if hasattr(v, "value"):  # RiskLevel 枚举
                return v.value
            return v

        initial_state = self._prepare_initial_state(session_id, user_input, input_source, user, conversation_history)
        running_state: Dict[str, Any] = dict(initial_state)

        # 通过后台线程运行图：response_generation 的 token 增量与各节点思考步骤统一进入 sink 队列，
        # 主生成器按序取出实时 yield，从而真实"边生成边推送" AI 回答内容。
        sink: "queue.Queue" = queue.Queue()
        self._stream_sink = sink

        def _run_graph() -> None:
            thinking_steps_t: List[Dict[str, Any]] = []
            try:
                for chunk in self.graph.stream(initial_state, stream_mode="updates"):
                    if not isinstance(chunk, dict):
                        continue
                    for node_name, node_update in chunk.items():
                        if isinstance(node_update, dict):
                            running_state.update(node_update)
                        step = self._build_thinking_step(node_name, node_update, len(thinking_steps_t) + 1)
                        if step:
                            thinking_steps_t.append(step)
                            sink.put(("thinking", step))
                sink.put(("_complete", running_state, thinking_steps_t))
            except Exception as e:  # noqa: BLE001
                try:
                    sink.put(("error", {"message": str(e)}))
                except Exception:  # noqa: BLE001
                    pass

        thread = threading.Thread(target=_run_graph, daemon=True)
        thinking_steps: List[Dict[str, Any]] = []
        thread.start()
        try:
            while True:
                item = sink.get()
                kind = item[0]
                if kind == "thinking":
                    thinking_steps.append(item[1])
                    yield ("thinking", item[1])
                elif kind == "content":
                    yield ("content", item[1])
                elif kind == "error":
                    yield ("error", item[1])
                    return
                elif kind == "_complete":
                    running_state = item[1]
                    break
        finally:
            self._stream_sink = None
            thread.join(timeout=1.0)

        final_response = running_state.get("final_response") or ""
        rl = running_state.get("risk_level")
        meta = json.dumps({"thinking_steps": thinking_steps}, ensure_ascii=False) if thinking_steps else None
        # 与同步路径一致：落库 user 消息与 assistant 消息（assistant 附带思考过程元数据）
        self.conversation_manager.add_message(session_id, "user", user_input)
        self.conversation_manager.add_message(session_id, "assistant", final_response, metadata=meta)

        yield ("done", {
            "final_response": final_response,
            "risk_level": _to_jsonable(rl),
            "can_proceed": running_state.get("can_proceed", False),
            "current_step": running_state.get("current_step"),
            "pending_human_approval": running_state.get("pending_human_approval", []),
            "detection_results": [_to_jsonable(r) for r in running_state.get("detection_results", [])],
            "tool_risk_results": [_to_jsonable(r) for r in running_state.get("tool_risk_results", [])],
            "tool_execution_results": running_state.get("tool_execution_results", []),
            "llm_response": running_state.get("llm_response"),
            "session_id": session_id,
            "runtime_trace": running_state.get("runtime_trace", []),
            "anomaly_alerts": running_state.get("anomaly_alerts", []),
            "guard_results": [_to_jsonable(r) for r in running_state.get("guard_results", [])],
            "thinking_steps": thinking_steps,
        })

    def run(self, user_input: str, input_source: str = "user_input", session_id: Optional[str] = None,
            user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        # 会话归属当前登录用户：新会话/首次落库时绑定 user_id，实现账户会话隔离
        user_id = (user or {}).get("username") or None
        if not session_id:
            session_id = self.conversation_manager.create_session(user_id)
        else:
            # 外部传入的 session_id 可能尚未在 DB 中创建，确保存在以避免外键失败
            session_id = self.conversation_manager.ensure_session(session_id, user_id)

        return self.run_with_history(session_id, user_input, input_source, user=user)

    def process_file_message(self, session_id: str, files, user_text: str = None,
                             user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """多文件上传处理：逐个识别/提取 → 安全检测 → 合并内容进入主链。

        files: List[Dict]，每项含 file_data / file_type / filename。
        任一文件检测到高危/严重风险即拦截整个上传批次。
        """
        content_parts = []
        for f in files:
            processed = self.file_processor.process_file(f["file_data"], f["file_type"], f["filename"])
            content = processed.get("content") or processed.get("text") or ""

            if processed["detection_required"] and content:
                detection_result = self.security_layer.input_detector.detect_single_input(
                    content,
                    source="uploaded_doc",
                    session_id=session_id,
                )

                if detection_result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                    self.conversation_manager.add_message(session_id, "user", f"[文件上传] {f['filename']}")
                    self.conversation_manager.add_message(session_id, "assistant",
                        f"文件 {f['filename']} 包含安全风险内容，已被拦截！\n风险等级: {detection_result.risk_level.value}")

                    return {
                        "success": False,
                        "message": f"文件内容检测到安全风险，已被拦截",
                        "risk_level": detection_result.risk_level.value,
                        "session_id": session_id,
                        "conversation_history": self.conversation_manager.get_history(session_id),
                    }

            if content:
                content_parts.append(f"[{f['filename']}]\n{content}")

        # 上传内容已在此处完整提供（图片已自动 OCR 识别为文字），
        # 文件读取/检索类工具由 decision_making 中的 uploaded_doc 硬防护统一过滤。
        content_body = "\n\n".join(content_parts) or ""
        user_input = f"以下文字是用户上传内容识别出的结果，请直接基于这段文字分析并回答：\n{content_body[:4000]}"
        # 用户上传时一并输入的附言/提问：合并进输入，让模型结合图片/文件内容回答
        if user_text:
            user_input += f"\n\n用户针对该上传内容的补充提问/要求：\n{user_text}"

        history_user = "[文件上传] " + "、".join(f["filename"] for f in files)
        if user_text:
            history_user += f"\n用户附言：{user_text}"
        self.conversation_manager.add_message(session_id, "user", history_user)

        return self.run_with_history(session_id, user_input, "uploaded_doc", user=user)

    def process_file_message_stream(self, session_id: str, files, user_text: str = None,
                                    user: Optional[Dict[str, Any]] = None):
        """附件问答流式版：识别阶段先推送思考步骤，之后复用 run_stream 全量流式（思考步骤 + AI token 增量 + done）。

        与 process_file_message 保持相同的真实执行副作用（识别、检测、落库）。
        files: List[Dict]，每项含 file_data / file_type / filename。
        """
        step_no = 0
        step_no += 1
        yield ("thinking", {"step": step_no, "phase": "uploaded_doc", "phase_label": "上传内容识别",
                            "title": "正在识别上传文件内容", "detail": f"文件数：{len(files)}", "node": "file_processing"})

        content_parts = []
        for f in files:
            processed = self.file_processor.process_file(f["file_data"], f["file_type"], f["filename"])
            content = processed.get("content") or processed.get("text") or ""

            if processed["detection_required"] and content:
                detection_result = self.security_layer.input_detector.detect_single_input(
                    content,
                    source="uploaded_doc",
                    session_id=session_id,
                )
                if detection_result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                    self.conversation_manager.add_message(session_id, "user", f"[文件上传] {f['filename']}")
                    self.conversation_manager.add_message(session_id, "assistant",
                        f"文件 {f['filename']} 包含安全风险内容，已被拦截！\n风险等级: {detection_result.risk_level.value}")
                    yield ("done", {
                        "final_response": f"文件 {f['filename']} 包含安全风险内容，已被拦截！\n风险等级: {detection_result.risk_level.value}",
                        "risk_level": detection_result.risk_level.value,
                        "session_id": session_id,
                        "thinking_steps": [],
                    })
                    return

            if content:
                content_parts.append(f"[{f['filename']}]\n{content}")

        content_body = "\n\n".join(content_parts) or ""
        user_input = f"以下文字是用户上传内容识别出的结果，请直接基于这段文字分析并回答：\n{content_body[:4000]}"
        # 用户上传时一并输入的附言/提问：合并进输入，让模型结合图片/文件内容回答
        if user_text:
            user_input += f"\n\n用户针对该上传内容的补充提问/要求：\n{user_text}"

        history_user = "[文件上传] " + "、".join(f["filename"] for f in files)
        if user_text:
            history_user += f"\n用户附言：{user_text}"
        self.conversation_manager.add_message(session_id, "user", history_user)

        # 复用全量流式：graph 各节点思考步骤 + AI 回答逐 token 增量 + done 收尾
        for event_type, payload in self.run_stream(session_id, user_input, "uploaded_doc", user=user):
            yield (event_type, payload)
    
    def get_conversation_history(self, session_id: str) -> Dict[str, Any]:
        history = self.conversation_manager.get_history(session_id)
        return {
            "session_id": session_id,
            "messages": history,
            "count": len(history)
        }
    
    def create_new_session(self, user_id: str = None) -> Dict[str, Any]:
        session_id = self.conversation_manager.create_session(user_id)
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
    
    def list_sessions(self, user_id: str = None) -> Dict[str, Any]:
        sessions = self.conversation_manager.list_sessions(user_id)
        return {
            "sessions": sessions,
            "count": len(sessions)
        }

    def delete_session(self, session_id: str) -> Dict[str, Any]:
        """删除整个历史会话（会话及全部消息）"""
        existed = self.conversation_manager.storage.get_session(session_id) is not None
        self.conversation_manager.delete_session(session_id)
        return {
            "success": True,
            "session_id": session_id,
            "deleted": existed,
            "message": "会话已删除" if existed else "会话不存在或已删除"
        }