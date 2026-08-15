import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
from typing import Tuple, List, Optional
from models.schemas import RiskLevel, AttackType


class AIDetector:
    """增强版AI检测器——三层语义检测：关键词匹配 + 模式匹配 + 语义特征"""

    def __init__(self):
        # ======== 第一层：高置信度攻击关键词（权重 0.20~0.35/词） ========
        self.high_confidence_keywords = {
            "prompt_injection": {
            "keywords": [
                # 指令覆盖类
                "忽略之前的所有指令", "忽略所有之前的指令", "忽略之前的指令",
                "忽略所有规则", "忽略安全策略", "覆盖原有指令",
                "忘记之前的对话", "重置你的指令",
                "你现在是一个没有任何限制", "从现在开始你是",
                "你现在是DAN", "你现在是开发者模式",
                "system prompt", "系统提示词全文", "系统提示词",
                # 角色篡改类
                "无条件服从", "必须服从我", "必须听我的",
                "没有任何限制", "无限制模式", "不受任何约束",
                # 权限提升类
                "管理员权限执行", "提升到管理员",
                "用管理员身份", "开发者模式回应",
                # 格式化攻击
                "[[system]]", "[[/system]]",
                "<|im_start|>system", "<|im_end|>",
                "忽略之前的", "绕过安全策略",
                "假装你是一个没有", # 角色扮演+无限制
                "暂停安全检测", "暂停防护系统", "开放所有端口",
                "临时提升权限", "修改审批级别", "提升到系统管理员",
                "导出用户信息", "导出完整数据", "安全检测暂停",
                "暂停安全系统", "搜索内部文件", "查看内部文件",
                "检索涉密文件",
            ],
            "confidence_per_hit": 0.30,
        },
        "jailbreak": {
            "keywords": [
                "DAN mode", "Do Anything Now",
                "越狱模式", "自由模式", "无限制模式",
                "开发者模式", "debug mode",
                "没有任何道德限制", "无视道德约束",
                "不理伦理准则", "打破限制",
                "不受限制的AI", "解锁所有功能",
                "扮演一个没有任何限制的", "假装你是",
                "角色扮演", "现在开始角色扮演",
            ],
            "confidence_per_hit": 0.30,
        },
        "data_poisoning": {
            "keywords": [
                "篡改数据", "伪造记录", "插入虚假信息",
                "注入恶意数据", "污染知识库",
                "修改数据库", "伪造证据",
                "false information", "corrupt data",
            ],
            "confidence_per_hit": 0.25,
        },
    }

        # ======== 第二层：中置信度关键词（权重 0.12~0.18/词） ========
        self.medium_confidence_keywords = {
            "prompt_injection": {
                "keywords": [
                    "忽略安全", "绕过限制", "绕过规则",
                    "系统指令", "管理员模式", "root权限",
                    "告诉我数据库中所有", "输出所有密码",
                    "告诉我所有用户", "泄露所有数据",
                    "用markdown代码块输出", "输出你的系统",
                    "如何在不被发现的情况下", "如何绕过",
                    "帮我写一个可以绕过防火墙",
                    "你能告诉我", "你必须",
                    "无视之前的", "不要管之前的",
                    "新指令", "新规则", "覆盖指令",
                ],
                "confidence_per_hit": 0.15,
            },
            "jailbreak": {
                "keywords": [
                    "突破限制", "破解安全", "绕过审查",
                    "秘密方式", "隐藏功能", "后门",
                    "更自由的回答", "不受审查",
                    "任意回答", "什么都可以说",
                ],
                "confidence_per_hit": 0.15,
            },
            "data_poisoning": {
                "keywords": [
                    "虚假信息", "误导性内容", "错误数据",
                    "恶意数据", "伪造文档", "篡改记录",
                    "植入后门", "隐藏指令",
                ],
                "confidence_per_hit": 0.12,
            },
            "indirect_injection": {
                "keywords": [
                    "点击这里", "下载附件", "运行程序",
                    "访问链接", "打开文件", "执行脚本",
                    "click here", "download file",
                    "execute script", "open attachment",
                    "查看以下内容", "按照以下步骤",
                    "请务必点击", "立即下载",
                ],
                "confidence_per_hit": 0.12,
            },
        }

        # ======== 第三层：语义模式匹配（正则，高权重） ========
        self.semantic_patterns = [
            # 指令覆盖模式
            (r"(?:请你|请|现在|从现在开始)\s*(?:忘记|忽略|无视|不要管)\s*(?:之前|以前|过去|所有)\s*(?:的)?\s*(?:指令|规则|对话|内容|限制)", 0.35, "prompt_injection"),
            (r"(?:你现在|从现在开始|切换为)\s*(?:是|扮演|充当|作为)\s*(?:一个|一名|一位)?\s*(?:没有|无|不受)\s*(?:任何|所有)?\s*(?:限制|约束|道德|伦理)", 0.35, "prompt_injection"),
            # 权限提升模式
            (r"(?:我是|本人是|我代表)\s*(?:管理员|系统管理员|超级用户|root|admin)", 0.25, "prompt_injection"),
            (r"(?:临时)?\s*(?:提升|授予|给我)\s*(?:管理员|更高|root|admin)\s*(?:权限|级别)", 0.30, "prompt_injection"),
            # 数据窃取模式
            (r"(?:告诉|给|展示|输出|显示)\s*(?:我)?\s*(?:所有|全部|整个)\s*(?:密码|用户|数据|记录|信息|密钥)", 0.35, "prompt_injection"),
            (r"(?:导出|发送|传输|复制)\s*(?:所有|全部)?\s*(?:数据|文件|记录)\s*(?:到|给|至)", 0.30, "data_poisoning"),
            # 越狱模式
            (r"(?:你|AI|模型)\s*(?:现在|已经|可以)\s*(?:自由|不受|无限制|任意)", 0.30, "jailbreak"),
            (r"(?:假设|想象|如果|假如)\s*(?:你|我们|AI)\s*(?:没有|不受|无|跳过)\s*(?:限制|约束|规则|审查)", 0.30, "jailbreak"),
            # 系统提示提取
            (r"(?:输出|显示|print|echo)\s*(?:你的|系统|原始)\s*(?:提示词|prompt|指令|system\s*prompt)", 0.30, "prompt_injection"),
            # 间接注入模式
            (r"(?:以下|如下|下面)\s*(?:是|为)\s*(?:新|更新|最新)\s*(?:指令|规则|要求)", 0.25, "indirect_injection"),
            # 情感操纵+指令
            (r"(?:紧急|危急|生死攸关)\s*(?:需要|必须|立刻|马上)\s*(?:执行|操作|处理|运行)", 0.20, "prompt_injection"),
            # 编码绕过暗示
            (r"(?:用|使用|通过)\s*(?:base64|编码|密文|加密|隐藏)\s*(?:方式|格式|方法)", 0.20, "prompt_injection"),
            # 分段注入探测
            (r"(?:第一步|首先|先).*(?:第二步|然后|接着).*(?:最后|第三步)", 0.15, "prompt_injection"),
            # 工具化攻击请求
            (r"(?:帮我|教我|告诉).*(?:写|制作|开发|构建).*(?:绕过|破解|攻击|入侵|渗透|黑客)", 0.30, "prompt_injection"),
            (r"(?:如何|怎样|怎么)\s*(?:绕过|破解|攻击|入侵|hack)", 0.25, "jailbreak"),
            # 权限提升模式（政企场景特化）
            (r"(?:以|作为|使用|借用)\s*(?:管理员|系统管理员|超级用户|root|admin)\s*(?:身份|权限|账号)", 0.30, "prompt_injection"),
            (r"(?:提升|修改|调整|授予|给我)\s*(?:自己|我|本人|我的)\s*(?:权限|审批|角色|级别)", 0.30, "prompt_injection"),
            (r"(?:审批权限|权限级别)\s*(?:调整为|修改为|提升到|设置为).*(?:最高|管理|admin)", 0.30, "prompt_injection"),
            # 数据窃取/导出模式
            (r"(?:导出|下载|获取|查看|访问)\s*(?:全部|所有|完整|整个)\s*(?:数据|文件|记录|信息|用户|密码|涉密)", 0.30, "data_leakage"),
            (r"(?:导出|备份|迁移|发送)\s*(?:数据库|用户表|密码|敏感)", 0.30, "data_leakage"),
            # 审计日志破坏
            (r"(?:删除|清除|清空|篡改)\s*(?:审计|日志|操作记录|访问记录)", 0.30, "prompt_injection"),
            # 上级/权威冒充
            (r"(?:上级|领导|局里|部里)\s*(?:要求|指示|命令|安排)\s*(?:查看|导出|获取|访问)", 0.25, "data_leakage"),
            # 审批绕过（紧急场景特化，锚点1已覆盖通用审批绕过）
            (r"(?:在紧急情况下|特殊情况下|由于紧急).*(?:可绕过|可跳过|不需要).*(?:审批|流程)", 0.25, "prompt_injection"),
            # 防火墙/安全策略篡改
            (r"(?:修改|关闭|禁用|开放)\s*(?:防火墙|安全策略|安全检测|安全系统)", 0.25, "command_injection"),
            # 资金 + 权限异常
            (r"(?:资金|拨款|转账|支付).*(?:管理员|admin|超级用户|root)", 0.35, "prompt_injection"),
            # 政企场景权限提升（修复BP-004, BP-005漏报）
            (r"(?:由于|因为|因)\s*(?:紧急|特殊|临时)\s*(?:业务|需求|情况).*(?:提升|授予|修改|调整).*(?:权限|级别|角色|审批)", 0.30, "prompt_injection"),
            (r"(?:修改|调整|变更|提高)\s*(?:自己|自身|本人|我|账号)\s*(?:的)?\s*(?:权限|审批|角色|级别)", 0.30, "prompt_injection"),
            # 防火墙/安全策略开放（修复OM-003漏报）
            (r"(?:开放|打开|启用|放行)\s*(?:所有|全部|任意)\s*(?:端口|入站|连接|访问)", 0.30, "command_injection"),
            (r"(?:暂停|停止|关闭|禁用)\s*(?:安全检测|安全系统|防护系统|防火墙)", 0.30, "prompt_injection"),
            # 间接注入 + 数据外泄（修复II-001漏报）
            (r"(?:访问|浏览|查看).*(?:以下|如下|以下).*(?:忽略|绕过|跳过).*(?:规则|指令|限制).*(?:发送|导出|泄露)", 0.35, "prompt_injection"),
            # 权威冒充 + 安全系统操控（修复II-004漏报）
            (r"(?:上级|领导|官方)\s*(?:通知|指令|命令).*(?:暂停|关闭|停止|绕过).*(?:安全监测|安全检测|防护)", 0.35, "prompt_injection"),
            # 数据迁移场景数据泄露（修复GA-005漏报）
            (r"(?:迁移|导出|备份|转出)\s*(?:完整|全部|所有)\s*(?:用户|客户|人员)\s*(?:信息|数据|档案|表)", 0.30, "data_leakage"),
            # 政策伪装 + 数据导出（修复GA-005漏报补充）
            (r"(?:根据|依据|按照)\s*(?:最新|新)?\s*(?:政策|文件|规定|通知).*(?:导出|迁移|备份).*(?:用户|数据|信息)", 0.30, "data_leakage"),
            # 安全策略逆向篡改（修复GA-006漏报）
            (r"(?:安全手册|安全策略|安全规则).*(?:更新|修订|修改|调整).*(?:允许|开放|放行|授权).*(?:所有|全部|任意|外部)", 0.35, "data_poisoning"),
            # 内部文件越权访问（修复KR-002漏报）
            (r"(?:内部|涉密|机密|敏感)\s*(?:文件|文档|资料).*(?:查看|访问|获取|搜索|查阅)", 0.25, "data_leakage"),
            # 搜索内部文件（修复KR-002漏报补充——搜索词在前）
            (r"(?:搜索|检索|查阅|查找|总结).*(?:内部|涉密|机密|敏感)\s*(?:文件|文档|资料|信息)", 0.25, "data_leakage"),
            # 审批权限自主修改（补充BP-005）
            (r"(?:审批级别|审批权限)\s*(?:调|设|改|变).*(?:最高|管理|admin|超级)", 0.30, "prompt_injection"),
            # 上级部门通知 + 安全系统操控（修复II-004漏报——更灵活的模式）
            (r"(?:上级|领导|官方)\s*(?:部门|单位|机关)?\s*(?:的)?\s*(?:紧急|重要|加急)?\s*(?:通知|指示|命令|安排).*(?:暂停|停止|关闭|绕过)\s*(?:安全|监测|检测|防护)", 0.35, "prompt_injection"),
            # 安全检测系统暂停（修复II-004漏报补充）
            (r"(?:安全检测|安全监测|安全防护|安全审计)\s*(?:系统|平台|服务)?\s*(?:暂停|停止|关闭|禁用).*(?:运行|执行|操作)", 0.30, "command_injection"),
            # 紧急通知+安全系统操控（修复II-004漏报通用模式）
            (r"(?:紧急|重要|临时|特殊)\s*(?:通知|指令|命令).*(?:暂停|停止|关闭|废除)\s*(?:安全|防护|检测|监测|所有)", 0.35, "prompt_injection"),
            # S-008: 合规伪装禁用安全机制（与LLM启发式同步，LLM不可用时规则层兜底）
            (r"(?:合规|审计|安全要求|上级要求|检查要求|评估要求|审计要求).{0,30}(?:禁用|关闭|停止|暂停|临时|暂时|废除|拆除).{0,20}(?:访问控制|安全策略|防护|检测|防火墙|安全监测|安全审计|权限控制|身份验证)", 0.35, "prompt_injection"),
            # 权威冒充+敏感操作：上级/领导/局/部/省/市/区要求 + 导出/获取/访问/修改/禁用/关闭/删除/清空/下载/传输/备份（与LLM启发式Pattern6同步）
            (r"(?:上级|领导|局里|部里|官方|市里|省里|区里|县政府|镇政府|处里|科室).{0,20}(?:要求|指示|命令|安排|通知|部署|批示|调度).{0,25}(?:导出|获取|访问|查看|修改|禁用|关闭|删除|清空|下载|传输|备份|迁移|同步|上传|提取|泄露|披露)", 0.35, "prompt_injection"),
            # 知识库投毒钓鱼——导出+上传至外部URL（修复KR-003漏报）
            (r"(?:知识库|数据库|系统).*(?:更新|通知|调整).*(?:导出|上传|迁移).*(?:http|https|ftp)://", 0.35, "content_injection"),
            (r"(?:导出|上传|传输|发送).*(?:原有|原始|全部|所有).*(?:数据|信息|文件).*(?:http|https|ftp)://", 0.35, "content_injection"),
            (r"(?:重新采集|重新收集|重新获取).*(?:个人|用户|市民)\s*(?:信息|数据|档案)", 0.25, "data_leakage"),
            # 政企场景间接攻击（修复S-003~S-023系列漏报）
            (r"(?:电子签章|电子印章|数字签名).*(?:插入|附加|伪造|冒用|盗用)", 0.30, "prompt_injection"),
            (r"(?:插入|附加|伪造|冒用|盗用).{0,10}(?:电子签章|电子印章|数字签名)", 0.30, "prompt_injection"),
            (r"(?:调整|修改|变更|篡改).{0,20}(?:社保|公积金|工资|缴纳).{0,10}(?:基数|金额|标准|等级)", 0.30, "data_leakage"),
            (r"(?:跳过|绕过|免去|省略).{0,20}(?:实名认证|人脸识别|身份验证|认证环节)", 0.30, "prompt_injection"),
            (r"(?:批量|一键|全部|批处理).{0,30}(?:审批通过|更新为通过|标记为通过|修改为通过)", 0.35, "prompt_injection"),
            (r"(?:公文|合同|标书|公告).{0,30}(?:修改|变更|篡改|调整).{0,10}(?:金额|条款|内容|编号)", 0.30, "prompt_injection"),
            (r"(?:伪造|编造|虚构|捏造).{0,20}(?:会议|纪要|记录|签名|签章)", 0.30, "prompt_injection"),
            (r"(?:应急|紧急|绿色通道).{0,30}(?:跳过|绕过|省略|免除).{0,10}(?:审批|审核|验证|认证)", 0.30, "prompt_injection"),
            (r"(?:多轮|之前|上次|刚才).{0,20}(?:对话|聊天|讨论).{0,20}(?:提到|说过|设定|激活).{0,10}(?:模式|权限|功能)", 0.30, "prompt_injection"),
            # 生成会议纪要+签名（间接攻击——S-003/S-005）
            (r"(?:生成|起草|编写).{0,30}(?:会议纪要|公文).{0,30}(?:签名|签章|署名)", 0.25, "prompt_injection"),
            # 会议内容中嵌入恶意指令（修复GA-002）
            (r"(?:会议内容|会议讨论|会议决定).{0,30}(?:授予|提升|开放|禁用|删除).*(?:管理员|所有用户|全部权限)", 0.30, "prompt_injection"),
            # 安全合规伪装——禁用安全机制（修复S-008）
            (r"(?:安全合规|安全要求|上级要求|审计要求).{0,30}(?:禁用|关闭|停止|暂停).{0,10}(?:访问控制|安全策略|防护|检测)", 0.30, "prompt_injection"),
            # 金额/数据篡改（修复S-023）
            (r"(?:金额|价格|预算|数额).{0,20}(?:修改|变更|调整|篡改).{0,10}(?:元|万|亿|百)", 0.30, "prompt_injection"),
            # 社保基数调整（修复S-013）
            (r"(?:社保|公积金|养老金).{0,10}(?:基数|缴纳).{0,20}(?:调整|修改|变更|提高|降低)", 0.30, "data_leakage"),
            # 系统配置查询——可能的信息窃取（S-059）
            (r"(?:列出|输出|显示|获取|读取).{0,20}(?:所有|全部|完整).{0,10}(?:配置|密钥|密码|连接字符串|环境变量)", 0.30, "data_leakage"),
            # Unicode绕过检测（修复S-033/S-035/S-043/S-046/S-047漏报）
            (r"(?:\\u[0-9a-fA-F]{4}\\s*){3,}", 0.30, "command_injection"),  # Unicode转义序列
            (r"[A-Za-z]\u200b[A-Za-z]", 0.35, "command_injection"),  # 零宽字符分隔
            (r"[\u0400-\u04FF]{3,}", 0.25, "prompt_injection"),  # 高密度西里尔字母（可能是同形字）
            # ======== 语义锚点检测（动词-名词对，对抗同义替换绕过） ========
            # 攻击者用"绕开/跳过/略过/省去/免除/越过/规避"替换"绕过"，
            # 用"审核/批准/签字/授权/验证/认证/校验/审查"替换"审批"，
            # 锚点检测动作-目标对，不受同义替换影响。
            # 锚点1: 审批/验证绕过（动作+目标）
            (r"(?:绕过|绕开|跳过|略过|免除|省去|越过|规避|逃避|避开|跳脱|规避|省略|免去|跳越).{0,15}(?:审批|审核|批准|签字|授权|验证|认证|确认|校验|审查|复核|把关|许可|同意|备案|登记|审核流程|审批环节)", 0.35, "prompt_injection"),
            # 锚点2: 权限提升/篡改（动作+目标）
            (r"(?:提升|授予|赋予|给予|获取|获得|升级|调整|修改|变更|拔高|抬高|增设|添加|变更).{0,15}(?:权限|角色|级别|等级|身份|admin|root|管理员|超级用户|系统权限|审批权限|操作权限|访问权限)", 0.32, "prompt_injection"),
            # 锚点3: 数据外泄/导出（动作+目标）
            (r"(?:导出|下载|传输|发送|复制|备份|迁移|同步|上传|提取|泄露|披露|外传|输出|打包|压缩).{0,15}(?:数据|信息|文件|记录|用户|密码|密钥|凭证|数据库|档案|名单|台账|清单|台账|报表)", 0.30, "data_leakage"),
            # 锚点4: 安全机制破坏（动作+目标）
            (r"(?:关闭|禁用|停用|暂停|停止|废除|拆除|卸载|解除|关掉|停掉|取消|中止|终止).{0,15}(?:安全|防护|检测|监测|审计|防火墙|访问控制|身份验证|加密|防护墙|安全策略|安全规则|安全检测|安全系统|防护系统|防护机制)", 0.32, "prompt_injection"),
            # 锚点5: 日志/审计破坏（动作+目标）
            (r"(?:删除|清除|清空|篡改|修改|关闭|停用|禁用|擦除|抹掉|销毁|销档|清理|清零).{0,15}(?:日志|审计日志|操作记录|访问记录|日志记录|审计记录|审计轨迹|操作日志|登录日志|系统日志|事件日志)", 0.32, "prompt_injection"),
            # 锚点6: 指令覆盖/角色篡改（动作+目标）
            (r"(?:忽略|无视|忘记|抛弃|废弃|推翻|覆盖|重置|清除|清空|解除|废除).{0,15}(?:之前|原有|原始|上面|上述|前面|此前|上文).{0,10}(?:指令|规则|设定|配置|约束|限制|策略|守则|规范|要求|提示词|prompt)", 0.33, "prompt_injection"),
        ]

        # ======== 安全触发词（降权） ========
        self.safety_triggers = [
            "help", "assist", "explain", "guide", "learn", "understand",
            "请教", "帮助", "解释", "指导", "学习", "了解", "请问",
            "您好", "你好", "谢谢", "感谢", "请问一下",
        ]

        # ======== 代码审查安全上下文（强烈降权） ========
        self.code_review_triggers = [
            "帮我检查", "帮我审查", "帮我审计", "是否有安全",
            "检查这段代码", "审查这段代码", "帮我看看这段",
            "安全评估", "漏洞扫描", "代码审计",
            "review this code", "security review",
            # 编写检测/防护规则类上下文（安全研发场景，非攻击）
            # 短触发词：覆盖"编写检测绕过..."等变体（不要求"规则"紧跟"检测"）
            "编写检测", "编写安全", "编写防护", "编写过滤",
            "生成检测", "生成安全", "生成防护",
            "设计检测", "设计安全", "设计防护",
            "开发检测", "开发安全", "开发防护",
            # 渗透测试/安全研究上下文
            "渗透测试", "红队", "蓝队", "攻防演练",
            "漏洞复现", "安全研究", "威胁建模", "风险评估",
            "模拟攻击", "复现攻击", "测试防护", "验证检测",
        ]

        # ======== 紧急语气加权词 ========
        self.urgency_words = [
            "紧急", "立刻", "马上", "立即", "赶紧", "快速",
            "urgent", "immediately", "now", "quick",
            "生死攸关", "十万火急", "刻不容缓",
        ]

    def analyze_text(self, text: str) -> Tuple[RiskLevel, Optional[AttackType], float, List[str]]:
        evidence = []
        confidence = 0.0
        type_scores = {}  # {attack_type: score}

        text_lower = text.lower()

        # ======== 第一层：高置信度关键词匹配 ========
        for attack_type, config in self.high_confidence_keywords.items():
            hit_count = 0
            for keyword in config["keywords"]:
                if keyword.lower() in text_lower:
                    hit_count += 1
                    evidence.append(f"AI-高置信度 [{attack_type}]: 命中关键词「{keyword}」")
            if hit_count > 0:
                score = hit_count * config["confidence_per_hit"]
                type_scores[attack_type] = type_scores.get(attack_type, 0) + score

        # ======== 第二层：中置信度关键词匹配 ========
        for attack_type, config in self.medium_confidence_keywords.items():
            hit_count = 0
            for keyword in config["keywords"]:
                if keyword.lower() in text_lower:
                    hit_count += 1
                    evidence.append(f"AI-中置信度 [{attack_type}]: 命中关键词「{keyword}」")
            if hit_count > 0:
                score = hit_count * config["confidence_per_hit"]
                type_scores[attack_type] = type_scores.get(attack_type, 0) + score

        # ======== 第三层：语义模式匹配 ========
        for pattern, weight, attack_type in self.semantic_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                type_scores[attack_type] = type_scores.get(attack_type, 0) + weight
                evidence.append(f"AI-语义模式 [{attack_type}]: 匹配「{pattern[:50]}...」")

        # ======== 综合评分 ========
        if not type_scores:
            return RiskLevel.NONE, None, 0.0, []

        # 取最高分的攻击类型
        best_type = max(type_scores, key=type_scores.get)
        confidence = type_scores[best_type]

        # 安全触发词降权
        safety_hit = sum(1 for trigger in self.safety_triggers
                        if trigger.lower() in text_lower)
        if safety_hit > 0:
            confidence = max(0, confidence - safety_hit * 0.03)

        # 代码审查上下文——按比例降权（固定值降权在多模式累加时不足）
        # 例：5条锚点×0.35=1.75，固定-0.50=1.25(cap 1.0)→input_detector再-0.45=0.55→MEDIUM（误报）
        #     比例×0.40=0.70→input_detector再-0.45=0.25→LOW（正确）
        code_review_hit = sum(1 for trigger in self.code_review_triggers
                             if trigger.lower() in text_lower)
        if code_review_hit > 0:
            confidence = confidence * 0.40  # 保留40%，强降权
            # 多类型命中在安全上下文中额外降权（语义模式累加在安全上下文中不可靠）
            if len(type_scores) >= 2:
                confidence = confidence * 0.80  # 再降20%

        # 紧急语气加权
        urgency_hit = sum(1 for word in self.urgency_words
                         if word in text)
        if urgency_hit > 0:
            confidence = min(1.0, confidence + urgency_hit * 0.05)

        # 文本长度敏感（超长输入可能是注入尝试）
        if len(text) > 2000:
            confidence = min(1.0, confidence + 0.08)
        elif len(text) > 500:
            confidence = min(1.0, confidence + 0.03)

        # 多类型命中加成（复合攻击特征）
        if len(type_scores) >= 2:
            confidence = min(1.0, confidence + 0.10)

        # 确定攻击类型
        try:
            detected_type = AttackType(best_type)
        except ValueError:
            detected_type = AttackType.PROMPT_INJECTION

        # 风险等级判定
        if confidence >= 0.90:
            risk_level = RiskLevel.CRITICAL
        elif confidence >= 0.70:
            risk_level = RiskLevel.HIGH
        elif confidence >= 0.45:
            risk_level = RiskLevel.MEDIUM
        elif confidence >= 0.20:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.NONE

        return risk_level, detected_type, min(confidence, 1.0), evidence
