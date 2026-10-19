"""第一层：毫秒级正则 DLP —— 敏感数据识别、脱敏、还原。"""
import re
from dataclasses import dataclass

BLOCK = "block"
MASK = "mask"


@dataclass
class Rule:
    name: str
    category: str
    token: str
    pattern: re.Pattern
    action: str
    keep_tail: int = 4


# action=block 的类别在请求发出前直接 403；action=mask 的类别替换为占位符后放行，响应侧还原。
# 边界一律用显式 ASCII lookaround：中文字符在 re 里算 \w，\b 在「手机号13812345678」这种紧邻处不成立。
RULES: list[Rule] = [
    # ── 1. 凭证密钥 ────────────────────────────────────────────────
    Rule("OpenAI/Anthropic 风格密钥", "credential", "SECRET_KEY",
         re.compile(r"(?<![A-Za-z0-9\-])sk-(?:proj-|ant-|api-)?[A-Za-z0-9\-_]{16,}(?![A-Za-z0-9\-])"), BLOCK),
    Rule("短 sk- Key", "credential", "SECRET_KEY",
         re.compile(r"(?<![A-Za-z0-9\-])sk-[0-9]{12,}(?![0-9])"), BLOCK),
    Rule("AWS Access Key ID", "credential", "AWS_KEY",
         re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"), BLOCK),
    Rule("GitHub Token", "credential", "GH_TOKEN",
         re.compile(r"(?<![A-Za-z0-9])(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,})(?![A-Za-z0-9])"), BLOCK),
    Rule("私钥文件头", "credential", "PRIVATE_KEY",
         re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"), BLOCK),
    Rule("Bearer JWT", "credential", "JWT",
         re.compile(r"(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}(?![A-Za-z0-9_\-])"), BLOCK),
    Rule("键值对形式的密码", "credential", "PASSWORD",
         re.compile(r"(?i)(?<![A-Za-z0-9_])(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*[^\s,;'\"]{6,}"), BLOCK),
    # ── 2. 个人隐私 PII ────────────────────────────────────────────
    Rule("中国大陆身份证号", "pii", "ID_CARD",
         re.compile(r"(?<![0-9A-Za-z])\d{17}[\dXx](?![0-9A-Za-z])"), MASK),
    Rule("中国大陆手机号", "pii", "PHONE",
         re.compile(r"(?<![0-9A-Za-z])1[3-9]\d{9}(?![0-9A-Za-z])"), MASK),
    Rule("银行卡号", "pii", "BANK_CARD",
         re.compile(r"(?<![0-9A-Za-z])(?:62\d{14,17}|4\d{15,18}|5[1-5]\d{14,16})(?![0-9A-Za-z])"), MASK),
    Rule("电子邮箱", "pii", "EMAIL",
         re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?![A-Za-z0-9\-])"), MASK),
    # ── 3. 内网与基础设施 ──────────────────────────────────────────
    Rule("内网 IP", "infra", "INTERNAL_IP",
         re.compile(r"(?<![0-9A-Za-z.])(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){1,3}(?![0-9A-Za-z.])"), MASK),
    Rule("数据库连接串", "infra", "DB_DSN",
         re.compile(r"(?i)\b(?:mysql|postgres(?:ql)?|mongodb|redis)://[^\s'\"]+"), BLOCK),
    Rule("内部域名", "infra", "INTERNAL_HOST",
         re.compile(r"(?<![A-Za-z0-9.\-])[A-Za-z0-9\-]+\.(?:corp|internal|intranet|local)\.[A-Za-z]{2,}(?![A-Za-z0-9\-])"), MASK),
    # ── 4. 财务与商业机密 ──────────────────────────────────────────
    Rule("工资/薪资数额", "business", "SALARY",
         re.compile(r"(?i)(?:薪资|工资|salary|年薪|月薪)\D{0,6}(\d{1,3}(?:,\d{3}){2,}|\d{4,7})\s*(?:元|k|K|万|RMB|USD|\$)?"), MASK),
    Rule("未公开财报金额", "business", "FINANCIAL_FIGURE",
         re.compile(r"(?i)(?:未公开|内部|保密).{0,10}(?:财报|营收|利润率|GMV|ARR)\D{0,6}[\d,.]+\s*(?:万|亿|元|%)?"), MASK),
    # ── 5. 人员身份（Deck 的 [NAME_1] 口径）───────────────────────
    Rule("标签式姓名", "identity", "NAME",
         re.compile(r"(?:姓名|联系人|负责人|客户|员工)\s*[:：]\s*(?:[一-龥]{2,4}|[A-Za-z][a-z]+(?:\s[A-Za-z][a-z]+){0,2})"), MASK),
    Rule("姓氏+称谓", "identity", "NAME",
         re.compile(r"[赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜]"
                    r"[一-龥]{1,2}(?=先生|女士|小姐|同志|经理|总监|老师|工程师|同事|的客户|的手机号|的邮箱|的电话)"), MASK),
    # ── 6. 注入与越狱特征（正则兜底，语义判定交给本地模型层）────────
    Rule("提示注入语句", "attack", "INJECTION",
         re.compile(r"(?i)(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions|rules|prompts)"
                    r"|忽略(?:之前|以上|所有)(?:的)?(?:指令|规则|设定|提示)"
                    r"|(?:system\s*prompt|系统提示词)\s*[:：]?\s*(?:reveal|输出|打印|泄露)"), BLOCK),
    Rule("越狱角色扮演模板", "attack", "JAILBREAK",
         re.compile(r"(?i)(?<![A-Za-z])(?:DAN|developer\s*mode|jailbreak)(?![A-Za-z])|越狱|没有限制的\s*(?:AI|人工智能)"), BLOCK),
]

PLACEHOLDER = re.compile(r"\[([A-Z][A-Z0-9_]*?)(_\d+)?\]")


@dataclass
class Finding:
    rule: str
    category: str
    action: str
    sample: str


class DlpScanner:
    def __init__(self, rules: list[Rule] = RULES):
        self.rules = rules

    def scan(self, text: str) -> tuple[list[Finding], list[Rule]]:
        findings, hits = [], []
        for rule in self.rules:
            for m in rule.pattern.finditer(text):
                sample = m.group(0)
                shown = sample[:8] + "…" if len(sample) > 8 + rule.keep_tail else sample
                findings.append(Finding(rule.name, rule.category, rule.action, shown))
                hits.append(rule)
                break
        return findings, hits

    def mask(self, text: str) -> tuple[str, dict[str, str]]:
        """返回脱敏文本与占位符→原值映射（映射只在网关内存活，绝不出网）。"""
        mapping: dict[str, str] = {}
        counters: dict[str, int] = {}
        out = text

        def make_sub(rule: Rule):
            def sub(m: re.Match) -> str:
                original = m.group(0)
                for existing, token in mapping.items():
                    if token == original:
                        return existing
                counters[rule.token] = counters.get(rule.token, 0) + 1
                placeholder = f"[{rule.token}_{counters[rule.token]}]"
                mapping[placeholder] = original
                return placeholder

            return sub

        for rule in self.rules:
            if rule.action != MASK:
                continue
            out = rule.pattern.sub(make_sub(rule), out)
        return out, mapping

    def restore(self, text: str, mapping: dict[str, str]) -> str:
        for placeholder, original in mapping.items():
            text = text.replace(placeholder, original)
        return text


class StreamRestorer:
    """流式还原：占位符可能跨 chunk 断开，尾部疑似半截占位符要先扣住。"""

    def __init__(self, mapping: dict[str, str]):
        self.mapping = mapping
        self.pending = ""

    def _safe_len(self) -> int:
        if "[" not in self.pending:
            return len(self.pending)
        idx = self.pending.rindex("[")
        return idx if re.match(r"^\[[A-Z0-9_]*\]?$", self.pending[idx:]) else len(self.pending)

    def feed(self, chunk: str) -> str:
        self.pending += chunk
        cut = self._safe_len()
        emit, self.pending = self.pending[:cut], self.pending[cut:]
        return self._sub(emit)

    def flush(self) -> str:
        emit, self.pending = self.pending, ""
        return self._sub(emit)

    def _sub(self, text: str) -> str:
        for placeholder, original in self.mapping.items():
            text = text.replace(placeholder, original)
        return text


dlp = DlpScanner()
