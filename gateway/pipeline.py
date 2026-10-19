"""级联编排：正则 DLP → 本地模型审计 → 远端大模型 → 响应侧还原。"""
import time
from dataclasses import dataclass, field

from .auditor import auditor
from .config import settings
from .dlp import BLOCK, Finding, dlp
from .llm import RemoteLLM
from .store import AuditLog

ALLOW = "allow"
BLOCKED = "block"


@dataclass
class LayerTrace:
    """一次请求在每一层的可观测结果，演示台直接渲染它。"""
    dlp_ms: int = 0
    findings: list[dict] = field(default_factory=list)
    masked_preview: str = ""
    masked_text: str = ""
    masked_count: int = 0
    local: dict = field(default_factory=dict)
    remote: dict = field(default_factory=dict)
    verdict: str = ALLOW
    blocked_by: str | None = None
    total_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "dlp_ms": self.dlp_ms,
            "findings": self.findings,
            "masked_preview": self.masked_preview,
            "masked_text": self.masked_text,
            "masked_count": self.masked_count,
            "local": self.local,
            "remote": self.remote,
            "verdict": self.verdict,
            "blocked_by": self.blocked_by,
            "total_ms": self.total_ms,
        }


@dataclass
class GateOutcome:
    allowed: bool
    answer: str | None = None
    status_code: int = 200
    error: str | None = None
    trace: LayerTrace = field(default_factory=LayerTrace)
    dry_run: bool = False


def _finding_dicts(findings: list[Finding]) -> list[dict]:
    return [{"rule": f.rule, "category": f.category, "action": f.action, "sample": f.sample} for f in findings]


def run_pipeline(user_text: str, *, history: list[dict] | None = None, user: str = "anonymous",
                 scanner=dlp, audit=None, llm: RemoteLLM | None = None, agent=None,
                 local_model: str | None = None, send_remote: bool = True) -> GateOutcome:
    audit = audit or AuditLog(settings.audit_db)
    llm = llm or RemoteLLM()
    agent = agent or auditor
    trace = LayerTrace()
    started = time.perf_counter()

    t0 = time.perf_counter()
    findings, _ = scanner.scan(user_text)
    masked_text, mapping = scanner.mask(user_text)
    trace.dlp_ms = int((time.perf_counter() - t0) * 1000)
    trace.findings = _finding_dicts(findings)
    trace.masked_preview = masked_text[:200]
    trace.masked_text = masked_text
    trace.masked_count = len(mapping)

    hard_block = [f for f in findings if f.action == BLOCK]
    if hard_block:
        return _finish_block(
            trace, audit, user=user, blocked_by="dlp_regex",
            reason=f"命中拦截规则：{hard_block[0].rule}", masked_text=masked_text, started=started,
            error="检测到凭证明文/攻击特征，请求在离开企业网络前已被拦截。",
        )

    result = agent.audit(masked_text, model=local_model)
    trace.local = {**result.to_dict(), "raw": result.raw}
    if result.verdict == BLOCK:
        return _finish_block(
            trace, audit, user=user, blocked_by="local_model",
            reason=result.reason or "本地模型判定为不安全请求", masked_text=masked_text, started=started,
            error="本地审计模型判定该请求存在安全风险，未向云端发送任何内容。",
        )

    if not send_remote:
        trace.verdict = ALLOW
        trace.total_ms = int((time.perf_counter() - started) * 1000)
        audit.record(user=user, action="dry_run", verdict=ALLOW, block_reason=None, masked_text=masked_text,
                     dlp_findings=trace.findings, local_audit=result.to_dict(),
                     remote_model=None, latency_ms=trace.total_ms)
        return GateOutcome(allowed=True, answer=None, trace=trace, dry_run=True)

    if not llm.configured:
        return _finish_block(
            trace, audit, user=user, blocked_by="remote_unconfigured",
            reason="远端大模型未配置", masked_text=masked_text, started=started,
            error="安全检查已通过，但远端大模型未配置（缺少 REMOTE_API_KEY）。",
        )

    messages = [{"role": "system", "content": settings.system_prompt}]
    messages += (history or [])[-6:]
    messages.append({"role": "user", "content": masked_text})

    try:
        reply = llm.chat(messages)
    except Exception as exc:
        return _finish_block(
            trace, audit, user=user, blocked_by="remote_error",
            reason=f"远端调用失败：{type(exc).__name__}", masked_text=masked_text, started=started,
            error=f"安全检查已通过，但远端大模型调用失败：{type(exc).__name__}",
        )

    trace.remote = {
        "model": reply.model, "latency_ms": reply.latency_ms,
        "prompt_tokens": reply.prompt_tokens, "completion_tokens": reply.completion_tokens,
        "total_tokens": reply.total_tokens,
    }
    answer = scanner.restore(reply.content, mapping)
    trace.verdict = ALLOW
    trace.total_ms = int((time.perf_counter() - started) * 1000)
    audit.record(user=user, action="proxy", verdict=ALLOW, block_reason=None, masked_text=masked_text,
                 dlp_findings=trace.findings, local_audit=result.to_dict(),
                 remote_model=reply.model, latency_ms=trace.total_ms)
    return GateOutcome(allowed=True, answer=answer, trace=trace)


def _finish_block(trace, audit, *, user, blocked_by, reason, masked_text, started, error) -> GateOutcome:
    trace.verdict = BLOCKED
    trace.blocked_by = blocked_by
    trace.total_ms = int((time.perf_counter() - started) * 1000)
    audit.record(user=user, action="block", verdict=BLOCKED, block_reason=f"{blocked_by}: {reason}",
                 masked_text=masked_text, dlp_findings=trace.findings,
                 local_audit=trace.local, remote_model=None, latency_ms=trace.total_ms)
    return GateOutcome(allowed=False, status_code=403, error=reason, trace=trace)
