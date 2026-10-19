"""FastAPI 网关：OpenAI 兼容入口 + 拦截演示台后端。"""
import json
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from gateway.auditor import auditor
from gateway.config import settings
from gateway.dlp import StreamRestorer, dlp
from gateway.llm import RemoteLLM
from gateway.pipeline import run_pipeline
from gateway.store import AuditLog

BASE = Path(__file__).resolve().parent
app = FastAPI(title="企业级本地 AI 安全网关", version="0.1.0")
audit_log = AuditLog(settings.audit_db)


class CheckRequest(BaseModel):
    text: str
    history: list[dict[str, str]] = []
    user: str = "demo-user"
    local_model: str | None = None
    call_remote: bool = True


class ChatRequest(BaseModel):
    model: str = settings.remote_model
    messages: list[dict[str, Any]]
    stream: bool = False
    temperature: float = 0.3


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (BASE / "web" / "index.html").read_text(encoding="utf-8")


@app.get("/api/models")
def local_models() -> dict:
    """已拉取的本地模型，供演示台现场对比判定差异。"""
    try:
        resp = httpx.get(f"{settings.ollama_host}/api/tags", timeout=3.0)
        resp.raise_for_status()
        names = [m["name"] for m in resp.json().get("models", [])]
        return {"models": names, "default": settings.local_model, "error": None}
    except (httpx.HTTPError, ValueError) as exc:
        return {"models": [], "default": settings.local_model, "error": str(exc)}


@app.get("/api/status")
def status() -> dict:
    ok, detail = auditor.available()
    return {
        "local_model": {"model": settings.local_model, "online": ok, "detail": detail, "host": settings.ollama_host},
        "remote": {
            "configured": settings.remote_configured,
            "base_url": settings.remote_base_url,
            "model": settings.remote_model,
            "key_source": "REMOTE_API_KEY 环境变量" if settings.remote_configured else "未设置",
        },
        "audit": audit_log.stats(),
    }


@app.post("/api/demo/check")
def demo_check(req: CheckRequest) -> dict:
    """跑完整级联；call_remote=false 时只做安检并返回「本该发给云端的内容」。"""
    if not req.text.strip():
        raise HTTPException(400, "text 不能为空")
    llm = RemoteLLM()
    send_remote = req.call_remote and llm.configured
    outcome = run_pipeline(req.text, history=req.history, user=req.user, audit=audit_log,
                           local_model=req.local_model, send_remote=send_remote)
    note = None
    if req.call_remote and not llm.configured and outcome.allowed:
        note = "远端未配置 REMOTE_API_KEY，已自动转为演练模式：只跑本地安检，不调用云端。"
    return {
        "allowed": outcome.allowed,
        "dry_run": outcome.dry_run,
        "answer": outcome.answer,
        "error": outcome.error,
        "note": note,
        "trace": outcome.trace.to_dict(),
    }


@app.get("/api/audit")
def audit_recent(limit: int = 20) -> dict:
    return {"stats": audit_log.stats(), "logs": audit_log.recent(limit)}


@app.post("/v1/chat/completions")
async def openai_chat(req: ChatRequest, authorization: str = Header(default="")):
    """OpenAI 兼容入口：现有工具只改 base_url 即可接入。"""
    token = authorization.removeprefix("Bearer ").strip()
    if token != settings.gateway_key:
        raise HTTPException(401, {"error": {"message": "无效的网关 Key"}})

    last_user = next((m["content"] for m in reversed(req.messages) if m.get("role") == "user"), "")
    history = [m for m in req.messages[:-1] if m.get("role") in ("user", "assistant")]

    findings, _ = dlp.scan(last_user)
    masked_text, mapping = dlp.mask(last_user)
    blocked = [f for f in findings if f.action == "block"]
    if blocked:
        _log_block(masked_text, blocked[0], user=req.model)
        raise HTTPException(403, {"error": {"message": f"敏感数据拦截：{blocked[0].rule}，请求未离开企业网络"}})

    result = auditor.audit(masked_text)
    if result.verdict == "block":
        _log_block(masked_text, None, user=req.model, local=result.to_dict())
        raise HTTPException(403, {"error": {"message": f"本地审计拦截：{result.reason}"}})

    llm = RemoteLLM(model=req.model)
    if not llm.configured:
        raise HTTPException(503, {"error": {"message": "远端大模型未配置 REMOTE_API_KEY"}})

    messages = [{"role": "system", "content": settings.system_prompt}, *history,
                {"role": "user", "content": masked_text}]

    if req.stream:
        return StreamingResponse(_streamed(messages, mapping, req.model), media_type="text/event-stream")

    try:
        reply = llm.chat(messages, temperature=req.temperature)
    except Exception as exc:
        raise HTTPException(502, {"error": {"message": f"远端调用失败：{exc}"}}) from exc
    audit_log.record(user=req.model, action="proxy", verdict="allow", block_reason=None, masked_text=masked_text,
                     dlp_findings=[{"rule": f.rule, "category": f.category} for f in findings],
                     local_audit=result.to_dict(), remote_model=reply.model, latency_ms=reply.latency_ms)
    return {
        "id": "chatcmpl-gw", "object": "chat.completion", "model": reply.model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": dlp.restore(reply.content, mapping)},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": reply.prompt_tokens, "completion_tokens": reply.completion_tokens,
                  "total_tokens": reply.total_tokens},
    }


async def _streamed(messages: list[dict], mapping: dict[str, str], model: str):
    restorer = StreamRestorer(mapping)
    async for delta in RemoteLLM(model=model).stream(messages):
        chunk = restorer.feed(delta)
        if chunk:
            yield f"data: {json.dumps({'choices': [{'delta': {'content': chunk}}]})}\n\n"
    tail = restorer.flush()
    if tail:
        yield f"data: {json.dumps({'choices': [{'delta': {'content': tail}}]})}\n\n"
    yield "data: [DONE]\n\n"


def _log_block(masked_text: str, finding, *, user: str, local: dict | None = None) -> None:
    audit_log.record(
        user=user, action="block", verdict="block",
        block_reason=finding.rule if finding else "local_model",
        masked_text=masked_text,
        dlp_findings=[{"rule": finding.rule, "category": finding.category}] if finding else [],
        local_audit=local or {}, remote_model=None, latency_ms=0,
    )


@app.get("/api/samples")
def samples() -> list[dict]:
    return json.loads((BASE / "web" / "samples.json").read_text(encoding="utf-8"))
