"""第三层：远端大模型。OpenAI 兼容端点，收到的永远是脱敏后的文本。"""
import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx

from .config import settings


@dataclass
class LlmReply:
    content: str
    model: str
    latency_ms: int
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class RemoteLLM:
    def __init__(self, base_url: str | None = None, api_key: str | None = None, model: str | None = None):
        self.base_url = (base_url or settings.remote_base_url).rstrip("/")
        self.api_key = api_key if api_key is not None else settings.remote_api_key
        self.model = model or settings.remote_model

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def chat(self, messages: list[dict], temperature: float = 0.3) -> LlmReply:
        started = time.perf_counter()
        if not self.configured:
            raise RuntimeError("未配置 REMOTE_API_KEY，无法调用远端大模型")
        resp = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={"model": self.model, "messages": messages, "temperature": temperature},
            timeout=120.0,
        )
        resp.raise_for_status()
        data = resp.json()
        usage = data.get("usage") or {}
        return LlmReply(
            content=data["choices"][0]["message"]["content"],
            model=data.get("model", self.model),
            latency_ms=int((time.perf_counter() - started) * 1000),
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
            total_tokens=usage.get("total_tokens", 0),
        )

    async def stream(self, messages: list[dict], temperature: float = 0.3) -> AsyncIterator[str]:
        if not self.configured:
            raise RuntimeError("未配置 REMOTE_API_KEY，无法调用远端大模型")
        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={"model": self.model, "messages": messages, "temperature": temperature, "stream": True},
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    body = line[5:].strip()
                    if body == "[DONE]":
                        return
                    try:
                        payload = json.loads(body)
                    except json.JSONDecodeError:
                        continue
                    delta = (payload.get("choices") or [{}])[0].get("delta", {}).get("content")
                    if delta:
                        yield delta


remote_llm = RemoteLLM()
