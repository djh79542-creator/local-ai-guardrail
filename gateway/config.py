"""集中配置：本地审计模型、远端大模型、拦截策略。"""
import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env(key: str, default: str) -> str:
    return os.getenv(key, default).strip()


def _load_dotenv(path: Path) -> None:
    """不引外部依赖的 .env 加载：真实环境变量优先，.env 只补缺。"""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(BASE_DIR / ".env")


@dataclass
class Settings:
    ollama_host: str = field(default_factory=lambda: _env("OLLAMA_HOST", "http://127.0.0.1:11434"))
    local_model: str = field(default_factory=lambda: _env("LOCAL_AUDIT_MODEL", "qwen2.5:1.5b"))
    local_timeout: float = field(default_factory=lambda: float(_env("LOCAL_AUDIT_TIMEOUT", "20")))

    remote_base_url: str = field(default_factory=lambda: _env("REMOTE_BASE_URL", "https://api.openai.com/v1"))
    remote_api_key: str = field(default_factory=lambda: _env("REMOTE_API_KEY", ""))
    remote_model: str = field(default_factory=lambda: _env("REMOTE_MODEL", "gpt-4o-mini"))
    system_prompt: str = field(
        default_factory=lambda: _env(
            "REMOTE_SYSTEM_PROMPT",
            "你是企业内部的技术助手。用户消息中的 [XXX_1] 形式占位符代表已脱敏的敏感值，回答时保持占位符原样。",
        )
    )

    # 本地模型输出无法解析时的降级策略：allow（依赖上游 DLP）/ block（保守）
    auditor_fail_mode: str = field(default_factory=lambda: _env("AUDITOR_FAIL_MODE", "allow"))
    audit_db: Path = field(default_factory=lambda: Path(_env("AUDIT_DB", str(BASE_DIR / "gateway_audit.db"))))
    gateway_key: str = field(default_factory=lambda: _env("GATEWAY_KEY", "demo-key"))

    @property
    def remote_configured(self) -> bool:
        return bool(self.remote_api_key)


settings = Settings()
