"""本地模型选型对比：同一批样本跑过 0.5b / 1.5b / 3b，看判定是否站得住。

用法：.venv/bin/python tools/model_bench.py [qwen2.5:0.5b qwen2.5:1.5b llama3.2:3b]
"""
import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from gateway.auditor import LocalAuditor  # noqa: E402
from gateway.dlp import dlp  # noqa: E402

EXPECTS = {"block_regex": "block", "block_local_model": "block", "mask_allow": "allow", "allow": "allow"}
# 正则层已经在模型之前处理掉这些样本，模型只需面对语义层考题
SKIP_MODEL_JUDGMENT = {"apikey", "injection_en", "dsn"}


def main() -> None:
    samples = json.loads((BASE / "web" / "samples.json").read_text(encoding="utf-8"))
    requested = sys.argv[1:] or ["qwen2.5:0.5b", "qwen2.5:1.5b", "llama3.2:3b"]

    models = []
    for name in requested:
        agent = LocalAuditor(model=name)
        ok, detail = agent.available()
        if ok:
            models.append(name)
        else:
            print(f"跳过 {name}：{detail}")
    if not models:
        raise SystemExit("没有可用的本地模型，先执行 ollama pull")

    print(f"{'样本':<16} {'期望':<6}", "".join(f"{m[:14]:<24}" for m in models))
    print("-" * (24 + 24 * len(models)))

    tally = {m: {"correct": 0, "total": 0, "ms": 0, "degraded": 0} for m in models}
    for sample in samples:
        if sample["id"] in SKIP_MODEL_JUDGMENT:
            continue
        masked, _ = dlp.mask(sample["text"])
        expect = EXPECTS[sample["expect"]]
        row = [f"{sample['id']:<16} {expect:<6}"]
        for model in models:
            result = LocalAuditor(model=model).audit(masked, model=model)
            if result.degraded:
                row.append(f"! {result.error[:18] or '降级'}".ljust(24))
                tally[model]["degraded"] += 1
                continue
            mark = "✓" if result.verdict == expect else "✗"
            row.append(f"{mark} {result.verdict}/{result.attack} {result.latency_ms}ms".ljust(24))
            tally[model]["correct"] += result.verdict == expect
            tally[model]["total"] += 1
            tally[model]["ms"] += result.latency_ms
        print(" ".join(row))

    print("\n正确率（不含降级样本）：")
    for model in models:
        t = tally[model]
        if t["total"]:
            extra = f"  降级 {t['degraded']} 例" if t["degraded"] else ""
            print(f"  {model:<16} {t['correct']}/{t['total']}  平均 {t['ms'] // t['total']}ms{extra}")


if __name__ == "__main__":
    main()
