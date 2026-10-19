# 企业级本地 AI 安全网关 · Demo

工程师把带密钥的代码粘给 ChatGPT 之前，先被本机的一道门拦下。**本地模型负责识别与拦截，远端大模型只负责生成**——云端全程只看到 `[PHONE_1]`、`[NAME_1]` 这类代号。

## 三层级联

```
用户请求
  │
  ├─ 第 1 层  正则 DLP（本机，<5ms，20 条规则 / 6 大类别 = 10 拦截 + 10 脱敏）
  │     凭证·内网·攻击特征 → 就地 403，一个字节都不出网
  │     PII·姓名·薪酬     → 替换为占位符，映射表只活在网关内存里
  │
  ├─ 第 2 层  本地小模型「AI 审计员」（Ollama，断网，只看脱敏后文本）
  │     输出 JSON Schema 约束的 verdict / attack / risk / reason
  │     判 block → 403，不调用云端
  │
  ├─ 第 3 层  远端大模型（OpenAI 兼容）
  │     收到的永远是脱敏文本
  │
  └─ 响应侧  占位符在网关内还原 → 用户无感知
        审计日志只落脱敏后请求的 SHA256 指纹，不留原文
```

### 为什么不能只靠"统一提示词"

| | 提示词方案 | 本方案 |
| --- | --- | --- |
| 隐私 | 明文已到达云端，泄露在请求那一刻就发生了 | 敏感值出局域网前已被替换 |
| 越狱 | 系统提示词与用户输入对模型只是两段文本，容易被覆盖 | 本地模型只做是/否判定；即使被绕过，它也拿不到云端控制权，更绕不过后端 `if` |
| 成本 | 违规请求照样全额发云端、按 token 计费 | 拦截发生在计费调用之前 |

## 快速开始

```bash
brew install ollama && brew services start ollama
ollama pull qwen2.5:1.5b
python3.11 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env      # 填 REMOTE_API_KEY
.venv/bin/python -m uvicorn server:app --port 8000
```

打开 http://127.0.0.1:8000 —— 8 个预置场景，点一下就能看到请求死在哪一层。
没填 Key 也能演示：缺 `REMOTE_API_KEY` 时自动转为**演练模式**，只跑本地安检并展示"云端本该收到的文本"，不产生任何 API 费用。

## 实测：本地模型选型不是玄学

`tools/model_bench.py` 用同一批语义样本跑过三个模型（正则层已在更早阶段处理掉的样本不计入）：

| 模型 | 判定正确率 | 平均延迟 | 问题 |
| --- | --- | --- | --- |
| qwen2.5:0.5b | 4/5 | 749ms | 漏判"换皮数据外传"；自由生成时把 `"none\|jailbreak\|..."` 枚举字面量照抄进结果 |
| **qwen2.5:1.5b** | **5/5** | **710ms** | 默认选择：准确率与速度同时最优 |
| llama3.2:3b | 5/5 | 4419ms | 精度与 1.5b 持平，冷启动单次 19s |

两个必须知道的坑（都已修，有回归测试）：
- **JSON Schema 约束解码**：`format=SCHEMA` 才能保证枚举合法，靠 prompt 要求小模型输出 JSON 不可靠。
- **`\b` 在中文里不成立**：中文字符算 `\w`，`手机号13812345678` 用 `\b` 会**整段漏检**。现在数字与标识符规则统一改用显式 ASCII 前后限。

## 接入方式：现有工具只改一个地址

```bash
curl http://127.0.0.1:8000/v1/chat/completions \
  -H "Authorization: Bearer demo-key" -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"我的密钥是 sk-proj-AbCdEf1234567890XYZabcdefg，帮我调用"}]}'
# → HTTP 403 敏感数据拦截：OpenAI/Anthropic 风格密钥，请求未离开企业网络
```

流式（`"stream":true`）同样可用，占位符跨 chunk 断开时由 `StreamRestorer` 扣住半个 token 再还原。

## 已知边界

- 本地审计层失效时（服务挂了 / 输出不可解析）走 `AUDITOR_FAIL_MODE`；默认 `allow` 依赖正则兜底，**生产建议设成 `block`**，演示台在该层会亮黄色警示条。
- 正则规则非穷尽，姓名脱敏基于"标签+称谓"启发式，会漏也会误伤；语义层是唯一能识别"每个词都合法、合起来是外传意图"的一环。
- 本 demo 只做单表审计（`audit_logs`），未实现 Deck 里的多租户 Key、策略引擎与多模型故障转移。

```bash
.venv/bin/python -m pytest -q      # 21 cases
.venv/bin/python tools/model_bench.py
```
