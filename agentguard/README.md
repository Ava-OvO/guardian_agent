# AgentGuard 模块说明

这套目录对应 Blue Agent、Red Agent、Guardian、模拟工具、评估和 Dashboard。仓库根目录的 `README.md` 还有完整启动及 API 文档。

## 启动

从仓库根目录运行：

```bash
python3 -m agentguard.main dashboard --port 8000
python3 -m agentguard.main replay --case S2
python3 -m agentguard.main evaluate
```

浏览器打开 `http://127.0.0.1:8000`。内置 Dashboard 无需安装依赖。也可安装可选的 Streamlit：

```bash
python3 -m pip install -r agentguard/requirements.txt
python3 -m streamlit run agentguard/dashboard.py
```

## LLM Guardian

`guardian.py` 默认以 policy 为硬边界。已被 policy 拒绝的操作不再送模型；来自外部资料、但 policy 原本可能放行或送审批的操作，才交给 LLM 判断是否存在诱导指令。模型可以**增加拦截**，不能解除 policy 的拒绝或跳过审批。模型不可用时回退到 policy，并在响应中标记 `llm_status=fallback_policy`。

`data/policies.json` 配置 agent 能力、资源标签、允许的只读操作和规则版本；匹配顺序与安全约束由 `core.py` 实现，模型不能修改。

模型接口采用 OpenAI-compatible `chat/completions` JSON 格式。通过环境变量设置 `AGENTGUARD_LLM_URL`、`AGENTGUARD_LLM_MODEL`、`AGENTGUARD_LLM_API_KEY`；URL 必须是 HTTPS。只向模型发送脱敏后的**合成演示数据**。如果 Kiro API 的格式不同，需要根据其接口文档写一个适配器；不要把密钥写进仓库。

配置好后运行 `python3 -m agentguard.main evaluate --llm`。该命令对 8 个相同案例比较纯规则、纯 LLM 和组合方案，并写入 `results/test_results.json`。未配置时只测纯规则，不会生成虚构的模型分数。为了遵守活动期间约 1 次/秒的模型调用建议，评估器在模型调用间暂停。

## 如何读评估结果

- `accuracy`：最终决定与案例预期完全一致的比例。
- `unsafe_allow_count`：恶意案例被直接放行的次数；越低越好。
- `benign_false_block_count`：正常案例被直接拒绝的次数；越低越好。
- `mean_latency_ms`：平均判断耗时。纯规则通常快，模型增加延迟和调用成本。

当前 8 个手工案例只能演示架构差异，不能证明生产环境防护率。尤其是模型评估需要真实配置并实测，测试替身只验证集成逻辑。无论 LLM 分数如何，身份、能力范围、敏感数据外发和审批都应留在确定性 policy 中。
