# open-evidence (中文说明)

[![CI](https://github.com/huangbuqubunao-alt/open-evidence/actions/workflows/ci.yml/badge.svg)](https://github.com/huangbuqubunao-alt/open-evidence/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**可追溯的 AI 证据与契约引擎 (RFC 8785 JCS + 加密封签)**

`open-evidence` 致力于解决现代生产级大模型系统中的核心可信挑战：**如何从密码学和规范层面证明，AI 模型的输出是真实、确定、可复核且在流转过程中未被篡改的。**

通过将纯标准库实现的 **RFC 8785 JSON 规范化方案 (JCS)** 与 SHA-256 证据封签、多 Provider 抽象契约相结合，`open-evidence` 为任何基于 LLM 的工程应用建立坚固的不可篡改审计链条。

---

## 核心技术特性

- **严格符合 RFC 8785 标准 (JCS)**：
  - 纯 Python 标准库实现，零第三方重量级依赖；
  - 严格符合 ECMA-262 7.1.12.1 规范的浮点数格式化，避免跨系统跨语言序列化偏差；
  - 基于 UTF-16 代码单元的键排序，严格杜绝重复键注入风险。
- **加密证据封签体系 (Evidence Sealing)**：
  - 确定性 SHA-256 证据摘要，深度绑定输入负载、模型配置、时间戳与调用方上下文；
  - 下游消费方可零门槛进行自动化防篡改检验。
- **Provider 中立的模型契约**：
  - 统一规范 OpenAI、Anthropic 及本地开源模型的结构化输出模式；
  - 提供具备环路检测与最大重试限制的有向无环图（DAG）降级容灾策略。
- **极致轻量**：
  - 仅引入 `pydantic>=2.0` 保障数据类型强约束，JCS 核心库 100% 仅依赖 Python 标准库。

---

## 快速安装

```bash
pip install open-evidence
```

或使用 `uv`：

```bash
uv add open-evidence
```

---

## 核心使用示例

### 1. 为 AI 分析结论生成防伪证据封签

```python
from open_evidence import seal_payload, verify_seal

payload = {
    "claim": "本季度运营利润率同比提升 14.2%",
    "source_documents": ["sec_10k_item7.pdf#p42"],
    "confidence_score": 0.96
}

# 生成加密证据封签
seal = seal_payload(payload, metadata={"auditor": "compliance-bot"})
print(f"数据摘要: {seal.payload_sha256}")
print(f"封签哈希: {seal.seal_sha256}")

# 校验有效性
result = verify_seal(payload, seal, strict=True)
assert result.is_valid is True
```

### 2. 自动化检测数据传输过程中的篡改

```python
from open_evidence import verify_seal

# 假设第三方未经授权篡改了置信度
tampered_payload = {
    "claim": "本季度运营利润率同比提升 14.2%",
    "source_documents": ["sec_10k_item7.pdf#p42"],
    "confidence_score": 0.99  # 被恶意篡改
}

result = verify_seal(tampered_payload, seal)
print(f"验证通过: {result.is_valid}")
# 输出: 验证通过: False
# 报错: Payload hash mismatch: payload hash is ..., seal asserts ...
```

---

## 架构说明

详见 [docs/architecture.md](docs/architecture.md)。

## 贡献与安全

- 欢迎提交 PR！请参考 [CONTRIBUTING.md](CONTRIBUTING.md)。
- 发现安全漏洞请查阅 [SECURITY.md](SECURITY.md)。

## 开源协议

本项目采用 [MIT 许可证](LICENSE)。
