# open-evidence (中文说明)

[![CI](https://github.com/huangbuqubunao-alt/open-evidence/actions/workflows/ci.yml/badge.svg)](https://github.com/huangbuqubunao-alt/open-evidence/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**确定性内容完整性与 AI 审计封签引擎 (RFC 8785 JCS + SHA-256 摘要封签)**

`open-evidence` 致力于解决现代生产级大模型系统中的基础设施挑战：**如何实现大模型输出、执行配置与结构化分析结果的确定性序列化与可验证内容完整性。**

通过将纯标准库实现的 **RFC 8785 JSON 规范化方案 (JCS)** 与 SHA-256 证据封签、多 Provider 抽象契约相结合，`open-evidence` 为 LLM 工程应用建立精确到字节级的审计与防篡改基石。

---

## 安全边界与密码学声明 (必须严格区分)

为保持严密的科学与密码学严谨性，`open-evidence` 明确界定以下属性边界：

| 属性维度 | `open-evidence` 能够保证的 | 本库不直接保证的（需依赖外部基础设施） |
|:---|:---|:---|
| **内容完整性 (Content Integrity)** | **100% 保证**：基于 RFC 8785 JCS 规范字节流与 SHA-256 哈希，任何细微的数据篡改、比特翻转或字段删改，在对照已知封签时均能被 100% 检出。 | 若无带外受信信道，无法阻止攻击者同时替换载荷与未加签封签。 |
| **内容来源真实性 (Origin Authenticity)** | **上下文参数深度绑定**：确定性地将 Prompt 哈希、模型超参数配置、原始响应及元数据封签为统一摘要。 | **不等于自主证明作者身份**：未加签的 SHA-256 仅能证明数据一致性，不能证明“谁生成了该数据”。如需抗抵赖，需配合私钥数字签名（如 Ed25519）或存证于只追加日志中。 |
| **数据实际真实性 (Factual Truth)** | **字节无损保持**：证明数据自封签刻起未被修改。 | **不保证模型事实性**：密码学哈希无法判断大模型本身是否产生了逻辑幻觉或输出事实错误。 |
| **可信时间戳 (Timestamping)** | **系统记录时间**：在封签前置像中记录 ISO-8601 UTC 时间。 | **不等于 TSA 权威认证**：属于应用自声明时间，非 RFC 3161 时间戳权威机构的加密时间凭证。 |

---

## 核心技术特性

- **严格符合 RFC 8785 标准 (JCS)**：
  - 纯 Python 标准库实现，零第三方重量级依赖；
  - 严格符合 ECMA-262 7.1.12.1 规范的浮点数格式化，在浮点精度与指数边界上与 Node.js/V8 引擎完全一致；
  - 严格遵循 I-JSON (RFC 7493) 安全整数范围 `[-(2^53 - 1), 2^53 - 1]`，杜绝跨语言解析截断；
  - 基于 UTF-16 代码单元的键排序，严格杜绝重复键注入风险；
  - 100% 通过官方 RFC 8785 标准参考用例差分验证。
- **内容完整性封签体系 (Content Integrity Sealing)**：
  - 确定性 SHA-256 证据摘要，深度绑定输入负载、模型配置、时间戳与调用方上下文；
  - 下游消费方可零门槛进行自动化防篡改检验。
- **Provider 中立的模型契约**：
  - 统一规范 OpenAI、Anthropic 及本地开源模型的结构化输出模式；
  - 提供具备环路检测与最大重试限制的有向无环图（DAG）降级容灾策略。
- **极致轻量**：
  - 仅引入 `pydantic>=2.0` 保障数据模型类型强约束，JCS 核心库 100% 仅依赖 Python 标准库。

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

### 1. 为 AI 分析结论生成内容完整性封签

```python
from open_evidence import seal_payload, verify_seal

payload = {
    "claim": "本季度运营利润率同比提升 14.2%",
    "source_documents": ["sec_10k_item7.pdf#p42"],
    "confidence_score": 0.96
}

# 生成加密完整性封签
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

# 假设数据流转中置信度字段被篡改
tampered_payload = {
    "claim": "本季度运营利润率同比提升 14.2%",
    "source_documents": ["sec_10k_item7.pdf#p42"],
    "confidence_score": 0.99  # 被恶意篡改
}

result = verify_seal(tampered_payload, seal)
print(f"验证通过: {result.is_valid}")
# 输出: 验证通过: False
# 报错: Payload hash mismatch: computed digest is ..., seal asserts ...
```

---

## 架构说明

详见 [docs/architecture.md](docs/architecture.md)。

## 贡献与安全

- 欢迎提交 PR！请参考 [CONTRIBUTING.md](CONTRIBUTING.md)。
- 发现安全漏洞请查阅 [SECURITY.md](SECURITY.md)。

## 开源协议

本项目采用 [MIT 许可证](LICENSE)。
