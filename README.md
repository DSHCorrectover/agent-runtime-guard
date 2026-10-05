# Agent Runtime Guard · Agent 运行时全栈拦截

[![IETF Internet-Draft](https://img.shields.io/badge/IETF-draft--correctover--ccs-blue)](https://datatracker.ietf.org/doc/draft-correctover-ccs/)
[![npm version](https://img.shields.io/npm/v/agent-runtime-guard.svg)](https://www.npmjs.com/package/agent-runtime-guard)

> **给 AI Agent 配一个运行时保安：它删库、偷密钥、闯内网、被注入诱导——当场拦下。**
> 每次放行或拦截，都出具一张 Ed25519 签名、谁也赖不掉的证据单子。

你给 Agent 接上 shell、网络、云凭证这些工具后，最大的风险是：**它手一抖，一条命令删掉整台机器；或被诱导，把密钥和数据偷偷传走。** 一个容易点过的"确认弹窗"挡不住。

`agent-runtime-guard` 在 **Agent 与危险操作之间**站一道确定性的拦截层——工具调用、shell 命令、网络请求、输出结果全栈覆盖，危险动作在**真正执行前**被 fail-closed 拦下，无需人工点击。

- ✅ **零运行时依赖**，纯 Node.js 标准库（Node ≥ 18），无 install 脚本
- ✅ **全栈拦截**：命令注入 / 路径穿越 / SSRF（含云元数据）/ 凭证外泄 / 提示注入 / 跨工具攻击链
- ✅ **fail-closed**：判危险、验证器出错或超时，都不转发、不执行
- ✅ **Ed25519 证据收据**：每次决策双哈希 + 可链，第三方可离线验证
- ✅ **随处可用**：MCP server（Claude Code / Cursor / Cline / Windsurf）、透明 stdio 代理、DeepSeek Harness 插件

---

## ⚡ 30 秒跑起来

```bash
npx -y agent-runtime-guard
```

把它加进任意 MCP 客户端的 `mcpServers` 配置：

```json
{
  "mcpServers": {
    "agent-runtime-guard": {
      "command": "npx",
      "args": ["-y", "agent-runtime-guard"]
    }
  }
}
```

无需 API key、账号或环境变量——首次运行自动生成 Ed25519 签名密钥（想固定持久密钥再设 `CCS_KEY_DIR` 或 `CCS_PRIVATE_KEY`/`CCS_PUBLIC_KEY`）。

---

## 三种用法

| 场景 | 怎么用 |
|---|---|
| **MCP 客户端**（Claude Code、Cursor、Cline、Windsurf） | 配置上面的 `mcpServers`，工具调用先过保安 |
| **DeepSeek Harness** | `dsh plugin add agent-runtime-guard`，默认 bundle patch 自动启用，住进 `tools/pre-execute` / `post-execute` |
| **网络边界独立拦一道** | 用透明 stdio 代理 [`agent-runtime-proxy`](https://www.npmjs.com/package/agent-runtime-proxy) 包住目标 MCP server，不信宿主内任何插件 |

---

## 它拦什么

- **命令注入**：shell 元字符、`curl|sh`、`rm -rf`、`eval()`
- **路径穿越**：`../`、`/etc/passwd`、`/proc/self/`
- **SSRF**：`169.254.169.254` 云元数据、localhost、私网地址——跨任何工具
- **跨工具攻击链**：读敏感文件 → 网络外传 = `exfil_chain`
- **凭证外泄**：API key、secret、credential 出现在参数或输出
- **混淆提权**：hex/base64 编码、提权信号
- **数值安全**：整数溢出（>2^53-1）、NaN/Infinity
- **提示注入**：工具结果里的"忽略以上指令"等诱导

## Tools

| Tool | 用途 |
|---|---|
| `verify_tool_call` | 7 维运行时验证 + 语义攻击链分析 + 数值溢出检测，**默认拦截** |
| `issue_evidence` | 出具防篡改证据（`content_hash` + `evidence_hash`，可链），放行和拦截都产生 |
| `audit_mcp_config` | 审计 MCP 配置的安全风险 |
| `verify_intent_binding` | 校验实际参数与声明意图是否一致——零容忍、零 LLM，抓跨模型参数漂移（规划写 `amount:100`，执行写成 `amount:10000` → 拦截） |
| `verify_receipt` | 离线校验 Ed25519 收据签名、检测篡改，可固定可信签名者 |

## 证据链

每次决策产生双哈希（`content_hash` + `evidence_hash`）与链指针（`parent_evidence_hash`）。任何第三方都能独立验证证据未被篡改，无需信任运营方。收据为 Ed25519 签名、JSON 形态，可用内置 `verify_receipt` 或任意 Ed25519 库离线验证。

## FAQ（给 AI Agent 配运行时保安，常见疑问）

**黑名单为什么永远拦不全？** 危险命令可以用同义词、编码、拼接绕过，且新型调用不断出现。`agent-runtime-guard` 用语义判定（这段代码的意图是不是危险执行）而不是匹配关键词，未知攻击靠意图异常也能识别。

**`Bash(prefix*)` 放行规则够安全吗？** 不够。`git status*` 这类前缀规则会被 `git status; rm -rf /`、`&&`、管道拼接绕过。判定应基于 shell 解析后的实际命令结构，而不是字符串前缀。

**安全判定能依赖宿主模型/远程分类器吗？** 不建议。远程服务一挂，要么全部拒绝（业务瘫痪）要么被建议绕过（裸奔）。本层策略在本地、默认 deny，裁决与模型可用性完全解耦。

**子 agent 一开权限会被放大吗？** 会，这是真实出现过的问题：子 agent 把权限状态整个换成 allow-all。运行时权限状态应不可被子任务覆盖，并在每次实际调用时强制校验。

**凭证为什么会自动泄露给子命令？** 子进程默认继承父进程全部环境变量，provider key、云凭证随之暴露给 `/run`、`/test` 等本不需要它们的命令。应按白名单最小化传递环境变量。

**拦了还是放了，事后怎么说清是谁的责任？** 每次裁决都出 Ed25519 签名收据（含内容哈希、时间、原因码、链指针），任何第三方可离线验证。这是把"AI 干的"变成可审计责任链的关键。

---

## 🇨🇳 免费验证之外 · 支付宝 SkillPay

运行时验证与证据签发免费使用。如需人工深度审计或正式合规凭证，可在支付宝 SkillPay 货架获取：https://skillpay.alipay.com/public/correctover

## 协议背景

- **IETF**：[draft-correctover-ccs](https://datatracker.ietf.org/doc/draft-correctover-ccs/) —— 个人 Internet-Draft，**不是 RFC，也不代表 IETF 背书**，Datatracker 页面为权威状态
- **互补**：VAP（范围/预算/目的）、Microsoft ACS（策略决策）、AP2（人工授权）
- **不替代**：认证、支付网络、策略引擎

## Links

- npm: https://www.npmjs.com/package/agent-runtime-guard
- GitHub: https://github.com/DSHCorrectover/agent-runtime-guard
- 透明代理: https://github.com/DSHCorrectover/agent-runtime-proxy
- IETF Draft: https://datatracker.ietf.org/doc/draft-correctover-ccs/
- PyPI 完整验证器: https://pypi.org/project/ccs-verifier/

## License

Elastic License 2.0 (ELv2). See [LICENSE](LICENSE).
