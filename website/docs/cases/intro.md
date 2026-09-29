# 实战案例

这里的每个案例都来自 `examples/` 目录中**可独立运行的真实 Go 程序**，输出是程序实际运行的结果，不是示意图。

跑起来看看：

```bash
# 案例 1：Prompt Injection 驱动的 SSRF
cd examples/case_ssrf_agent && go run main.go

# 案例 2：HTTP 中间件 + JSON 策略（一行接入）
cd examples/08_http_middleware && go run main.go

# 案例 3：域名模式规则（精确/子域/前缀/后缀/正则）
cd examples/12_domain_pattern_acl && go run main.go
```

| 案例 | 问题 | 涉及的 acl-skills 能力 |
|------|------|------------------------|
| [案例 1：AI Agent 的 SSRF 攻防](case-1-agent-ssrf.md) | Agent 被 Prompt Injection 引导访问云元数据/内网 | `CheckDomain` + `CheckIP` 双维度、IP 预定义集、fail-closed |
| [案例 2：一份策略文件接管整个 Web 服务](case-2-middleware-policy.md) | 已有的 HTTP 服务出站安全完全裸奔 | JSON Policy + HTTP 中间件，一行挂载 |
| [案例 3：用域名模式规则拦截数据外泄](case-3-domain-pattern.md) | 应用出流量无法按域名形态精细化管控 | 域名精确/子域/前缀/后缀/正则匹配、不误伤粒度 |

想直接看原理与 API，可以从 [核心架构](../architecture.md) 或 [API 参考](../api/types.md) 入手。