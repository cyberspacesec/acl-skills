# 案例 3：用域名模式规则拦截数据外泄

> 源码：[`examples/12_domain_pattern_acl/main.go`](https://github.com/cyberspacesec/acl-skills/blob/main/examples/12_domain_pattern_acl/main.go)（`cd examples/12_domain_pattern_acl && go run main.go`）

## 问题

出站流量里，攻击者用来外泄数据的域名各有形态：有的用攻击者自有的顶级域（`evil.com`），有的用公司内部服务的前缀（`api.*`），有的伪装成「看起来像内部」的名字（`internal-7.corp`）。黑名单只写死具体域名远远不够，需要**按形态规则**管控。

## 五种匹配方式，一套 API

`DomainACL` 的规则可以混用以下形态：

| 形态 | 配置写法 | 匹配 `api.prod.internal-7.corp` |
|------|----------|------------------------------|
| 精确 | `internal-7.corp` | ✅（完全一致） |
| 子域 | `corp.com` + `includeSubdomains` | ✅（含所有子域） |
| 前缀 | `*.api.example.com` | ✅ |
| 后缀 | `*evil.com` | ❌（这是设计：见下） |
| 正则 | `/internal-\d+\.corp/` | ✅ |

## 规则与真实运行输出

程序配置了三条规则，跑出的结果：

```text
===== 域名模式匹配 ACL 示例 =====

测试结果:
  api.example.com:       拒绝访问 ✗   ← 命中前缀规则 *.api.example.com
  api.sub.example.com:   拒绝访问 ✗   ← 子域也一并命中
  evil.com:              拒绝访问 ✗   ← 命中后缀规则 *evil.com
  sub.evil.com:          拒绝访问 ✗   ← 后缀规则覆盖任意前缀
  notevil.com:           允许访问 ✓   ← 重要：不误伤
  internal-7.corp:       拒绝访问 ✗   ← 命中正则 internal-\d+\.corp
  internal-x.corp:       允许访问 ✓   ← 正则只匹配数字编号
  safe.org:              允许访问 ✓
```

## 三个值得注意的设计点

1. **`*evil.com` 不误伤 `notevil.com`**。后缀规则从「点」边界开始匹配，`*evil.com` 只会命中 `evil.com` 及其子域，不会把 `notevil.com`、`myevilexample.com` 一起拦掉——这正是写黑名单时最怕「一刀切」伤到正常业务的地方。
2. **正则能锁定形态**。`internal-\d+\.corp` 只拦带数字编号的内部主机名，`internal-x.corp` 照常放行，规则粒度精确到一个字符。
3. **前缀规则自动覆盖任意子域**。配了 `*.api.example.com`，`api.sub.example.com` 同样被拦，不用额外再写一条。

## 这套能力怎么用

- **出站数据外泄管控**：把「禁止访问的域名形态」放进黑名单，应用层出站前统一 `CheckDomain`
- **Agent 工具白名单**：用 `Whitelist` + 前缀/子域规则，只允许 Agent 调用你信任的少量 API 域
- **行为审计前置**：规则命中点可以打日志，外泄尝试第一时间可见

所有匹配都发生在域名标准化之后（自动去掉协议、`www.`、端口），规则对 `https://api.example.com/path` 与 `api.example.com` 一视同仁。

- [返回案例索引](intro.md)