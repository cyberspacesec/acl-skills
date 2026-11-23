# acl-skills

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.18+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="License" />
  <img src="https://img.shields.io/codecov/c/github/cyberspacesec/acl-skills?style=flat-square&logo=codecov&logoColor=white" alt="Coverage" />
  <img src="https://img.shields.io/github/v/release/cyberspacesec/acl-skills?style=flat-square&logo=github&label=release" alt="Release" />
</p>

<p align="center">
  <b>面向 AI Agent 的访问控制库 — 阻断 SSRF，管控出站域名与 IP</b>
</p>

<p align="center">
  <a href="README.md">English</a> | <b>简体中文</b>
</p>

---

AI Agent 在使用工具时会发起 HTTP 请求。一旦缺少护栏，它们就可能被诱导访问内部服务（SSRF）、把数据泄露到非预期的目的地，或者打到云元数据端点。**acl-skills** 提供一套干净的 Go API，在任何出站请求离开 Agent 之前强制实施域名与 IP 的 allow/deny 列表。

```go
// 一次调用即可为你的 Agent 挡住 SSRF 与意外的出站访问
manager.SetIPACLWithDefaults(nil, types.Blacklist, []ip.PredefinedSet{
    ip.PrivateNetworks,   // 10.x, 192.168.x, 172.16.x
    ip.LoopbackNetworks,  // 127.x, ::1
    ip.CloudMetadata,     // 169.254.169.254, fd00:ec2::254
    ip.DockerNetworks,    // 172.17.x
}, false)

if perm, _ := manager.CheckIP(resolvedIP); perm == types.Denied {
    return errors.New("access denied: internal address")
}
```

## 为什么 Agent 需要 ACL

| 风险 | 没有 acl-skills | 有 acl-skills |
|------|-----------------|---------------|
| 用户传入 URL 导致的 SSRF | Agent 会请求内部服务 | 在请求发出前就被阻断 |
| 提示词注入导致数据外泄 | Agent 向攻击者服务器 POST 数据 | 域名黑名单将其拦截 |
| 云凭证窃取 | Agent 打到 `169.254.169.254` | CloudMetadata 预设将其阻断 |
| 未经授权的工具调用 | 对 Agent 调用的对象毫无护栏 | 按种类（kind）的 ACL 并带审计记录 |

## 安装

```bash
go get github.com/cyberspacesec/acl-skills
```

要求 Go 1.18+，零外部依赖。

## 快速开始

### 场景 1 — 保护一个抓取网页的工具

```go
import (
    "github.com/cyberspacesec/acl-skills/pkg/acl"
    "github.com/cyberspacesec/acl-skills/pkg/ip"
    "github.com/cyberspacesec/acl-skills/pkg/types"
)

manager := acl.NewManager()

// 阻断 Agent 永远不该访问的所有地址
manager.SetIPACLWithDefaults(nil, types.Blacklist, []ip.PredefinedSet{
    ip.PrivateNetworks,
    ip.LoopbackNetworks,
    ip.CloudMetadata,
    ip.LinkLocalNetworks,
    ip.DockerNetworks,
}, false)

// 在 Agent 的 HTTP 拨号之前：
func agentDial(network, addr string) (net.Conn, error) {
    host, _, _ := net.SplitHostPort(addr)
    if perm, _ := manager.CheckIP(host); perm == types.Denied {
        return nil, fmt.Errorf("acl: blocked %s", host)
    }
    return net.Dial(network, addr)
}
```

### 场景 2 — 用白名单限定 Agent 可以调用的域名

```go
manager := acl.NewManager()

// 只允许调用自己的 API 与已批准的第三方服务
manager.SetDomainACL([]string{
    "api.openai.com",
    "api.anthropic.com",
    "your-backend.internal",
}, types.Whitelist, true) // true = 同时包含子域名

if perm, _ := manager.CheckDomain(targetHost); perm == types.Denied {
    return fmt.Errorf("acl: domain %s not in allowlist", targetHost)
}
```

### 场景 3 — JSON 策略文件（非常适合作为 Agent 配置）

把你的编排系统可以在启动时注入的规则定义为文件：

```json
{
  "ip": {
    "listType": "blacklist",
    "predefinedSets": ["private_networks", "loopback", "cloud_metadata", "docker_networks"],
    "allowPredefined": false
  },
  "domain": {
    "domains": ["evil-exfil.com", "attacker.io"],
    "listType": "blacklist",
    "includeSubdomains": true,
    "predefinedSets": ["shorteners", "disposable_email"],
    "allowPredefined": false
  }
}
```

```go
pol, _ := config.LoadPolicyFromFile("./agent-policy.json")
manager := acl.NewManager()
manager.ApplyPolicy(pol)
```

### 场景 4 — 面向 Agent 服务的 HTTP 中间件

如果你的 Agent 对外暴露 HTTP 服务或代理，可以把 ACL 作为中间件挂上去：

```go
handler := middleware.New(manager, middleware.Options{
    CheckClientIP: true,  // 阻断来自不良 IP 的入站连接
    CheckHost:     true,  // 阻断指向被封域名的请求
    // TrustProxy 默认 false — 防止 X-Forwarded-For 伪造
})(mux)
http.ListenAndServe(":8080", handler)
```

任何被拒绝的请求都会返回 403。`TrustProxy` 默认为 `false`，用于防止通过请求头伪造绕过。

## 核心 API

```go
manager := acl.NewManager()

// 域名 ACL
manager.SetDomainACL(domains []string, list types.ListType, includeSubdomains bool)
manager.SetDomainACLWithDefaults(domains, list, includeSubdomains, predefined, allowPredefined)
manager.AddDomain(domains ...string)
manager.RemoveDomain(domains ...string)
perm, err := manager.CheckDomain(domain string)

// IP ACL
manager.SetIPACL(ranges []string, list types.ListType)
manager.SetIPACLWithDefaults(ranges, list, predefined, allowPredefined)
manager.AddIP(ips ...string)
manager.RemoveIP(ips ...string)
perm, err  := manager.CheckIP(ip string)
cidr, err  := manager.LookupIP(ip string)   // 最长前缀反向查找

// 统一策略
manager.ApplyPolicy(pol *config.Policy)

// 自定义 ACL 种类（可扩展到 token、用户 ID、API key 等）
manager.RegisterACL("api-key", myKeyACL)
perm, err := manager.CheckKind("api-key", value)
```

## 预定义 IP 集合

| 常量 | 覆盖范围 | Agent 使用场景 |
|------|----------|----------------|
| `ip.PrivateNetworks` | RFC 1918（10.x, 172.16.x, 192.168.x） | 阻断内网 SSRF |
| `ip.LoopbackNetworks` | 127.x, ::1 | 阻断本地回环访问 |
| `ip.CloudMetadata` | 169.254.169.254, fd00:ec2::254 | 保护云凭证 |
| `ip.LinkLocalNetworks` | 169.254.x, fe80::/10 | 阻断链路本地地址 |
| `ip.DockerNetworks` | 172.17.x | 阻断容器网络 |
| `ip.PublicDNS` | 8.8.8.8, 1.1.1.1, … | DNS 服务器白名单 |

## 预定义域名集合

| 常量 | 覆盖范围 | Agent 使用场景 |
|------|----------|----------------|
| `domain.Shorteners` | bit.ly, tinyurl, … | 阻断隐藏的跳转目标 |
| `domain.DisposableEmail` | mailinator, guerrilla, … | 阻断一次性邮箱 |
| `domain.PublicFileSharing` | pastebin, mega, … | 阻断数据外泄通道 |
| `domain.CodeHosting` | github, gitlab, … | 管控源码访问 |
| `domain.SocialMedia` | twitter, reddit, … | 企业策略执行 |
| `domain.TorExitNodes` | Tor 相关域名 | 阻断匿名流量 |
| `domain.TrustedCDN` | cloudflare, fastly, … | CDN 白名单 |
| `domain.AllMaliciousDomains` | 所有高风险集合的合并 | 最大化封锁 |

## 域名模式匹配

除精确匹配外，域名 ACL 还支持通配符与正则：

```go
manager.SetDomainACL([]string{
    "*.evil.com",          // 仅子域名（evil.com 本身可以通过）
    "*evil.com",           // evil.com 及其所有子域名
    "api.*",               // 任意以 api. 开头的域名
    `/^internal-\d+\.corp$/`, // RE2 正则（无回溯，天然抗 ReDoS）
}, types.Blacklist, false)
```

## IP 范围支持

```go
// CIDR
manager.SetIPACL([]string{"10.0.0.0/8", "2001:db8::/32"}, types.Blacklist)

// 闭区间 — 自动合并为最小 CIDR 集合
manager.SetIPACL([]string{"192.168.1.10-192.168.1.20"}, types.Blacklist)
```

## 可扩展性

为任意字符串型资源（API key、用户 ID、OAuth scope）注册自定义 ACL 种类：

```go
// MutableACL 接口：Check / GetListType / Add / Remove / GetRules
manager.RegisterACL("oauth-scope", myScopeACL)
perm, _ := manager.CheckKind("oauth-scope", "write:data")
manager.AddRule("oauth-scope", "read:public")
```

内置的 `KindDomain` / `KindIP` 已预先注册；所有旧的 `SetDomainACL` / `CheckIP` 调用保持兼容。

## 性能

使用 `go test -bench=. -benchmem ./...` 基准测试：

| 操作 | 规模 | 延迟 | 内存分配 |
|------|------|------|----------|
| `IPACL.Check` | 10 000 条规则 | ~75 ns/op | 0 |
| `IPACL.Check`（并发） | 10 000 条规则 | ~45 ns/op | 0 |
| `DomainACL.Check`（精确匹配） | 10 000 条规则 | ~70 ns/op | 0 |
| `Manager.CheckIP` | 10 000 条规则 | ~80 ns/op | 0 |

IP 匹配使用按位前缀树（IPv4 为 O(32)，IPv6 为 O(128)）——无论规则数量多少，查找时间恒定。检查路径零内存分配。

## 示例

| 示例 | 说明 |
|------|------|
| [01_domain_acl](examples/01_domain_acl/) | 基础域名白名单/黑名单 |
| [02_ip_acl](examples/02_ip_acl/) | 基于 CIDR 的 IP 黑名单 |
| [04_predefined_sets](examples/04_predefined_sets/) | 使用预定义集合进行 SSRF 防护 |
| [05_acl_manager](examples/05_acl_manager/) | 域名 + IP 规则组合使用 |
| [06_complete_example](examples/06_complete_example/) | 完整的 Web 应用防护 |
| [07_custom_acl](examples/07_custom_acl/) | 自定义 ACL 种类注册 |
| [08_http_middleware](examples/08_http_middleware/) | JSON 策略 + 中间件 |
| [09_domain_predefined_sets](examples/09_domain_predefined_sets/) | 域名预定义集合 |
| [10_subdomain_acl](examples/10_subdomain_acl/) | 子域名通配符模式 |
| [11_ipv6_subnet_acl](examples/11_ipv6_subnet_acl/) | IPv6 子网 + 反向查找 |
| [12_domain_pattern_acl](examples/12_domain_pattern_acl/) | 前缀 / 后缀 / 正则模式 |
| [13_ip_range_acl](examples/13_ip_range_acl/) | IP 区间范围 |

## API 稳定性

从 `v1.0.0` 起，以下内容保证在次版本内保持稳定：

- `types`：`ACL`、`ListTypeACL`、`MutableACL`、`ListType`、`Permission`
- `domain.DomainACL`、`ip.IPACL`：`Check` / `Add` / `Remove` / `GetRules` / `GetListType`
- `acl.Manager`：所有 `Set*` / `Check*` / `Add*` / `Remove*` / `Get*` / `LookupIP` 方法
- `config.Policy` 结构体及其 JSON 字段名
- `middleware.New` 与 `Options` 字段

实验性 API（可能在次版本中变化）：`Manager.RegisterACL` / `UnregisterACL`、`SetDomainACLStrict`。

## 贡献

欢迎提交 Issue 与 PR，详见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

MIT — 详见 [LICENSE](LICENSE)。
