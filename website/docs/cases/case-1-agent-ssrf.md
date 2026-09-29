# 案例 1：AI Agent 的 SSRF 攻防

> 源码：[`examples/case_ssrf_agent/main.go`](https://github.com/cyberspacesec/acl-skills/blob/main/examples/case_ssrf_agent/main.go)（`cd examples/case_ssrf_agent && go run main.go`）

## 问题

AI Agent 拿到工具调用能力后，攻击者的一条 Prompt Injection 消息就能让它去访问**本不该访问的地址**：

- `http://169.254.169.254/latest/meta-data/...` — 云服务商元数据端点，能拿到临时云凭证
- `http://10.0.0.5/internal/api-tokens` — 内网未授权接口
- `http://api.legit-cdn.com/status` — 域名看似可信，但 DNS 二次解析指向 `10.0.0.9`（DNS rebinding）

如果没有访问控制，Agent 会真的建立连接，把凭证和内部数据带回来。

## 无防护时（攻击得逞）

真实程序输出——三个目标**全部放行**：

```text
【阶段 1】Agent 未接入任何 ACL
  执行结果：
    [放行] http://169.254.169.254/latest/meta-data/iam/security-credentials/ → 连接建立，请求发出（攻击得逞）
    [放行] http://10.0.0.5/internal/api-tokens → 连接建立，请求发出（攻击得逞）
    [放行] http://api.legit-cdn.com/status → 连接建立，请求发出（攻击得逞）

  >> 云凭证被窃取、内网接口被访问。这正是真实 SSRF 漏洞的成因。
```

## 接入 acl-skills 后（全部拦截）

同样的请求，程序里只多了几行配置：

```go
manager := acl.NewManager()

// IP 层：私有网络 / 云元数据 / 回环 / Docker 全部进黑名单
manager.SetIPACLWithDefaults(nil, types.Blacklist, []ip.PredefinedSet{
    ip.PrivateNetworks,
    ip.LoopbackNetworks,
    ip.CloudMetadata,
    ip.DockerNetworks,
    ip.LinkLocalNetworks,
}, false)
```

真实程序输出——恶意目标在两层中被拦截，**请求根本没有发出**，正常业务地址不受影响：

```text
【阶段 2】接入 acl-skills：域名黑名单 + IP 预定义集
  域名黑名单：16 条（含短链预定义集）
  IP 黑名单：  13 条 CIDR（含私有网络、云元数据预定义集）

  同样的请求再次执行：
    [拦截] http://169.254.169.254/latest/meta-data/iam/security-credentials/
        → acl(ip): 拦截 169.254.169.254 → 169.254.169.254（命中 IP 黑名单）
    [拦截] http://10.0.0.5/internal/api-tokens
        → acl(ip): 拦截 10.0.0.5 → 10.0.0.5（命中 IP 黑名单）
    [拦截] http://api.legit-cdn.com/status
        → acl(ip): 拦截 api.legit-cdn.com → 10.0.0.9（命中 IP 黑名单）
    [放行] https://api.example.com/legit → 正常请求不受影响
```

## 为什么是"双维度"

案例刻意覆盖了三种绕过路径，只做单层防护都会被攻破：

| 绕过方式 | 单层域名防护 | 单层 IP 防护 | acl-skills 双维度 |
|----------|--------------|--------------|--------------------|
| 直接给 IP（`169.254.169.254`） | ❌ 域名层无从下手 | ✅ 命中 CloudMetadata | ✅ 域名/IP 层都拦 |
| 内网域名（`10.0.0.5`） | ❌ 不在域名黑名单 | ✅ 命中私有网络 | ✅ |
| DNS rebinding（`api.legit-cdn.com` → 内网） | ❌ 域名看起来可信 | ✅ 解析后 IP 命中内网 | ✅ IP 层兜底 |

- 域名层 `CheckDomain` 在工具调用发起前拦截，能拦掉短链、一次性邮箱等恶意域名类别
- IP 层 `CheckIP` 放在 dial 钩子里，拿到的是 **DNS 解析后的真实 IP**，专治域名可信但指向内网这类绕过

## fail-closed：配置缺失时拒绝而不是放行

程序最后还演示了一个安全语义：当 ACL 未配置时，`CheckIP` 返回 `ErrNoACL`，而不是「放行」。上层 dial 钩子收到这个错误即可默认拒绝——**宁可误伤，不可裸奔**：

```text
【附加】fail-closed：ACL 配置缺失时拒绝而非放行
  CheckIP 返回 ErrNoACL —— 上层 dial 钩子可据此默认拒绝
```

## 一行的代价

把检查放进 dial 钩子后，每次出站请求的额外开销是两次常数级查找，**零内存分配**。真实基准：`Manager.CheckIP` 约 **60 ns/op**，`Manager.CheckDomain` 约 **78 ns/op**。对一次实际 HTTP 请求的耗时占比可以忽略不计。

- [案例 2：一份策略文件接管整个 Web 服务](case-2-middleware-policy.md)
