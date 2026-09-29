# 案例 2：一份策略文件接管整个 Web 服务

> 源码：[`examples/08_http_middleware/main.go`](https://github.com/cyberspacesec/acl-skills/blob/main/examples/08_http_middleware/main.go)（`cd examples/08_http_middleware && go run main.go`）

## 问题

很多团队有现成的 HTTP 服务（内部系统、Agent 回调端点、管理后台），出站安全长期裸奔：既不拦内网地址，也不管恶意域名，谁都能访问云元数据端点。逐个 handler 加检查又太侵入。

## 做法：JSON 策略 + 一行中间件

第一步，把规则写进**一份** `testdata/security_policy.json`（同时含域名层与 IP 层，还引用预定义集合）：

```json
{
  "domain": {
    "domains": ["malware-site.com", "phishing-example.org"],
    "listType": "blacklist",
    "includeSubdomains": true,
    "predefinedSets": ["shorteners", "disposable_email"],
    "allowPredefined": false
  },
  "ip": {
    "ranges": ["203.0.113.0/24"],
    "listType": "blacklist",
    "predefinedSets": [
      "private_networks",
      "loopback_networks",
      "cloud_metadata",
      "docker_networks"
    ],
    "allowPredefined": false
  }
}
```

第二步，加载策略并挂载中间件，业务代码一行不用改：

```go
// 1. 从 JSON 加载域名 + IP 规则
pol, _ := config.LoadPolicyFromFile("security_policy.json")

manager := acl.NewManager()
manager.ApplyPolicy(pol)

// 2. 中间件包装业务 mux
mux := http.NewServeMux()
mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, %s!\n", r.Host)
})

// CheckClientIP: 校验来源 IP；CheckHost: 校验请求 Host（域名层）
handler := middleware.New(manager, middleware.Options{
    CheckClientIP: true,
    CheckHost:     true,
})(mux)

http.ListenAndServe(":8080", handler)
```

## 运行结果

程序启动时的真实输出：

```text
已从 JSON 加载域名 + IP 访问控制策略
中间件已挂载，监听 :8080
  - 域名黑名单 + 子域名 → 403
  - IP 黑名单（内网/云元数据/Docker/203.0.113.0/24）→ 403
```

之后的行为：

- 请求 `Host` 命中域名黑名单（含 `sub.malware-site.com` 这样的子域名）→ **403**
- 请求来源 IP 命中内网、云元数据或 `203.0.113.0/24` → **403**
- 其余正常请求原样放行

## 两个容易踩的安全细节

1. **默认不信任 `X-Forwarded-For`**。中间件 `Options` 里 `TrustProxy` 默认为 `false`，直接读 socket 对端 IP，防止攻击者伪造转发头绕过 IP 黑名单。
2. **策略即代码**。同一份 JSON 可以进 Git 评审、走环境差异配置、在 CI 里做规则变更审计，规则来源可追溯。

- [案例 3：用域名模式规则拦截数据外泄](case-3-domain-pattern.md)
