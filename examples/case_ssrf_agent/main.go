// Package main 演示 acl-skills 如何在真实 AI Agent 中拦截 SSRF 攻击
//
// 场景：Agent 收到一条"用户消息"，其中被注入恶意指令，试图让 Agent
// 访问云元数据端点 / 内网服务。演示双维度防护：
//
//  1. 域名层 CheckDomain —— 工具调用发起前，先校验目标域名
//  2. IP 层 CheckIP     —— TCP dial 钩子里兜底，防 DNS rebinding 绕过
//
// 运行：go run main.go  （本地直接可跑，无外部依赖、不真正联网）
package main

import (
	"errors"
	"fmt"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/domain"
	"github.com/cyberspacesec/acl-skills/pkg/ip"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// dns 模拟 Agent 的 DNS 解析结果（本地可跑，不真正联网）。
// 恶意目标由注入消息给出；解析结果由真实 DNS / Agent 的解析器提供。
var dns = map[string]string{
	// 恶意目标：攻击者让 Agent 访问"看似正常"的地址，实则指向内网
	"http://169.254.169.254/latest/meta-data/iam/security-credentials/": "169.254.169.254", // 云元数据 → 云凭证
	"http://10.0.0.5/internal/api-tokens":                               "10.0.0.5",        // 内网服务 → 未授权数据
	"https://api.example.com/legit":                                     "93.184.216.34",   // 正常业务地址 → 应予放行

	// DNS rebinding：域名看似可信，二次解析却指向内网
	"http://api.legit-cdn.com/status": "10.0.0.9",
}

// send 模拟 Agent 的一次 HTTP 工具调用，走"域名层 → IP 层"双检查。
// 返回 error 即代表连接没有被建立。
func send(m *acl.Manager, url string) error {
	host := hostOnly(url)

	// 第一层：域名校验（工具调用发起前）
	perm, err := m.CheckDomain(host)
	if err != nil && !errors.Is(err, types.ErrNoACL) {
		return fmt.Errorf("域名校验异常: %v", err)
	}
	if err == nil && perm == types.Denied {
		return fmt.Errorf("acl(domain): 拦截 %s（命中域名黑名单）", host)
	}

	// 第二层：IP 校验（dial 钩子内，拿到解析后的 IP）
	addrIP := dns[url]
	if ipPerm, err := m.CheckIP(addrIP); err == nil && ipPerm == types.Denied {
		return fmt.Errorf("acl(ip): 拦截 %s → %s（命中 IP 黑名单）", host, addrIP)
	}
	return nil // 两层均放行，连接建立
}

// hostOnly 从 URL 提取裸主机名
func hostOnly(url string) string {
	raw := url
	if len(raw) >= 7 && raw[:7] == "http://" {
		raw = raw[7:]
	} else if len(raw) >= 8 && raw[:8] == "https://" {
		raw = raw[8:]
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] == '/' {
			return raw[:i]
		}
	}
	return raw
}

// naiveSend 模拟无防护的 Agent：域名/IP 一律放行
func naiveSend(url string) error { return nil }

func main() {
	fmt.Println("==========================================================")
	fmt.Println("  案例：Prompt Injection 驱动的 SSRF —— 无防护 vs acl-skills")
	fmt.Println("==========================================================")

	// ---------- 阶段 1：未接入 ACL（攻击得逞） ----------
	fmt.Println("\n【阶段 1】Agent 未接入任何 ACL")
	fmt.Println("  注入的恶意消息使 Agent 尝试访问：")
	for _, u := range []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://10.0.0.5/internal/api-tokens",
		"http://api.legit-cdn.com/status",
	} {
		fmt.Printf("    %s\n", u)
	}
	fmt.Println("\n  执行结果：")
	for _, u := range []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://10.0.0.5/internal/api-tokens",
		"http://api.legit-cdn.com/status",
	} {
		_ = naiveSend(u)
		fmt.Printf("    [放行] %s → 连接建立，请求发出（攻击得逞）\n", u)
	}
	fmt.Println("\n  >> 云凭证被窃取、内网接口被访问。这正是真实 SSRF 漏洞的成因。")

	// ---------- 阶段 2：一行配置接入 acl-skills ----------
	fmt.Println("\n----------------------------------------------------------")
	fmt.Println("【阶段 2】接入 acl-skills：域名黑名单 + IP 预定义集")

	m := acl.NewManager()

	// 域名层：短链 / 一次性邮箱等高风险类别整体拦截
	if err := m.SetDomainACLWithDefaults(
		nil, types.Blacklist, true,
		[]domain.PredefinedSet{
			domain.Shorteners,      // bit.ly、tinyurl.com 等
			domain.DisposableEmail, // mailinator.com 等
		},
		false,
	); err != nil {
		panic(err)
	}

	// IP 层：私有网络 / 云元数据 / 回环 / Docker / 链路本地
	if err := m.SetIPACLWithDefaults(
		nil, types.Blacklist,
		[]ip.PredefinedSet{
			ip.PrivateNetworks,
			ip.LoopbackNetworks,
			ip.CloudMetadata,
			ip.DockerNetworks,
			ip.LinkLocalNetworks,
		},
		false,
	); err != nil {
		panic(err)
	}

	fmt.Printf("  域名黑名单：%d 条（含短链预定义集）\n", len(m.GetDomains()))
	fmt.Printf("  IP 黑名单：  %d 条 CIDR（含私有网络、云元数据预定义集）\n", len(m.GetIPRanges()))

	fmt.Println("\n  同样的请求再次执行：")
	cases := []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://10.0.0.5/internal/api-tokens",
		"http://api.legit-cdn.com/status",
		"https://api.example.com/legit",
	}
	for _, u := range cases {
		err := send(m, u)
		if err != nil {
			fmt.Printf("    [拦截] %s\n        → %v\n", u, err)
		} else {
			fmt.Printf("    [放行] %s → 正常请求不受影响\n", u)
		}
	}

	fmt.Println("\n  >> 恶意目标在域名层或 IP 层被拦截，请求根本没有发出；")
	fmt.Println("     正常业务地址在两层均通过，照常放行。")
	fmt.Println("     DNS rebinding（域名可信但指向内网）也由 IP 层兜底拦截。")

	// ---------- 收尾：fail-closed 兜底 ----------
	fmt.Println("\n----------------------------------------------------------")
	fmt.Println("【附加】fail-closed：ACL 配置缺失时拒绝而非放行")
	strict := acl.NewManager() // 未配置任何 ACL
	_, err := strict.CheckIP("10.0.0.1")
	if errors.Is(err, types.ErrNoACL) {
		fmt.Println("  CheckIP 返回 ErrNoACL —— 上层 dial 钩子可据此默认拒绝")
	}
}
