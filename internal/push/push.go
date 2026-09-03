// Package push 推送（Bark / PushPlus）+ 2FA 登录验证码
// 验证码格式与流程对齐 OCI-Panel：6 位数字、5 分钟有效、错满 5 次作废
package push

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"ctyun-panel/internal/store"
)

// Result 推送结果
type Result struct {
	Ok        bool
	Error     string
	Retryable bool
}

// Provider 推送渠道参数
type Provider struct {
	Provider string // bark / pushplus
	BarkURL  string
	BarkKey  string
	Token    string
}

// BuildProviderFromSettings 从用户设置构造（forceChannel 可强制渠道）
func BuildProviderFromSettings(s store.Settings, forceChannel string) Provider {
	channel := forceChannel
	if channel == "" {
		channel = s.TwoFAChannel
	}
	if channel == "" {
		channel = "bark"
	}
	if channel == "pushplus" {
		return Provider{Provider: "pushplus", Token: s.PushplusToken}
	}
	barkURL := s.BarkURL
	if barkURL == "" {
		barkURL = "https://api.day.app"
	}
	return Provider{Provider: "bark", BarkURL: barkURL, BarkKey: s.BarkKey}
}

// ---- HTTP 工具（15s 超时，禁止重定向） ----

// 仅用于推送出口（pushplus 目标主机固定），禁止跟随重定向防止 SSRF 时被引导到内网
var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func httpGet(rawURL string) (any, error) {
	resp, err := httpClient.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var parsed any
	if err := json.Unmarshal(b, &parsed); err == nil {
		return parsed, nil
	}
	return string(b), nil
}

func httpPostJSON(rawURL string, body any) (any, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Post(rawURL, "application/json; charset=utf-8", strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var parsed any
	if err := json.Unmarshal(rb, &parsed); err == nil {
		return parsed, nil
	}
	return string(rb), nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ValidateBarkURL 校验 Bark 服务器地址：仅允许 https，且禁止指向
// 环回/私网/链路本地地址（防止 SSRF 内网探测与 BarkKey 明文外带）。
func ValidateBarkURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("URL 格式错误")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("Bark 服务器地址必须使用 https://")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("缺少主机名")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("不允许指向内网地址")
		}
		return nil
	}
	// 域名：解析后逐个 IP 检查
	addrs, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("域名无法解析")
	}
	for _, ip := range addrs {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("不允许指向内网地址")
		}
	}
	return nil
}

// barkPushUrl {server}/{deviceKey}/{content}?title=xxx
func barkPushUrl(barkURL, barkKey, content, title string) string {
	server := strings.TrimRight(strings.TrimSpace(barkURL), "/")
	key := strings.TrimSpace(barkKey)
	return fmt.Sprintf("%s/%s/%s?title=%s", server, key, urlEncode(content), urlEncode(title))
}

func urlEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// ---- 推送 ----

func pushOnce(p Provider, contentBark, contentHtml, title string) Result {
	if p.Provider == "bark" {
		if p.BarkURL == "" {
			return Result{Error: "Bark 服务器地址未配置"}
		}
		if err := ValidateBarkURL(p.BarkURL); err != nil {
			return Result{Error: "Bark 服务器地址无效：" + err.Error()}
		}
		if p.BarkKey == "" {
			return Result{Error: "Bark 设备 Key 未配置（在 Bark App 内复制）"}
		}
		r, err := httpGet(barkPushUrl(p.BarkURL, p.BarkKey, contentBark, title))
		if err != nil {
			return Result{Error: "推送失败：" + err.Error(), Retryable: isRetryable(err)}
		}
		if m, ok := r.(map[string]any); ok {
			if code, _ := m["code"].(float64); code == 200 {
				return Result{Ok: true}
			}
		}
		js, _ := json.Marshal(r)
		return Result{Error: "Bark 返回异常：" + clip(string(js), 150)}
	}
	if p.Provider == "pushplus" {
		if p.Token == "" {
			return Result{Error: "PushPlus Token 未配置"}
		}
		r, err := httpPostJSON("https://www.pushplus.plus/send", map[string]any{
			"token":    p.Token,
			"title":    title,
			"content":  contentHtml,
			"template": "html",
		})
		if err != nil {
			return Result{Error: "推送失败：" + err.Error(), Retryable: isRetryable(err)}
		}
		if m, ok := r.(map[string]any); ok {
			if code, _ := m["code"].(float64); code == 200 {
				return Result{Ok: true}
			}
		}
		js, _ := json.Marshal(r)
		return Result{Error: "PushPlus 返回异常：" + clip(string(js), 150)}
	}
	return Result{Error: "未知的推送方式"}
}

func isRetryable(err error) bool {
	msg := err.Error()
	for _, s := range []string{"no such host", "lookup", "connection reset", "Client.Timeout", "EOF"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// SendAlertText 通用文本推送（测试推送）
func SendAlertText(s store.Settings, forceChannel, title, content string) Result {
	info := BuildProviderFromSettings(s, forceChannel)
	if info.Provider == "bark" {
		if info.BarkKey == "" {
			return Result{Error: "未配置 Bark 设备 Key"}
		}
		return pushOnce(info, clip(content, 4000), "", clip(title, 200))
	}
	if info.Provider == "pushplus" {
		if info.Token == "" {
			return Result{Error: "未配置 PushPlus Token"}
		}
		// template 为 html，\n 换行不生效，需转 <br>
		html := strings.ReplaceAll(clip(content, 3000), "\n", "<br>")
		return pushOnce(info, "", html, clip(title, 50))
	}
	return Result{Error: "未知推送渠道"}
}

// TestPush 测试推送通道（按传入参数直接推）
func TestPush(p Provider) Result {
	title := "TY CloudPC 推送测试"
	content := "这是一条测试消息，如果收到说明配置正确。"
	return SendAlertText(store.Settings{
		BarkURL:       p.BarkURL,
		BarkKey:       p.BarkKey,
		PushplusToken: p.Token,
		TwoFAChannel:  p.Provider,
	}, p.Provider, title, content)
}

// ---- 2FA 验证码 ----

type pendingCode struct {
	code      string
	expiresAt time.Time
	attempts  int
}

var (
	codeMu       sync.Mutex
	pendingCodes = map[string]*pendingCode{}
)

const codeTTL = 5 * time.Minute

func genCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return "000000"
	}
	return fmt.Sprintf("%06d", n.Int64()+100000)
}

// SendCode 发送验证码（校验通过前不落 session；失败作废）
func SendCode(p Provider, username, ip string) Result {
	code := genCode()
	codeMu.Lock()
	pendingCodes[username] = &pendingCode{code: code, expiresAt: time.Now().Add(codeTTL)}
	codeMu.Unlock()

	location := lookupIpLocation(ip)
	ipPart := ""
	if location != "" {
		ipPart = fmt.Sprintf("来自：【%s】", location)
	}
	// 标题与正文格式对齐 OCI-Panel
	title := "TYC验证码" + code
	contentBark := fmt.Sprintf("TY CloudPC提醒你：\n%s\n正在执行登录操作\n验证码为：%s\n验证码有效期 5 分钟，请尽快认证", ipPart, code)
	contentHtml := fmt.Sprintf("TY CloudPC提醒你：<br>%s<br>正在执行登录操作<br>验证码为：<b>%s</b><br>验证码有效期 5 分钟，请尽快认证", ipPart, code)

	r := pushOnce(p, contentBark, contentHtml, title)
	if r.Ok {
		return r
	}
	if r.Retryable {
		time.Sleep(800 * time.Millisecond) // DNS 偶发失败稍等重试一次
		r2 := pushOnce(p, contentBark, contentHtml, title)
		if r2.Ok {
			return r2
		}
		discardCode(username)
		return Result{Error: r2.Error}
	}
	discardCode(username)
	return r
}

func discardCode(username string) {
	codeMu.Lock()
	delete(pendingCodes, username)
	codeMu.Unlock()
}

// VerifyCode 校验验证码（错满 5 次作废）
func VerifyCode(username, code string) Result {
	codeMu.Lock()
	defer codeMu.Unlock()
	p, ok := pendingCodes[username]
	if !ok {
		return Result{Error: "请先获取验证码"}
	}
	if time.Now().After(p.expiresAt) {
		delete(pendingCodes, username)
		return Result{Error: "验证码已过期，请重新获取"}
	}
	if p.code != code {
		p.attempts++
		if p.attempts >= 5 {
			delete(pendingCodes, username)
			return Result{Error: "错误次数过多，验证码已作废，请重新获取"}
		}
		return Result{Error: fmt.Sprintf("验证码错误（剩余 %d 次机会）", 5-p.attempts)}
	}
	delete(pendingCodes, username)
	return Result{Ok: true}
}

// ---- IP 归属地（ip-api.com，4s 超时，30 分钟缓存；失败降级只显示 IP） ----

var (
	locMu    sync.Mutex
	locCache = map[string]locEntry{}
)

type locEntry struct {
	location   string
	expiresAt  time.Time
}

func isPrivateIP(ip string) bool {
	if ip == "" {
		return true
	}
	s := strings.TrimPrefix(ip, "::ffff:")
	if s == "::1" || s == "0.0.0.0" {
		return true
	}
	ipObj := net.ParseIP(s)
	if ipObj == nil {
		return false
	}
	return ipObj.IsLoopback() || ipObj.IsPrivate() || ipObj.IsLinkLocalUnicast()
}

func lookupIpLocation(ip string) string {
	if ip == "" {
		return "未知"
	}
	if isPrivateIP(ip) {
		return ip + "/本地网络"
	}
	locMu.Lock()
	if c, ok := locCache[ip]; ok && time.Now().Before(c.expiresAt) {
		locMu.Unlock()
		return c.location
	}
	locMu.Unlock()

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?lang=zh-CN&fields=status,country,regionName,city", ip))
	if err != nil {
		return ip
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return ip
	}
	var j struct {
		Status     string `json:"status"`
		Country    string `json:"country"`
		RegionName string `json:"regionName"`
		City       string `json:"city"`
	}
	if err := json.Unmarshal(b, &j); err != nil || j.Status != "success" {
		return ip
	}
	parts := []string{}
	for _, p := range []string{j.Country, j.RegionName, j.City} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return ip
	}
	location := ip + "/" + strings.Join(parts, "")
	locMu.Lock()
	locCache[ip] = locEntry{location: location, expiresAt: time.Now().Add(30 * time.Minute)}
	locMu.Unlock()
	return location
}
