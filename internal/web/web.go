// Package web HTTP 路由与页面渲染（安全加固参照 OCI-Panel：会话签名、
// 登录限流、哑哈希防枚举、安全响应头）
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ctyun-panel/internal/cryptoutil"
	"ctyun-panel/internal/keeper"
	"ctyun-panel/internal/push"
	"ctyun-panel/internal/ratelimit"
	"ctyun-panel/internal/session"
	"ctyun-panel/internal/store"
)

//go:embed templates/*.html static/style.css
var files embed.FS

var funcs = template.FuncMap{
	"statusText": statusText,
}

var tmpl = template.Must(template.New("").Funcs(funcs).ParseFS(files, "templates/*.html"))

var staticFS, _ = fs.Sub(files, "static")

func statusText(s string) string {
	switch s {
	case keeper.StatusStarting:
		return "启动中"
	case keeper.StatusAwaitingSMS:
		return "待输入验证码"
	case keeper.StatusRunning:
		return "保活中"
	case keeper.StatusError:
		return "异常"
	case keeper.StatusStopped:
		return "已停止"
	}
	return s
}

// New 构造带全部路由与中间件的 Handler
func New(m *keeper.Manager) http.Handler {
	mux := http.NewServeMux()

	// 静态资源
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// 初始化 / 认证
	mux.HandleFunc("GET /setup", handleSetupPage)
	mux.HandleFunc("POST /setup", handleSetupSubmit)
	mux.HandleFunc("GET /login", handleLoginPage)
	mux.HandleFunc("POST /login", handleLoginSubmit)
	mux.HandleFunc("POST /login/send-code", handleSendCode)
	mux.HandleFunc("POST /logout", handleLogout)

	// 首页
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/accounts", http.StatusFound)
	})

	// 账号管理
	mux.HandleFunc("GET /accounts", handleAccountsPage)
	mux.HandleFunc("POST /accounts/add", handleAccountAdd)
	mux.HandleFunc("POST /accounts/{id}/delete", handleAccountDelete)
	mux.HandleFunc("POST /accounts/{id}/restart", handleAccountRestart)
	mux.HandleFunc("POST /accounts/{id}/stop", handleAccountStop)
	mux.HandleFunc("POST /accounts/{id}/start", handleAccountStart)
	mux.HandleFunc("POST /accounts/{id}/edit", handleAccountEdit)
	mux.HandleFunc("POST /accounts/{id}/sms", handleAccountSMS)
	mux.HandleFunc("POST /accounts/{id}/resend", handleAccountResend)
	mux.HandleFunc("GET /api/accounts", handleAPIAccounts)

	// 日志
	mux.HandleFunc("GET /logs", handleLogsPage)
	mux.HandleFunc("GET /api/logs", handleAPILogs)

	// 设置
	mux.HandleFunc("GET /settings", handleSettingsPage)
	mux.HandleFunc("POST /settings/password", handleSettingsPassword)
	mux.HandleFunc("POST /settings/keepalive", handleSettingsKeepalive)
	mux.HandleFunc("POST /settings/channel", handleSettingsChannel)
	mux.HandleFunc("POST /settings/channel/test", handleSettingsChannelTest)
	mux.HandleFunc("POST /settings/2fa", handleSettings2FA)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	return securityHeaders(authMiddleware(setupMiddleware(mux)))
}

// securityHeaders 全局安全响应头：防点击劫持、MIME 嗅探、外站引用泄露
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// ============================================================
// 中间件
// ============================================================

type ctxKey int

const usernameKey ctxKey = 1

// 首次使用（无用户）：除 /setup 和静态资源外全部跳转初始化页
func setupMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !store.HasUser() && !strings.HasPrefix(r.URL.Path, "/setup") && !strings.HasPrefix(r.URL.Path, "/static") {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// 登录校验：/login /setup /static 之外需登录
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasPrefix(path, "/login") || strings.HasPrefix(path, "/setup") || strings.HasPrefix(path, "/static") {
			next.ServeHTTP(w, r)
			return
		}
		username, _, epoch, ok := session.Current(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		// 会话吊销：改密码后旧 Cookie 的 epoch 落后于当前值，强制下线
		if u := store.FindUser(username); u == nil || u.PasswordEpoch != epoch {
			session.Logout(w)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), usernameKey, username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func currentUsername(r *http.Request) string {
	if v, ok := r.Context().Value(usernameKey).(string); ok {
		return v
	}
	return ""
}

// ============================================================
// 视图模型与渲染辅助
// ============================================================

type page struct {
	Title, Active, Username string
	Error, Success          string
	FormUsername            string
	// 登录页 2FA
	TwoFaEnabled    bool
	SubtitleText    string
	CodePlaceholder string
	// 账号页 / 日志页
	Accounts      []keeper.AccountStatus
	KeepAliveMin  int
	KeepAliveMax  int
	// 设置页
	Settings store.Settings
}

func render(w http.ResponseWriter, name string, data *page) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "模板渲染失败: "+err.Error(), http.StatusInternalServerError)
	}
}

func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func errOut(w http.ResponseWriter, msg string) {
	jsonOut(w, map[string]any{"ok": false, "error": msg})
}

func okOut(w http.ResponseWriter) {
	jsonOut(w, map[string]any{"ok": true})
}

func form(r *http.Request) map[string]string {
	_ = r.ParseForm()
	m := map[string]string{}
	for k, v := range r.PostForm {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}

// clientIP 获取客户端真实 IP；TRUST_PROXY=true 时取 X-Forwarded-For
// 最后一段（由最近的反向代理追加，客户端无法伪造）
func clientIP(r *http.Request) string {
	if os.Getenv("TRUST_PROXY") == "true" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			last := strings.TrimSpace(parts[len(parts)-1])
			if last != "" {
				return last
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

// ============================================================
// 初始化 / 认证
// ============================================================

func handleSetupPage(w http.ResponseWriter, r *http.Request) {
	if store.HasUser() {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	render(w, "setup.html", &page{Title: "初始化"})
}

var usernameRe = regexp.MustCompile(`^[\w.\-]{2,32}$`)

func handleSetupSubmit(w http.ResponseWriter, r *http.Request) {
	if store.HasUser() {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	f := form(r)
	username := strings.TrimSpace(f["username"])
	password := f["password"]
	confirm := f["confirm_password"]

	fail := func(msg string) {
		render(w, "setup.html", &page{Title: "初始化", Error: msg, FormUsername: username})
	}
	if !usernameRe.MatchString(username) {
		fail("用户名格式错误（2~32 位，字母 / 数字 / . _ -）")
		return
	}
	if len(password) < 6 {
		fail("密码至少 6 位")
		return
	}
	if password != confirm {
		fail("两次输入的密码不一致")
		return
	}
	hash, err := cryptoutil.HashPassword(password)
	if err != nil {
		fail("密码加密失败: " + err.Error())
		return
	}
	if !store.CreateUser(username, hash) {
		fail("用户名已存在")
		return
	}
	u := store.FindUser(username)
	session.Login(w, username, u.ID, u.PasswordEpoch)
	http.Redirect(w, r, "/accounts", http.StatusFound)
}

// loginView 登录页视图（2FA 开启时显示验证码输入框与获取按钮）
func loginView(firstTwoFA bool, subtitle string) *page {
	p := &page{
		Title:          "登录",
		TwoFaEnabled:   firstTwoFA,
		SubtitleText:   subtitle,
		CodePlaceholder: "请输入验证码",
	}
	if firstTwoFA {
		p.SubtitleText = "请输入账号、密码并完成验证码验证"
	} else if p.SubtitleText == "" {
		p.SubtitleText = "请输入账号和密码登录面板"
	}
	return p
}

// anyUser2FA 是否有用户开启 2FA（登录页据此决定是否显示验证码输入框）
func anyUser2FA() bool {
	for _, u := range store.ListUsers() {
		if store.GetUserSettings(u.Username).TwoFAEnabled {
			return true
		}
	}
	return false
}

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, _, _, ok := session.Current(r); ok {
		http.Redirect(w, r, "/accounts", http.StatusFound)
		return
	}
	render(w, "login.html", loginView(anyUser2FA(), ""))
}

// handleSendCode 登录第一步：账号密码正确后推送 2FA 验证码
func handleSendCode(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	username := strings.TrimSpace(f["username"])
	password := f["password"]
	if username == "" || password == "" {
		errOut(w, "请填写账号和密码")
		return
	}
	ip := clientIP(r)
	// 双维度限流：IP+用户名（防轰炸）+ 纯 IP 总量（防轮换用户名稀释计数）
	if ratelimit.Limited("sc:"+ip+"|"+username, 5, 10*time.Minute) || ratelimit.Limited("scip:"+ip, 20, 10*time.Minute) {
		errOut(w, "发送太频繁，请 10 分钟后再试")
		return
	}
	user := store.FindUser(username)
	if user == nil {
		// 哑哈希消除用户名枚举时序差
		cryptoutil.VerifyPassword(password, cryptoutil.DummyHash)
		errOut(w, "账号或密码错误")
		return
	}
	if !cryptoutil.VerifyPassword(password, user.PasswordHash) {
		errOut(w, "账号或密码错误")
		return
	}
	s := store.GetUserSettings(username)
	if !s.TwoFAEnabled {
		errOut(w, `该账号未开启二次验证，直接点击"登录"即可`)
		return
	}
	res := push.SendCode(push.BuildProviderFromSettings(s, s.TwoFAChannel), username, ip)
	if res.Ok {
		okOut(w)
		return
	}
	errOut(w, res.Error)
}

func handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	username := strings.TrimSpace(f["username"])
	password := f["password"]
	code := strings.TrimSpace(f["code"])
	ip := clientIP(r)
	// 双维度限流：IP+用户名（防单账号爆破）+ 纯 IP 总量（防轮换用户名稀释计数）
	rlKey := "lg:" + ip + "|" + username
	rlIPKey := "lgip:" + ip
	if ratelimit.Limited(rlKey, 10, 15*time.Minute) || ratelimit.Limited(rlIPKey, 50, 15*time.Minute) {
		p := loginView(true, "")
		p.Error = "尝试次数过多，请 15 分钟后再试"
		render(w, "login.html", p)
		return
	}

	failLogin := func(msg, subtitle string) {
		p := loginView(anyUser2FA(), "")
		p.Error = msg
		p.FormUsername = username
		if subtitle != "" {
			p.SubtitleText = subtitle
		}
		render(w, "login.html", p)
	}

	user := store.FindUser(username)
	if user == nil {
		// 哑哈希消除用户名枚举时序差
		cryptoutil.VerifyPassword(password, cryptoutil.DummyHash)
		failLogin("用户名或密码错误", "")
		return
	}
	if !cryptoutil.VerifyPassword(password, user.PasswordHash) {
		failLogin("用户名或密码错误", "")
		return
	}
	// 2FA 二次验证：验证码必填且须校验通过
	s := store.GetUserSettings(username)
	if s.TwoFAEnabled {
		if code == "" {
			failLogin(`请先点击"获取验证码"，再填入收到的验证码`, "请输入账号、密码并完成验证码验证")
			return
		}
		v := push.VerifyCode(username, code)
		if !v.Ok {
			failLogin(v.Error, "请输入账号、密码并完成验证码验证")
			return
		}
	}
	session.Login(w, user.Username, user.ID, user.PasswordEpoch)
	ratelimit.Clear(rlKey)
	http.Redirect(w, r, "/accounts", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	session.Logout(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// ============================================================
// 账号管理
// ============================================================

func accountsPage(r *http.Request) *page {
	kaMin, kaMax := store.KeepAlive()
	return &page{
		Title: "账号管理", Active: "accounts", Username: currentUsername(r),
		Accounts:     manager.Statuses(),
		KeepAliveMin: kaMin, KeepAliveMax: kaMax,
	}
}

func handleAccountsPage(w http.ResponseWriter, r *http.Request) {
	render(w, "accounts.html", accountsPage(r))
}

func handleAccountAdd(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	if err := manager.Add(f["name"], f["username"], f["password"], f["device_code"]); err != nil {
		errOut(w, err.Error())
		return
	}
	okOut(w)
}

func handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		errOut(w, "账号 ID 无效")
		return
	}
	if !manager.Delete(id) {
		errOut(w, "账号不存在")
		return
	}
	okOut(w)
}

func handleAccountRestart(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		errOut(w, "账号 ID 无效")
		return
	}
	if err := manager.Restart(id); err != nil {
		errOut(w, err.Error())
		return
	}
	okOut(w)
}

func handleAccountStop(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		errOut(w, "账号 ID 无效")
		return
	}
	if err := manager.Stop(id); err != nil {
		errOut(w, err.Error())
		return
	}
	okOut(w)
}

func handleAccountStart(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		errOut(w, "账号 ID 无效")
		return
	}
	if err := manager.Start(id); err != nil {
		errOut(w, err.Error())
		return
	}
	okOut(w)
}

func handleAccountEdit(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		errOut(w, "账号 ID 无效")
		return
	}
	f := form(r)
	if err := manager.Update(id, f["name"], f["password"]); err != nil {
		errOut(w, err.Error())
		return
	}
	okOut(w)
}

func handleAccountSMS(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		errOut(w, "账号 ID 无效")
		return
	}
	if err := manager.SubmitSMS(id, form(r)["code"]); err != nil {
		errOut(w, err.Error())
		return
	}
	okOut(w)
}

func handleAccountResend(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		errOut(w, "账号 ID 无效")
		return
	}
	if err := manager.ResendSMS(id); err != nil {
		errOut(w, err.Error())
		return
	}
	okOut(w)
}

func handleAPIAccounts(w http.ResponseWriter, r *http.Request) {
	kaMin, kaMax := store.KeepAlive()
	jsonOut(w, map[string]any{
		"ok":           true,
		"accounts":     manager.Statuses(),
		"keepAliveMin": kaMin,
		"keepAliveMax": kaMax,
	})
}

// ============================================================
// 日志
// ============================================================

func handleLogsPage(w http.ResponseWriter, r *http.Request) {
	render(w, "logs.html", &page{
		Title: "运行日志", Active: "logs", Username: currentUsername(r),
		Accounts: manager.Statuses(),
	})
}

func handleAPILogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	after, _ := strconv.Atoi(q.Get("after"))
	accountID, _ := strconv.Atoi(q.Get("account"))
	logs := manager.Logs(after, accountID)
	if logs == nil {
		logs = []keeper.LogEntry{}
	}
	jsonOut(w, map[string]any{"ok": true, "logs": logs, "maxSeq": manager.MaxLogSeq()})
}

// ============================================================
// 设置
// ============================================================

func settingsPage(r *http.Request, errMsg, success string) *page {
	kaMin, kaMax := store.KeepAlive()
	return &page{
		Title: "设置", Active: "settings", Username: currentUsername(r),
		KeepAliveMin: kaMin, KeepAliveMax: kaMax,
		Error:        errMsg, Success: success,
		Settings: store.GetUserSettings(currentUsername(r)),
	}
}

func handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	render(w, "settings.html", settingsPage(r, "", ""))
}

func handleSettingsPassword(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	username := currentUsername(r)
	user := store.FindUser(username)
	if user == nil {
		render(w, "settings.html", settingsPage(r, "用户不存在", ""))
		return
	}
	if !cryptoutil.VerifyPassword(f["current_password"], user.PasswordHash) {
		render(w, "settings.html", settingsPage(r, "当前密码错误", ""))
		return
	}
	newPassword := f["new_password"]
	if len(newPassword) < 6 {
		render(w, "settings.html", settingsPage(r, "新密码至少 6 位", ""))
		return
	}
	if newPassword != f["confirm_password"] {
		render(w, "settings.html", settingsPage(r, "两次输入的新密码不一致", ""))
		return
	}
	hash, err := cryptoutil.HashPassword(newPassword)
	if err != nil {
		render(w, "settings.html", settingsPage(r, "密码加密失败: "+err.Error(), ""))
		return
	}
	store.UpdateUserPassword(username, hash)
	render(w, "settings.html", settingsPage(r, "", "密码已修改，请重新登录"))
}

func handleSettingsKeepalive(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	minVal, err1 := strconv.Atoi(strings.TrimSpace(f["keepalive_min"]))
	maxVal, err2 := strconv.Atoi(strings.TrimSpace(f["keepalive_max"]))
	if err1 != nil || err2 != nil || minVal < 10 || maxVal < 10 || minVal > 120 || maxVal > 120 {
		render(w, "settings.html", settingsPage(r, "保活周期必须是 10 ~ 120 之间的整数（秒），不能超过服务端单连接 120 秒存活上限", ""))
		return
	}
	if minVal > maxVal {
		render(w, "settings.html", settingsPage(r, "最小周期不能大于最大周期", ""))
		return
	}
	store.SetKeepAlive(minVal, maxVal)
	manager.RestartAll()
	render(w, "settings.html", settingsPage(r, "", fmt.Sprintf("保活周期已设为 %d ~ %d 秒随机重连，全部任务已重启生效", minVal, maxVal)))
}

// ============================================================
// 推送渠道与 2FA
// ============================================================

// handleSettingsChannel 保存 Bark / PushPlus 推送渠道参数
func handleSettingsChannel(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	username := currentUsername(r)
	barkURL := strings.TrimSpace(f["bark_url"])
	if barkURL != "" {
		if err := push.ValidateBarkURL(barkURL); err != nil {
			render(w, "settings.html", settingsPage(r, "Bark 服务器地址无效："+err.Error(), ""))
			return
		}
	}
	store.UpdateUserSettings(username, func(s *store.Settings) {
		s.BarkURL = barkURL
		s.BarkKey = strings.TrimSpace(f["bark_key"])
		s.PushplusToken = strings.TrimSpace(f["pushplus_token"])
	})
	render(w, "settings.html", settingsPage(r, "", "推送渠道配置已保存"))
}

// handleSettingsChannelTest 测试推送（支持未保存的表单参数直接测试）
func handleSettingsChannelTest(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	channel := f["provider"]
	if channel == "" {
		channel = f["channel"] // 兼容旧参数名
	}
	if channel != "bark" && channel != "pushplus" {
		errOut(w, "推送渠道无效")
		return
	}
	s := store.GetUserSettings(currentUsername(r))
	p := push.BuildProviderFromSettings(s, channel)
	// 表单参数覆盖已保存值：填写后无需先保存即可测试
	if v := strings.TrimSpace(f["bark_url"]); v != "" {
		p.BarkURL = v
	}
	if v := strings.TrimSpace(f["bark_key"]); v != "" {
		p.BarkKey = v
	}
	if v := strings.TrimSpace(f["pushplus_token"]); v != "" {
		p.Token = v
	}
	if channel == "bark" && p.BarkKey == "" {
		errOut(w, "Bark 设备 Key 未配置，请先填写")
		return
	}
	if channel == "pushplus" && p.Token == "" {
		errOut(w, "PushPlus Token 未配置，请先填写")
		return
	}
	res := push.TestPush(p)
	if !res.Ok {
		errOut(w, res.Error)
		return
	}
	chName := "Bark"
	if channel == "pushplus" {
		chName = "PushPlus"
	}
	jsonOut(w, map[string]any{"ok": true, "message": "已通过 " + chName + " 发送测试消息，请查收"})
}

// handleSettings2FA 保存 2FA 设置（勾选开启时强制测试推送，防止把自己锁在门外）
func handleSettings2FA(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	ch := f["two_fa_channel"]
	if ch != "bark" && ch != "pushplus" {
		ch = "bark"
	}
	enable := f["two_fa_enabled"] == "on"
	username := currentUsername(r)
	settings := store.GetUserSettings(username)

	if enable {
		if ch == "bark" && settings.BarkKey == "" {
			render(w, "settings.html", settingsPage(r, "Bark 未配置，请先在上方「推送渠道」中填写并保存 Bark 设备 Key", ""))
			return
		}
		if ch == "pushplus" && settings.PushplusToken == "" {
			render(w, "settings.html", settingsPage(r, "PushPlus 未配置，请先在上方「推送渠道」中填写并保存 PushPlus Token", ""))
			return
		}
		// 渠道必须测试推送能过，否则不开（避免开完收不到验证码被锁在门外）
		if res := push.TestPush(push.BuildProviderFromSettings(settings, ch)); !res.Ok {
			store.UpdateUserSettings(username, func(s *store.Settings) {
				s.TwoFAChannel = ch
				s.TwoFAEnabled = false
			})
			render(w, "settings.html", settingsPage(r, "2FA 推送测试失败，未开启："+res.Error+"（请先确认上方「推送渠道」配置正常）", ""))
			return
		}
		store.UpdateUserSettings(username, func(s *store.Settings) {
			s.TwoFAEnabled = true
			s.TwoFAChannel = ch
		})
		chName := "Bark"
		if ch == "pushplus" {
			chName = "PushPlus"
		}
		render(w, "settings.html", settingsPage(r, "", fmt.Sprintf("2FA 二次验证已开启（使用 %s），下次登录需要输入验证码", chName)))
		return
	}
	prev := settings.TwoFAEnabled
	store.UpdateUserSettings(username, func(s *store.Settings) {
		s.TwoFAEnabled = false
		s.TwoFAChannel = ch
	})
	msg := "2FA 设置已保存（未开启）"
	if prev {
		msg = "2FA 二次验证已关闭"
	}
	render(w, "settings.html", settingsPage(r, "", msg))
}

// manager 由 main 通过 SetManager 注入
var manager *keeper.Manager

// SetManager 注入保活管理器
func SetManager(m *keeper.Manager) {
	manager = m
}
