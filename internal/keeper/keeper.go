// Package keeper 账号保活管理器：登录、设备绑定（短信验证码）、WebSocket 保活
package keeper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"ctyun-panel/internal/ctyun"
	"ctyun-panel/internal/store"
)

// 账号运行状态
const (
	StatusStarting    = "starting"
	StatusAwaitingSMS = "awaiting_sms"
	StatusRunning     = "running"
	StatusError       = "error"
	StatusStopped     = "stopped"
)

const (
	smsWaitTimeout  = 5 * time.Minute // 等待用户输入短信验证码的超时
	maxBindAttempts = 6               // 验证码最大尝试次数
	initialPayloadB64 = "UkVEUQIAAAACAAAAGgAAAAAAAAABAAEAAAABAAAAEgAAAAkAAAAECAAA"
)

type DesktopStatus struct {
	Code       string `json:"code"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	LastConnect string `json:"lastConnect,omitempty"`
}

type AccountStatus struct {
	ID         int             `json:"id"`
	Name       string          `json:"name"`
	Username   string          `json:"username"`
	DeviceCode string          `json:"deviceCode,omitempty"`
	Status     string          `json:"status"`
	Message    string          `json:"message,omitempty"`
	Desktops   []DesktopStatus `json:"desktops,omitempty"`
}

// Manager 管理所有账号的保活任务
type Manager struct {
	mu      sync.Mutex
	runners map[int]*runner
	logs    *LogBuffer
}

func NewManager() *Manager {
	return &Manager{
		runners: make(map[int]*runner),
		logs:    NewLogBuffer(2000),
	}
}

// StartAll 启动所有已存账号的保活任务（程序启动时调用）
func (m *Manager) StartAll() {
	for _, a := range store.ListAccounts() {
		m.startRunner(a)
	}
}

// Add 新增账号并立即启动保活；deviceCode 选填（从原 C# 版迁移时填入可免重新绑定设备）
func (m *Manager) Add(name, username, password, deviceCode string) error {
	a, err := store.AddAccount(name, username, password, deviceCode)
	if err != nil {
		return err
	}
	m.startRunner(*a)
	return nil
}

// Update 更新账号（名称/密码）并重启任务；密码修改后沿用原设备码，无需重新绑定设备
func (m *Manager) Update(id int, name, password string) error {
	a, err := store.UpdateAccount(id, name, password)
	if err != nil {
		return err
	}
	m.startRunner(*a)
	return nil
}

// Delete 删除账号并停止任务
func (m *Manager) Delete(id int) bool {
	m.mu.Lock()
	if r, ok := m.runners[id]; ok {
		r.cancel()
		delete(m.runners, id)
	}
	m.mu.Unlock()
	return store.DeleteAccount(id)
}

// Restart 重启账号任务
func (m *Manager) Restart(id int) error {
	a := store.GetAccount(id)
	if a == nil {
		return fmt.Errorf("账号不存在")
	}
	m.startRunner(*a)
	return nil
}

// RestartAll 重启全部任务（修改保活周期后调用）
func (m *Manager) RestartAll() {
	for _, a := range store.ListAccounts() {
		m.startRunner(a)
	}
}

// SubmitSMS 提交短信验证码（设备绑定）
func (m *Manager) SubmitSMS(id int, code string) error {
	code = strings.TrimSpace(code)
	if code == "" {
		return fmt.Errorf("请输入验证码")
	}
	m.mu.Lock()
	r := m.runners[id]
	status := ""
	if r != nil {
		status = r.status.Status
	}
	m.mu.Unlock()
	if r == nil {
		return fmt.Errorf("账号任务不存在")
	}
	if status != StatusAwaitingSMS {
		return fmt.Errorf("当前状态无需输入验证码")
	}
	select {
	case r.smsCh <- code:
		return nil
	default:
		return fmt.Errorf("验证码提交繁忙，请稍后重试")
	}
}

// ResendSMS 重发短信验证码（仅待输入验证码状态可用）
func (m *Manager) ResendSMS(id int) error {
	m.mu.Lock()
	r := m.runners[id]
	var api *ctyun.Client
	var username string
	if r != nil {
		api = r.api
		username = r.acct.Username
	}
	m.mu.Unlock()
	if r == nil || api == nil {
		return fmt.Errorf("当前无需重发验证码")
	}
	go func() {
		log := func(level, format string, args ...interface{}) {
			m.logs.Add(id, r.acct.Name, "", level, fmt.Sprintf(format, args...))
		}
		if api.SendSMSCode(context.Background(), username, log) {
			m.logs.Add(id, r.acct.Name, "", "ok", "短信验证码已重新发送，请注意查收")
		} else {
			m.logs.Add(id, r.acct.Name, "", "error", "短信验证码重发失败")
		}
	}()
	return nil
}

// Statuses 返回所有账号状态（按 ID 排序）
func (m *Manager) Statuses() []AccountStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]AccountStatus, 0, len(m.runners))
	for _, r := range m.runners {
		out = append(out, r.status)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Logs 查询日志
func (m *Manager) Logs(after, accountID int) []LogEntry {
	return m.logs.After(after, accountID)
}

// ============================================================
// 单账号任务
// ============================================================

type runner struct {
	mgr    *Manager
	acct   store.Account
	cancel context.CancelFunc
	smsCh  chan string
	// 以下字段由 mgr.mu 保护
	status AccountStatus
	api    *ctyun.Client // 待输入验证码时保留登录态，用于绑定/重发
}

func (m *Manager) startRunner(acct store.Account) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &runner{
		mgr:    m,
		acct:   acct,
		cancel: cancel,
		smsCh:  make(chan string, 8),
		status: AccountStatus{
			ID: acct.ID, Name: acct.Name, Username: acct.Username, DeviceCode: acct.DeviceCode,
			Status: StatusStarting, Message: "正在登录",
		},
	}
	m.mu.Lock()
	if old, ok := m.runners[acct.ID]; ok {
		old.cancel()
	}
	m.runners[acct.ID] = r
	m.mu.Unlock()
	go r.run(ctx)
}

func (r *runner) set(mutate func(*AccountStatus)) {
	r.mgr.mu.Lock()
	mutate(&r.status)
	r.mgr.mu.Unlock()
}

func (r *runner) setError(msg string) {
	r.set(func(s *AccountStatus) { s.Status = StatusError; s.Message = msg })
	r.log("", "error", "%s", msg)
}

func (r *runner) log(desktop, level, format string, args ...interface{}) {
	r.mgr.logs.Add(r.acct.ID, r.acct.Name, desktop, level, fmt.Sprintf(format, args...))
}

// run 账号任务主流程：登录 → （可选）短信绑定 → 连接云电脑 → 启动保活
func (r *runner) run(ctx context.Context) {
	log := func(level, format string, args ...interface{}) {
		r.log("", level, format, args...)
	}

	password, err := store.AccountPassword(&r.acct)
	if err != nil {
		r.setError("读取账号密码失败: " + err.Error())
		return
	}

	api := ctyun.NewClient(r.acct.DeviceCode)
	log("info", "开始登录")
	if !api.Login(ctx, r.acct.Username, password, log) {
		if ctx.Err() != nil {
			return
		}
		r.setError("登录失败，请检查账号密码后重试")
		return
	}
	log("ok", "登录成功")

	if !api.LoginInfo.BondedDevice {
		if !r.bindDeviceFlow(ctx, api, log) {
			return
		}
	}

	r.set(func(s *AccountStatus) { s.Status = StatusRunning; s.Message = "正在获取云电脑列表"; s.Desktops = nil })
	desktops, err := api.ListDesktops(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		r.setError("获取云电脑列表失败: " + err.Error())
		return
	}
	if len(desktops) == 0 {
		r.setError("该账号下没有云电脑")
		return
	}

	var active []activeDesktop
	for _, d := range desktops {
		if d.UseStatusText != "运行中" {
			log("warn", "[%s] 云电脑状态「%s」，未开机（正在开机，可稍后点击重试）", d.DesktopCode, d.UseStatusText)
		}
		info, msg, err := api.Connect(ctx, d.DesktopID)
		if err != nil {
			log("error", "[%s] 连接失败: %v", d.DesktopCode, err)
			continue
		}
		if info == nil {
			log("error", "[%s] 连接失败: %s", d.DesktopCode, msg)
			continue
		}
		active = append(active, activeDesktop{desktop: d, info: *info})
	}
	if len(active) == 0 {
		r.setError("没有可保活的云电脑")
		return
	}

	kaMin, kaMax := store.KeepAlive()
	dss := make([]DesktopStatus, 0, len(active))
	for _, ad := range active {
		dss = append(dss, DesktopStatus{
			Code: ad.desktop.DesktopCode, Name: ad.desktop.DesktopName, Status: "keepalive",
		})
	}
	r.set(func(s *AccountStatus) {
		s.Status = StatusRunning
		if kaMin == kaMax {
			s.Message = fmt.Sprintf("保活中（每 %d 秒重连）", kaMin)
		} else {
			s.Message = fmt.Sprintf("保活中（每 %d~%d 秒随机重连）", kaMin, kaMax)
		}
		s.Desktops = dss
	})

	var wg sync.WaitGroup
	for _, ad := range active {
		wg.Add(1)
		go func(ad activeDesktop) {
			defer wg.Done()
			r.keepAliveWorker(ctx, api, ad, kaMin, kaMax, log)
		}(ad)
	}
	wg.Wait()
	r.set(func(s *AccountStatus) {
		if s.Status != StatusError {
			s.Status = StatusStopped
			s.Message = "已停止"
		}
	})
}

// bindDeviceFlow 设备绑定流程：发送短信 → 等待网页输入验证码 → 绑定，支持多次尝试
func (r *runner) bindDeviceFlow(ctx context.Context, api *ctyun.Client, log ctyun.LogFunc) bool {
	log("info", "当前设备未绑定，需要短信验证码")
	for attempt := 1; attempt <= maxBindAttempts; attempt++ {
		r.set(func(s *AccountStatus) {
			s.Status = StatusAwaitingSMS
			s.Message = "正在发送短信验证码"
		})
		r.mgr.mu.Lock()
		r.api = api
		r.mgr.mu.Unlock()
		log("info", "发送短信验证码...")
		if !api.SendSMSCode(ctx, r.acct.Username, log) {
			if ctx.Err() != nil {
				return false
			}
			r.setError("短信验证码发送失败，请点击重试")
			return false
		}
		r.set(func(s *AccountStatus) { s.Status = StatusAwaitingSMS; s.Message = "短信已发送，请输入验证码" })
		log("info", "短信验证码已发送，等待输入（5 分钟内有效）")

		var code string
		select {
		case code = <-r.smsCh:
		case <-ctx.Done():
			return false
		case <-time.After(smsWaitTimeout):
			r.setError("等待验证码超时，请点击重试")
			return false
		}
		ok, msg := api.BindDevice(ctx, code)
		if ok {
			log("ok", "设备绑定成功")
			r.mgr.mu.Lock()
			r.api = nil
			r.mgr.mu.Unlock()
			return true
		}
		log("warn", "绑定失败: %s", msg)
		if attempt == maxBindAttempts {
			r.setError("绑定失败次数过多: " + msg)
			return false
		}
	}
	return false
}

// ============================================================
// WebSocket 保活（移植自原版 KeepAliveWorkerWithForcedReset + ReceiveLoop）
// ============================================================

type activeDesktop struct {
	desktop ctyun.Desktop
	info    ctyun.DesktopInfo
}

func (r *runner) keepAliveWorker(ctx context.Context, api *ctyun.Client, ad activeDesktop, keepAliveMin, keepAliveMax int, log ctyun.LogFunc) {
	label := ad.desktop.DesktopCode
	initialPayload, _ := base64.StdEncoding.DecodeString(initialPayloadB64)
	uri := fmt.Sprintf("wss://%s/clinkProxy/%s/MAIN", ad.info.ClinkLvsOutHost, ad.desktop.DesktopID)

	dialer := &websocket.Dialer{
		Subprotocols:     []string{"binary"},
		HandshakeTimeout: 20 * time.Second,
	}
	header := http.Header{"Origin": []string{"https://pc.ctyun.cn"}}

	for {
		if ctx.Err() != nil {
			return
		}
		log("info", "[%s] === 新周期开始，尝试连接 ===", label)
		conn, _, err := dialer.DialContext(ctx, uri, header)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log("error", "[%s] WebSocket 连接失败: %v", label, err)
			if !sleepCtx(ctx, 5*time.Second) {
				return
			}
			continue
		}
		// 每个周期在区间内随机取一个保持时长，避免固定周期的机械特征
		cycle := randRange(keepAliveMin, keepAliveMax)
		cycleErr := r.wsSession(ctx, conn, api, ad, initialPayload, cycle, keepAliveMin, keepAliveMax, log)
		_ = conn.Close()
		if ctx.Err() != nil {
			return
		}
		if cycleErr != nil {
			log("error", "[%s] 异常: %v", label, cycleErr)
			if !sleepCtx(ctx, 5*time.Second) {
				return
			}
		} else {
			log("info", "[%s] 周期时间到，准备重连...", label)
		}
	}
}

// randRange 在 [min, max] 闭区间内取随机整数
func randRange(min, max int) int {
	if max <= min {
		return min
	}
	return min + rand.Intn(max-min+1)
}

// wsSession 单个保活周期：建连 → 控制消息 → 收发循环，周期到后返回
// cycleSeconds 为本周期随机抽取的保持时长
func (r *runner) wsSession(ctx context.Context, conn *websocket.Conn, api *ctyun.Client, ad activeDesktop, initialPayload []byte, cycleSeconds, keepAliveMin, keepAliveMax int, log ctyun.LogFunc) error {
	label := ad.desktop.DesktopCode

	// ConnecMessage 控制消息
	hostParts := strings.SplitN(ad.info.ClinkLvsOutHost, ":", 2)
	port := "443"
	if len(hostParts) > 1 {
		port = hostParts[1]
	}
	msg := ctyun.ConnecMessage{
		Type: 1, SSL: 1,
		Host: hostParts[0], Port: port,
		CA: ad.info.CaCert, Cert: ad.info.ClientCert, Key: ad.info.ClientKey,
		ServerName: ad.info.Host + ":" + ad.info.Port,
		OQS:        0,
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if err := conn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		return err
	}
	select {
	case <-time.After(500 * time.Millisecond):
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, initialPayload); err != nil {
		return err
	}
	if keepAliveMin == keepAliveMax {
		log("ok", "[%s] 连接已就绪，保持 %d 秒...", label, cycleSeconds)
	} else {
		log("ok", "[%s] 连接已就绪，本次随机保持 %d 秒（区间 %d~%d）...", label, cycleSeconds, keepAliveMin, keepAliveMax)
	}

	r.set(func(s *AccountStatus) {
		for i := range s.Desktops {
			if s.Desktops[i].Code == label {
				s.Desktops[i].LastConnect = time.Now().Format("15:04:05")
			}
		}
	})

	// 周期到点强制重连：读超时 = 本周期随机时长
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(cycleSeconds) * time.Second))

	encryptor := ctyun.NewEncryptor()
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil // 周期结束，正常重连
			}
			return err
		}
		if len(data) == 0 {
			continue
		}
		// "REDQ" 开头（hex 52454451）：保活校验，加密响应
		if len(data) >= 4 && string(data[:4]) == "REDQ" {
			log("ok", "[%s] -> 收到保活校验", label)
			resp := encryptor.Execute(data)
			if resp == nil {
				log("warn", "[%s] 保活校验报文异常，已忽略", label)
				continue
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, resp); err != nil {
				return err
			}
			log("ok", "[%s] -> 发送保活响应成功", label)
			continue
		}
		// type 103 → 回复 type 118 用户信息
		for _, si := range ctyun.ParseSendInfos(data) {
			if si.Type == 103 {
				payload := []byte(fmt.Sprintf(`{"type":1,"userName":"%s","userInfo":"","userId":%d}`,
					api.LoginInfo.UserName, api.LoginInfo.UserID))
				resp := (&ctyun.SendInfo{Type: 118, Data: payload}).ToBuffer(true)
				if err := conn.WriteMessage(websocket.BinaryMessage, resp); err != nil {
					return err
				}
			}
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}
