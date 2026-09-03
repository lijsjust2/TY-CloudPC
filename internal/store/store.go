// Package store 数据持久化：面板用户、天翼账号（密码加密存储）、全局设置
package store

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"ctyun-panel/internal/config"
	"ctyun-panel/internal/cryptoutil"
)

var storeFile = filepath.Join(config.DataDir, "store.json")

// Settings 用户设置：推送渠道（Bark/PushPlus）与 2FA 二次验证
type Settings struct {
	BarkURL       string `json:"bark_url,omitempty"`
	BarkKey       string `json:"bark_key,omitempty"`
	PushplusToken string `json:"pushplus_token,omitempty"`
	TwoFAEnabled  bool   `json:"two_fa_enabled,omitempty"`
	TwoFAChannel  string `json:"two_fa_channel,omitempty"` // bark / pushplus
}

type User struct {
	ID            int      `json:"id"`
	Username      string   `json:"username"`
	PasswordHash  string   `json:"password_hash"`
	PasswordEpoch int      `json:"password_epoch,omitempty"` // 改密码时递增，使旧会话 Cookie 失效
	Settings      Settings `json:"settings,omitempty"`
}

type Account struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Username    string `json:"username"`
	PasswordEnc string `json:"password_enc"` // AES-256-GCM 加密后的天翼密码
	DeviceCode  string `json:"device_code"`
	CreatedAt   string `json:"created_at,omitempty"`
}

type dataFile struct {
	Users         []User    `json:"users"`
	Accounts      []Account `json:"accounts"`
	NextUserID    int       `json:"nextUserId"`
	NextAccountID int       `json:"nextAccountId"`
	// 旧版单值周期，仅读取迁移用；迁移完成后不再写入
	KeepAliveSeconds int `json:"keepAliveSeconds,omitempty"`
	// 保活重连随机区间 [KeepAliveMin, KeepAliveMax]（秒）
	KeepAliveMin int `json:"keepAliveMin"`
	KeepAliveMax int `json:"keepAliveMax"`
}

var (
	mu   sync.Mutex
	data dataFile
)

// Init 加载 store.json；支持 ADMIN_PASSWORD 环境变量首次自动创建 admin
func Init() {
	mu.Lock()
	defer mu.Unlock()
	if raw, err := os.ReadFile(storeFile); err == nil {
		if err := json.Unmarshal(raw, &data); err != nil {
			panic("store.json 解析失败: " + err.Error())
		}
	}
	if data.NextUserID == 0 {
		data.NextUserID = 1
	}
	if data.NextAccountID == 0 {
		data.NextAccountID = 1
	}
	// 旧版单值周期迁移为随机区间（min = max = 旧值）
	if data.KeepAliveMin <= 0 || data.KeepAliveMax <= 0 {
		legacy := data.KeepAliveSeconds
		if legacy < 10 {
			legacy = 60
		}
		data.KeepAliveMin, data.KeepAliveMax = legacy, legacy
	}
	clampKeepAlive(&data.KeepAliveMin, &data.KeepAliveMax)
	needSave := data.KeepAliveSeconds > 0
	data.KeepAliveSeconds = 0
	if needSave {
		saveLocked() // 迁移结果立即落盘
	}
	if len(data.Users) == 0 {
		if pw := os.Getenv("ADMIN_PASSWORD"); pw != "" {
			if hash, err := cryptoutil.HashPassword(pw); err == nil {
				data.Users = append(data.Users, User{
					ID: data.NextUserID, Username: "admin", PasswordHash: hash, PasswordEpoch: 1,
				})
				data.NextUserID++
				saveLocked()
			}
		}
	}
}

func saveLocked() {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return
	}
	tmp := storeFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, storeFile)
}

// ---- 面板用户 ----

func HasUser() bool {
	mu.Lock()
	defer mu.Unlock()
	return len(data.Users) > 0
}

// ListUsers 列出全部面板用户（含设置，用于登录页判断是否显示 2FA 输入框）
func ListUsers() []User {
	mu.Lock()
	defer mu.Unlock()
	out := make([]User, len(data.Users))
	copy(out, data.Users)
	return out
}

func CreateUser(username, hash string) bool {
	mu.Lock()
	defer mu.Unlock()
	for _, u := range data.Users {
		if u.Username == username {
			return false
		}
	}
	data.Users = append(data.Users, User{
		ID: data.NextUserID, Username: username, PasswordHash: hash, PasswordEpoch: 1,
	})
	data.NextUserID++
	saveLocked()
	return true
}

func FindUser(username string) *User {
	mu.Lock()
	defer mu.Unlock()
	for i := range data.Users {
		if data.Users[i].Username == username {
			u := data.Users[i]
			return &u
		}
	}
	return nil
}

func UpdateUserPassword(username, hash string) bool {
	mu.Lock()
	defer mu.Unlock()
	for i := range data.Users {
		if data.Users[i].Username == username {
			data.Users[i].PasswordHash = hash
			data.Users[i].PasswordEpoch++
			saveLocked()
			return true
		}
	}
	return false
}

// GetUserSettings 读取用户设置
func GetUserSettings(username string) Settings {
	mu.Lock()
	defer mu.Unlock()
	for i := range data.Users {
		if data.Users[i].Username == username {
			return data.Users[i].Settings
		}
	}
	return Settings{}
}

// UpdateUserSettings 原子更新用户设置
func UpdateUserSettings(username string, mutate func(*Settings)) {
	mu.Lock()
	defer mu.Unlock()
	for i := range data.Users {
		if data.Users[i].Username == username {
			mutate(&data.Users[i].Settings)
			saveLocked()
			return
		}
	}
}

// ---- 天翼账号 ----

func ListAccounts() []Account {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Account, len(data.Accounts))
	copy(out, data.Accounts)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func GetAccount(id int) *Account {
	mu.Lock()
	defer mu.Unlock()
	for i := range data.Accounts {
		if data.Accounts[i].ID == id {
			a := data.Accounts[i]
			return &a
		}
	}
	return nil
}

// AddAccount 新增天翼账号：密码加密存储；deviceCode 选填（迁移自原 C# 版部署时填入，
// 可免重新绑定设备），留空则自动生成 web_ + 32 位随机字符
func AddAccount(name, username, password, deviceCode string) (*Account, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, fmt.Errorf("账号和密码不能为空")
	}
	deviceCode = strings.TrimSpace(deviceCode)
	if deviceCode == "" {
		deviceCode = randomDeviceCode()
	} else if err := validateDeviceCode(deviceCode); err != nil {
		return nil, err
	}
	enc, err := cryptoutil.EncryptText(password)
	if err != nil {
		return nil, fmt.Errorf("密码加密失败: %w", err)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = username
	}
	mu.Lock()
	defer mu.Unlock()
	a := Account{
		ID:          data.NextAccountID,
		Name:        name,
		Username:    username,
		PasswordEnc: enc,
		DeviceCode:  deviceCode,
		CreatedAt:   time.Now().Format(time.RFC3339),
	}
	data.Accounts = append(data.Accounts, a)
	data.NextAccountID++
	saveLocked()
	return &a, nil
}

// validateDeviceCode 设备码格式校验：web_ 前缀 + 字母数字，总长 10 ~ 64
//（原版为 web_ + 32 位随机字符，放宽到 64 兼容历史部署）
func validateDeviceCode(code string) error {
	if len(code) < 10 || len(code) > 64 {
		return fmt.Errorf("设备码长度需为 10 ~ 64 个字符")
	}
	if !strings.HasPrefix(code, "web_") {
		return fmt.Errorf("设备码需以 web_ 开头")
	}
	for _, c := range code[4:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_') {
			return fmt.Errorf("设备码只能包含字母、数字和下划线")
		}
	}
	return nil
}

// UpdateAccount 更新账号信息；password 为空表示不修改密码（保留原设备码，无需重新绑定设备）
func UpdateAccount(id int, name, password string) (*Account, error) {
	mu.Lock()
	defer mu.Unlock()
	for i := range data.Accounts {
		if data.Accounts[i].ID != id {
			continue
		}
		if name = strings.TrimSpace(name); name != "" {
			data.Accounts[i].Name = name
		}
		if password != "" {
			enc, err := cryptoutil.EncryptText(password)
			if err != nil {
				return nil, fmt.Errorf("密码加密失败: %w", err)
			}
			data.Accounts[i].PasswordEnc = enc
		}
		saveLocked()
		a := data.Accounts[i]
		return &a, nil
	}
	return nil, fmt.Errorf("账号不存在")
}

func DeleteAccount(id int) bool {
	mu.Lock()
	defer mu.Unlock()
	for i := range data.Accounts {
		if data.Accounts[i].ID == id {
			data.Accounts = append(data.Accounts[:i], data.Accounts[i+1:]...)
			saveLocked()
			return true
		}
	}
	return false
}

// AccountPassword 解密账号密码（仅内部使用）
func AccountPassword(a *Account) (string, error) {
	return cryptoutil.DecryptText(a.PasswordEnc)
}

// ---- 全局设置 ----

// KeepAlive 返回保活重连随机区间（秒）
func KeepAlive() (min, max int) {
	mu.Lock()
	defer mu.Unlock()
	return data.KeepAliveMin, data.KeepAliveMax
}

// SetKeepAlive 设置保活重连随机区间（秒），自动钳制到 [10, 3600] 并交换颠倒的区间
func SetKeepAlive(min, max int) {
	mu.Lock()
	defer mu.Unlock()
	clampKeepAlive(&min, &max)
	data.KeepAliveMin, data.KeepAliveMax = min, max
	saveLocked()
}

// clampKeepAlive 区间钳制：下限 10、上限 3600，min > max 时交换
func clampKeepAlive(min, max *int) {
	if *min < 10 {
		*min = 10
	}
	if *max < 10 {
		*max = 10
	}
	if *min > 3600 {
		*min = 3600
	}
	if *max > 3600 {
		*max = 3600
	}
	if *min > *max {
		*min, *max = *max, *min
	}
}

// randomDeviceCode 生成 web_ 前缀 + 32 位随机字符的设备码（对齐原版格式）
func randomDeviceCode() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 32)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			b[i] = chars[i%len(chars)]
			continue
		}
		b[i] = chars[n.Int64()]
	}
	return "web_" + string(b)
}
