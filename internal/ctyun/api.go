// Package ctyun 天翼云电脑 API 客户端（移植自原 C# 版 CtYunApi.cs）
package ctyun

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"ctyun-panel/internal/config"
)

const (
	BaseURL    = "https://desk.ctyun.cn:8810"
	DeviceType = "60"
	Version    = "103020001"
)

// LogFunc 业务日志回调：level 取 info/ok/warn/error
type LogFunc func(level, format string, args ...interface{})

type Client struct {
	deviceCode string
	http       *http.Client
	LoginInfo  *LoginInfo
}

func NewClient(deviceCode string) *Client {
	return &Client{
		deviceCode: deviceCode,
		http:       &http.Client{Timeout: 60 * time.Second},
	}
}

// ---- 登录流程 ----

// Login 登录天翼云电脑：challenge + 图形验证码 OCR + 密码哈希，最多重试 3 次
func (c *Client) Login(ctx context.Context, userphone, password string, log LogFunc) bool {
	for i := 1; i <= 3; i++ {
		ch, err := c.genChallengeData(ctx)
		if err != nil {
			log("warn", "获取 challenge 失败: %v", err)
			continue
		}
		img, err := c.getLoginCaptcha(ctx, userphone)
		if err != nil {
			log("warn", "登录图形验证码获取失败: %v", err)
			continue
		}
		code, err := c.OCR(ctx, img, log)
		if err != nil || code == "" {
			continue
		}
		form := url.Values{}
		form.Set("userAccount", userphone)
		form.Set("password", sha256Hex(password+ch.ChallengeCode))
		form.Set("sha256Password", sha256Hex(sha256Hex(password)+ch.ChallengeCode))
		form.Set("challengeId", ch.ChallengeID)
		form.Set("captchaCode", code)
		c.addDeviceFields(form)
		var result ResultBase[LoginInfo]
		if err := c.postForm(ctx, BaseURL+"/api/auth/client/login", form, &result); err != nil {
			log("warn", "登录请求失败: %v", err)
			continue
		}
		if result.OK() {
			info := result.Data
			c.LoginInfo = &info
			return true
		}
		log("warn", "第 %d 次登录失败: %s", i, result.Msg)
		if result.Msg == "用户名或密码错误" {
			return false
		}
	}
	return false
}

// SendSMSCode 发送设备绑定短信验证码（带图形验证码 OCR），最多重试 3 次
func (c *Client) SendSMSCode(ctx context.Context, userphone string, log LogFunc) bool {
	for i := 1; i <= 3; i++ {
		img, err := c.getSmsCodeCaptcha(ctx)
		if err != nil {
			log("warn", "短信图形验证码获取失败: %v", err)
			continue
		}
		code, err := c.OCR(ctx, img, log)
		if err != nil || code == "" {
			continue
		}
		u := BaseURL + "/api/cdserv/client/device/getSmsCode?mobilePhone=" +
			url.QueryEscape(userphone) + "&captchaCode=" + url.QueryEscape(code)
		var result ResultBase[bool]
		if err := c.getJSON(ctx, u, &result); err != nil {
			log("warn", "发送短信请求失败: %v", err)
			continue
		}
		if result.OK() {
			return true
		}
		log("warn", "第 %d 次发送短信失败: %s", i, result.Msg)
	}
	return false
}

// BindDevice 用短信验证码绑定当前设备码
func (c *Client) BindDevice(ctx context.Context, verificationCode string) (bool, string) {
	u := BaseURL + "/api/cdserv/client/device/binding?verificationCode=" + url.QueryEscape(verificationCode) +
		"&deviceName=" + url.QueryEscape("Chrome浏览器") +
		"&deviceCode=" + url.QueryEscape(c.deviceCode) +
		"&deviceModel=" + url.QueryEscape("Windows NT 10.0; Win64; x64") +
		"&sysVersion=" + url.QueryEscape("Windows NT 10.0; Win64; x64") +
		"&appVersion=3.2.0&hostName=pc.ctyun.cn&deviceInfo=Win32"
	var result ResultBase[bool]
	req, err := c.newRequest(ctx, http.MethodPost, u, nil, "")
	if err != nil {
		return false, err.Error()
	}
	if err := c.doJSON(req, &result); err != nil {
		return false, err.Error()
	}
	if result.OK() {
		return true, ""
	}
	return false, result.Msg
}

// ListDesktops 获取云电脑列表
func (c *Client) ListDesktops(ctx context.Context) ([]Desktop, error) {
	body := `{"getCnt":20,"desktopTypes":["1","2001","2002","2003"],"sortType":"createTimeV1"}`
	var result ResultBase[clientInfoData]
	if err := c.postJSON(ctx, BaseURL+"/api/desktop/client/pageDesktop", body, &result); err != nil {
		return nil, err
	}
	if !result.OK() {
		return nil, fmt.Errorf("%s", result.Msg)
	}
	return result.Data.DesktopList, nil
}

// Connect 申请连接云电脑，返回连接信息
func (c *Client) Connect(ctx context.Context, desktopID string) (*DesktopInfo, string, error) {
	form := url.Values{}
	form.Set("objId", desktopID)
	form.Set("objType", "0")
	form.Set("osType", "15")
	form.Set("deviceId", DeviceType)
	form.Set("vdCommand", "")
	form.Set("ipAddress", "")
	form.Set("macAddress", "")
	c.addDeviceFields(form)
	var result ResultBase[ConnectInfo]
	if err := c.postForm(ctx, BaseURL+"/api/desktop/client/connect", form, &result); err != nil {
		return nil, "", err
	}
	if !result.OK() {
		return nil, result.Msg, nil
	}
	return &result.Data.DesktopInfo, "", nil
}

// ---- 私有辅助 ----

func (c *Client) genChallengeData(ctx context.Context) (*ChallengeData, error) {
	var result ResultBase[ChallengeData]
	if err := c.postJSON(ctx, BaseURL+"/api/auth/client/genChallengeData", "{}", &result); err != nil {
		return nil, err
	}
	if !result.OK() {
		return nil, fmt.Errorf("%s", result.Msg)
	}
	return &result.Data, nil
}

// getLoginCaptcha 登录图形验证码（登录前无签名，对齐原版）
func (c *Client) getLoginCaptcha(ctx context.Context, userphone string) ([]byte, error) {
	u := BaseURL + "/api/auth/client/captcha?height=36&width=85&userInfo=" +
		url.QueryEscape(userphone) + "&mode=auto&_t=" + strconv.FormatInt(time.Now().UnixMilli(), 10)
	return c.getBytes(ctx, u, false)
}

// getSmsCodeCaptcha 短信验证码流程的图形验证码（带签名）
func (c *Client) getSmsCodeCaptcha(ctx context.Context) ([]byte, error) {
	u := BaseURL + "/api/auth/client/validateCode/captcha?width=120&height=40&_t=" +
		strconv.FormatInt(time.Now().UnixMilli(), 10)
	return c.getBytes(ctx, u, true)
}

// OCR 调用识别服务识别图形验证码
func (c *Client) OCR(ctx context.Context, img []byte, log LogFunc) (string, error) {
	log("info", "正在识别图形验证码...")
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	fw, err := w.CreateFormField("image")
	if err != nil {
		return "", err
	}
	if _, err := fw.Write([]byte(base64.StdEncoding.EncodeToString(img))); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	req, err := c.newRequest(ctx, http.MethodPost, config.OCRURL, &b, w.FormDataContentType())
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("识别服务返回 %d", resp.StatusCode)
	}
	var out struct {
		Data string `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	log("ok", "识别结果：%s", out.Data)
	return out.Data, nil
}

func (c *Client) addDeviceFields(form url.Values) {
	form.Set("deviceCode", c.deviceCode)
	form.Set("deviceName", "Chrome浏览器")
	form.Set("deviceType", DeviceType)
	form.Set("deviceModel", "Windows NT 10.0; Win64; x64")
	form.Set("appVersion", "3.2.0")
	form.Set("sysVersion", "Windows NT 10.0; Win64; x64")
	form.Set("clientVersion", Version)
}

// applySignature 已登录请求的签名头（对齐原版 ApplySignature）
func (c *Client) applySignature(req *http.Request) {
	if c.LoginInfo == nil {
		return
	}
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	req.Header.Set("ctg-userid", strconv.Itoa(c.LoginInfo.UserID))
	req.Header.Set("ctg-tenantid", strconv.Itoa(c.LoginInfo.TenantID))
	req.Header.Set("ctg-timestamp", ts)
	req.Header.Set("ctg-requestid", ts)
	str := DeviceType + ts + strconv.Itoa(c.LoginInfo.TenantID) + ts +
		strconv.Itoa(c.LoginInfo.UserID) + Version + c.LoginInfo.SecretKey
	req.Header.Set("ctg-signaturestr", md5Hex(str))
}

func (c *Client) newRequest(ctx context.Context, method, rawURL string, body io.Reader, contentType string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	h := req.Header
	h.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	h.Set("ctg-devicetype", DeviceType)
	h.Set("ctg-version", Version)
	h.Set("ctg-devicecode", c.deviceCode)
	h.Set("referer", "https://pc.ctyun.cn/")
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	c.applySignature(req)
	return req, nil
}

func (c *Client) doJSON(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) getJSON(ctx context.Context, rawURL string, out any) error {
	req, err := c.newRequest(ctx, http.MethodGet, rawURL, nil, "")
	if err != nil {
		return err
	}
	return c.doJSON(req, out)
}

func (c *Client) getBytes(ctx context.Context, rawURL string, signed bool) ([]byte, error) {
	req, err := c.newRequest(ctx, http.MethodGet, rawURL, nil, "")
	if err != nil {
		return nil, err
	}
	_ = signed // 签名头已由 applySignature 按登录态统一处理
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func (c *Client) postForm(ctx context.Context, rawURL string, form url.Values, out any) error {
	req, err := c.newRequest(ctx, http.MethodPost, rawURL,
		bytes.NewReader([]byte(form.Encode())),
		"application/x-www-form-urlencoded")
	if err != nil {
		return err
	}
	return c.doJSON(req, out)
}

func (c *Client) postJSON(ctx context.Context, rawURL, body string, out any) error {
	req, err := c.newRequest(ctx, http.MethodPost, rawURL,
		bytes.NewReader([]byte(body)), "application/json")
	if err != nil {
		return err
	}
	return c.doJSON(req, out)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func md5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}
