// Package session 无状态签名 Cookie 会话：HMAC-SHA256 签名，改密码后旧会话吊销
package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"ctyun-panel/internal/config"
)

const cookieName = "ctyunpanel_session"
const maxAge = 24 * time.Hour

// payload = username|userId|epoch|expiryUnix，epoch 为签发时的密码版本号
// （改密码后旧 Cookie 的 epoch 落后于当前值，强制下线）。
// 密钥持久化在 data/session.secret，重启后登录态不失效。

func sign(payload string) string {
	mac := hmac.New(sha256.New, []byte(config.SessionSecret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func createValue(username string, userID, epoch int) string {
	payload := username + "|" + strconv.Itoa(userID) + "|" + strconv.Itoa(epoch) + "|" + strconv.FormatInt(time.Now().Add(maxAge).Unix(), 10)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sign(payload)
}

func parseValue(v string) (username string, userID, epoch int, ok bool) {
	parts := strings.SplitN(v, ".", 2)
	if len(parts) != 2 {
		return "", 0, 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", 0, 0, false
	}
	payload := string(raw)
	if !hmac.Equal([]byte(sign(payload)), []byte(parts[1])) {
		return "", 0, 0, false
	}
	fields := strings.Split(payload, "|")
	if len(fields) != 4 {
		return "", 0, 0, false
	}
	uid, err := strconv.Atoi(fields[1])
	if err != nil {
		return "", 0, 0, false
	}
	ep, err := strconv.Atoi(fields[2])
	if err != nil {
		return "", 0, 0, false
	}
	exp, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", 0, 0, false
	}
	return fields[0], uid, ep, true
}

// Login 写入登录会话（签发全新 Cookie，防会话固定攻击）
func Login(w http.ResponseWriter, username string, userID, epoch int) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    createValue(username, userID, epoch),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   os.Getenv("COOKIE_SECURE") == "true",
		MaxAge:   int(maxAge.Seconds()),
	})
}

func Logout(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   os.Getenv("COOKIE_SECURE") == "true",
		MaxAge:   -1,
	})
}

// Current 从请求解析当前登录用户（返回密码版本号 epoch，供会话吊销比对）
func Current(r *http.Request) (username string, userID, epoch int, ok bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", 0, 0, false
	}
	return parseValue(c.Value)
}
