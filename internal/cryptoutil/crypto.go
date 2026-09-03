// Package cryptoutil 密码哈希（scrypt）与敏感数据加密（AES-256-GCM）
package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/scrypt"

	"ctyun-panel/internal/config"
)

var aesKey []byte

// getKey 天翼账号密码的加密密钥：首次启动自动生成，保存在 data/secret.key（0600）
func getKey() ([]byte, error) {
	if aesKey != nil {
		return aesKey, nil
	}
	if b, err := os.ReadFile(config.SecretFile); err == nil && len(b) == 32 {
		aesKey = b
		return aesKey, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(config.SecretFile, b, 0o600); err != nil {
		return nil, err
	}
	aesKey = b
	return aesKey, nil
}

// ---- 面板登录密码（scrypt，格式 salt:hash 十六进制） ----

func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 64)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x:%x", salt, hash), nil
}

func VerifyPassword(password, stored string) bool {
	parts := strings.SplitN(stored, ":", 2)
	if len(parts) != 2 {
		// 格式无效时也执行一次 scrypt，消除响应时序差
		_, _ = scrypt.Key([]byte(password), make([]byte, 16), 16384, 8, 1, 64)
		return false
	}
	salt, err1 := hexDecode(parts[0])
	want, err2 := hexDecode(parts[1])
	if err1 != nil || err2 != nil {
		_, _ = scrypt.Key([]byte(password), make([]byte, 16), 16384, 8, 1, 64)
		return false
	}
	got, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 64)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func hexDecode(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi := hexVal(s[i*2])
		lo := hexVal(s[i*2+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("非法十六进制字符")
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out, nil
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// DummyHash 启动时预计算的哑哈希：用户不存在时用它跑一次完整的
// VerifyPassword，使响应时间与真实用户一致，防止时序枚举用户名。
var DummyHash = func() string {
	h, _ := HashPassword("dummy-password-for-timing")
	return h
}()

// ---- 天翼账号密码存储（AES-256-GCM，格式 base64(iv).base64(tag).base64(enc)） ----

func EncryptText(text string) (string, error) {
	key, err := getKey()
	if err != nil {
		return "", err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	enc := gcm.Seal(nil, iv, []byte(text), nil)
	tag, data := enc[len(enc)-gcm.Overhead():], enc[:len(enc)-gcm.Overhead()]
	b64 := base64.StdEncoding.EncodeToString
	return b64(iv) + "." + b64(tag) + "." + b64(data), nil
}

func DecryptText(stored string) (string, error) {
	key, err := getKey()
	if err != nil {
		return "", err
	}
	parts := strings.Split(stored, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("密文格式错误")
	}
	dec := base64.StdEncoding.DecodeString
	iv, err1 := dec(parts[0])
	tag, err2 := dec(parts[1])
	data, err3 := dec(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return "", fmt.Errorf("密文 base64 解码失败")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, iv, append(data, tag...), nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
