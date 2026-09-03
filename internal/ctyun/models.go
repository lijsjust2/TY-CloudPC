// Package ctyun 天翼云电脑 API 数据模型（对齐原 C# 版 Models/）
package ctyun

// ResultBase 通用响应结构，code == 0 表示成功
type ResultBase[T any] struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data T      `json:"data"`
}

func (r ResultBase[T]) OK() bool { return r.Code == 0 }

type LoginInfo struct {
	BondedDevice bool   `json:"bondedDevice"`
	SecretKey    string `json:"secretKey"`
	UserID       int    `json:"userId"`
	TenantID     int    `json:"tenantId"`
	UserName     string `json:"userName"`
}

type ChallengeData struct {
	ChallengeID   string `json:"challengeId"`
	ChallengeCode string `json:"challengeCode"`
}

type Desktop struct {
	DesktopID     string `json:"desktopId"`
	DesktopName   string `json:"desktopName"`
	DesktopCode   string `json:"desktopCode"`
	UseStatusText string `json:"useStatusText"`
}

type DesktopInfo struct {
	DesktopID           int    `json:"desktopId"`
	Host                string `json:"host"`
	Port                string `json:"port"`
	ClinkLvsOutHost     string `json:"clinkLvsOutHost"`
	CaCert              string `json:"caCert"`
	ClientCert          string `json:"clientCert"`
	ClientKey           string `json:"clientKey"`
	Token               string `json:"token"`
	TenantMemberAccount string `json:"tenantMemberAccount"`
}

type ConnectInfo struct {
	DesktopInfo DesktopInfo `json:"desktopInfo"`
}

type clientInfoData struct {
	DesktopList []Desktop `json:"desktopList"`
}

// ConnecMessage WebSocket 建连后发送的 JSON 控制消息
type ConnecMessage struct {
	Type       int    `json:"type"`
	SSL        int    `json:"ssl"`
	Host       string `json:"host"`
	Port       string `json:"port"`
	CA         string `json:"ca"`
	Cert       string `json:"cert"`
	Key        string `json:"key"`
	ServerName string `json:"servername"`
	OQS        int    `json:"oqs"`
}
