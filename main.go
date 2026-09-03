// 天翼云电脑保活面板（Go 版）入口：
// 初始化存储 → 启动全部保活任务 → 启动 HTTP 服务
package main

import (
	"log"
	"net/http"
	"time"

	"ctyun-panel/internal/config"
	"ctyun-panel/internal/keeper"
	"ctyun-panel/internal/store"
	"ctyun-panel/internal/web"
)

func main() {
	store.Init()
	m := keeper.NewManager()
	m.StartAll()
	web.SetManager(m)

	srv := &http.Server{
		Addr:              ":" + config.Port,
		Handler:           web.New(m),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("TY CloudPC 面板已启动，监听端口 %s，数据目录 %s", config.Port, config.DataDir)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP 服务启动失败: %v", err)
	}
}
