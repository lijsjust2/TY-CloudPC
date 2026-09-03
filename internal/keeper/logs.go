// Package keeper 账号保活管理器：登录、设备绑定（短信验证码）、WebSocket 保活
package keeper

import (
	"sync"
	"time"
)

// LogEntry 单条运行日志（内存环形缓冲，不落盘）
type LogEntry struct {
	Seq       int    `json:"seq"`
	Time      string `json:"time"`
	Account   string `json:"account"`
	Desktop   string `json:"desktop,omitempty"`
	Level     string `json:"level"` // info / ok / warn / error
	Message   string `json:"message"`
	accountID int
}

// LogBuffer 线程安全的环形日志缓冲
type LogBuffer struct {
	mu      sync.Mutex
	entries []LogEntry
	seq     int
	max     int
}

func NewLogBuffer(max int) *LogBuffer {
	return &LogBuffer{max: max}
}

func (l *LogBuffer) Add(accountID int, account, desktop, level, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	l.entries = append(l.entries, LogEntry{
		Seq:       l.seq,
		Time:      time.Now().Format("15:04:05.000"),
		Account:   account,
		Desktop:   desktop,
		Level:     level,
		Message:   msg,
		accountID: accountID,
	})
	if len(l.entries) > l.max {
		l.entries = l.entries[len(l.entries)-l.max:]
	}
}

// After 返回序号大于 seq 的日志；accountID > 0 时只返回该账号的日志
func (l *LogBuffer) After(seq, accountID int) []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []LogEntry
	for _, e := range l.entries {
		if e.Seq <= seq {
			continue
		}
		if accountID > 0 && e.accountID != accountID {
			continue
		}
		out = append(out, e)
	}
	return out
}
