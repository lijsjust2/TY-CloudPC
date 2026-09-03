// Package ratelimit 进程内滑动窗口限流（用于登录等敏感操作）
package ratelimit

import (
	"sync"
	"time"
)

var (
	mu   sync.Mutex
	hits = map[string][]time.Time{}
)

// Limited 判断 key 在 window 时间窗内是否超过 max 次；未超限时记录本次并返回 false
func Limited(key string, max int, window time.Duration) bool {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now()
	list := hits[key]
	kept := list[:0]
	for _, t := range list {
		if now.Sub(t) <= window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= max {
		hits[key] = kept
		return true
	}
	hits[key] = append(kept, now)
	// 顺手清理过期 key，防止 map 无限增长
	if len(hits) > 10000 {
		for k, v := range hits {
			if len(v) == 0 {
				delete(hits, k)
			}
		}
	}
	return false
}

// Clear 清除 key 的计数（登录成功后调用，避免误伤正常用户）
func Clear(key string) {
	mu.Lock()
	defer mu.Unlock()
	delete(hits, key)
}
