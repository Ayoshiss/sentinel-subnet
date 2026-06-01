package ratelimit

import (
	"sync"
	"time"
)

type window struct {
	count int
	reset time.Time
}

var (
	mu      sync.Mutex
	windows = make(map[string]*window)
)

// Allow checks if the key is within its requests-per-minute quota.
// Returns (allowed, remaining, resetAt).
func Allow(keyID string, limitRPM int) (bool, int, time.Time) {
	if limitRPM <= 0 {
		limitRPM = 60 // default
	}

	mu.Lock()
	defer mu.Unlock()

	now := time.Now()
	w, ok := windows[keyID]

	if !ok || now.After(w.reset) {
		// New window
		w = &window{
			count: 1,
			reset: now.Add(time.Minute),
		}
		windows[keyID] = w
		return true, limitRPM - 1, w.reset
	}

	if w.count >= limitRPM {
		return false, 0, w.reset
	}

	w.count++
	return true, limitRPM - w.count, w.reset
}

// Cleanup removes expired windows to prevent memory leaks.
// Call this periodically (e.g. every minute).
func Cleanup() {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now()
	for k, w := range windows {
		if now.After(w.reset) {
			delete(windows, k)
		}
	}
}
