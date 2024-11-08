package concurrency

import (
	"sync"
	"time"
)

func NewDebouncer(after time.Duration) *debouncer {
	d := &debouncer{after: after, timers: make(map[string]*time.Timer)}
	return d
}

type debouncer struct {
	mu     sync.Mutex
	after  time.Duration
	timers map[string]*time.Timer
}

func (d *debouncer) Do(key string, f func()) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if timer, ok := d.timers[key]; ok {
		timer.Stop()
	}
	d.timers[key] = time.AfterFunc(d.after, func() {
		// delete the timer
		d.mu.Lock()
		delete(d.timers, key)
		d.mu.Unlock()
		f()
	})
}
