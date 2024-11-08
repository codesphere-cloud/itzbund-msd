package concurrency

import (
	"log/slog"
	"time"
)

func LogLongRunning[T any](name string, fn func() T) func() T {
	return func() T {
		start := time.Now()
		val := fn()
		duration := time.Since(start)
		if duration > 5*time.Second {
			slog.Warn("long running", "name", name, "duration", duration.Milliseconds())
		}
		return val
	}

}
func WrapInChan[T any](fn func() T) <-chan T {
	c := make(chan T)
	go func() {
		c <- fn()
		close(c)
	}()
	return c
}

// might block forever if the channels are not closed
func Collect[T any](results ...<-chan T) []T {
	out := make([]T, 0)
	for _, r := range results {
		for v := range r {
			out = append(out, v)
		}
	}
	return out
}

// combines channel wrapping and collection
func All[T any](fn ...(func() T)) []T {
	ch := make([]<-chan T, len(fn))
	for i, f := range fn {
		ch[i] = WrapInChan(f)
	}

	return Collect(ch...)
}
