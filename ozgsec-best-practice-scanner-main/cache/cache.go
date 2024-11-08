package cache

import (
	"context"
	"time"
)

type cacheMissError struct {
	Key string
}
type cacher[T any] interface {
	// Get returns the value for the given key.
	Get(ctx context.Context, key string) (T, error)
	// Set sets the value for the given key.
	Set(ctx context.Context, key string, value T, expires time.Duration) error
	// Delete deletes the value for the given key.
	Delete(ctx context.Context, key string) error
}

func (c cacheMissError) Error() string {
	return "cache miss for key: " + c.Key
}

func NewCacheMissError(key string) cacheMissError {
	return cacheMissError{Key: key}
}
