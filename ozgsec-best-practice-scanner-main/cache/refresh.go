package cache

import (
	"context"
	"time"
)

type refreshCache[T any] struct {
	cacher[T]
}

// will always return a cache miss but will call the underlying cache for Set and Delete
// this is useful for refreshing the cache
func NewRefreshCache[T any](cache cacher[T]) refreshCache[T] {
	return refreshCache[T]{cacher: cache}
}

func (r refreshCache[T]) Get(ctx context.Context, key string) (T, error) {
	t := new(T)
	return *t, NewCacheMissError(key)
}

func (r refreshCache[T]) Set(ctx context.Context, key string, value T, expires time.Duration) error {
	return r.cacher.Set(ctx, key, value, expires)
}

func (r refreshCache[T]) Delete(ctx context.Context, key string) error {
	return r.cacher.Delete(ctx, key)
}
