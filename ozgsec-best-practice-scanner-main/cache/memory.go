package cache

import (
	"context"
	"sync"
	"time"
)

type memoryCacheEntry[T any] struct {
	value   T
	expires time.Time
}

type memory[T any] struct {
	data map[string]memoryCacheEntry[T]
	mut  *sync.Mutex
}

func NewMemoryCache[T any]() memory[T] {
	return memory[T]{
		data: make(map[string]memoryCacheEntry[T]),
		mut:  &sync.Mutex{},
	}
}

func (c memory[T]) Get(ctx context.Context, key string) (T, error) {
	c.mut.Lock()
	defer c.mut.Unlock()

	if entry, ok := c.data[key]; !ok {
		return entry.value, NewCacheMissError(key)
	}

	entry := c.data[key]

	if entry.expires.Before(time.Now()) {
		delete(c.data, key)
		return entry.value, NewCacheMissError(key)
	}

	return entry.value, nil
}

func (c memory[T]) Set(ctx context.Context, key string, value T, expires time.Duration) error {
	c.mut.Lock()
	defer c.mut.Unlock()

	c.data[key] = memoryCacheEntry[T]{
		value:   value,
		expires: time.Now().Add(expires),
	}
	return nil
}

func (c memory[T]) Delete(ctx context.Context, key string) error {
	delete(c.data, key)
	return nil
}
