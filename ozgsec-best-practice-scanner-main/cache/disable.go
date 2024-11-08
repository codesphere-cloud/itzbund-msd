package cache

import (
	"context"
	"time"
)

type disableCache struct{}

func (d disableCache) Get(ctx context.Context, key string) (any, error) {
	return nil, NewCacheMissError(key)
}

func (d disableCache) Set(ctx context.Context, key string, value any, expires time.Duration) error {
	return nil
}

func (d disableCache) Delete(ctx context.Context, key string) error {
	return nil
}

func NewDisableCache() disableCache {
	return disableCache{}
}
