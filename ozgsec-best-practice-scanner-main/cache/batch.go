package cache

import (
	"context"
	"reflect"
	"sync"
	"time"
)

type batchCacheEntry struct {
	value   interface{}
	expires time.Duration
}

type batchCache struct {
	wrappedCache cacher[interface{}]
	memory       map[string]batchCacheEntry
	mut          *sync.Mutex
}

func NewBatchCache(wrappedCache cacher[any]) batchCache {
	return batchCache{wrappedCache: wrappedCache, memory: make(map[string]batchCacheEntry), mut: &sync.Mutex{}}
}

func (b batchCache) Get(ctx context.Context, key string) (interface{}, error) {
	return b.wrappedCache.Get(ctx, key)
}

func (b batchCache) Set(ctx context.Context, key string, value interface{}, expires time.Duration) error {
	// if the value does not exist just write it
	b.mut.Lock()
	defer b.mut.Unlock()

	if _, ok := b.memory[key]; !ok {
		b.memory[key] = batchCacheEntry{
			value:   value,
			expires: expires,
		}
		return nil
	}
	// get the type of the value - if it is a map, we need to merge the values
	if reflectionValue := reflect.ValueOf(value); reflectionValue.Kind() == reflect.Map {
		// get the current value from the cache
		currentValue := b.memory[key]
		cv := reflect.ValueOf(currentValue.value)
		// merge the two maps
		for _, k := range reflectionValue.MapKeys() {
			cv.SetMapIndex(k, reflectionValue.MapIndex(k))
		}
		// use the smallest expiration time
		if expires < currentValue.expires {
			cv.SetMapIndex(reflect.ValueOf("expires"), reflect.ValueOf(expires))
		}

		// set the new value
		b.memory[key] = batchCacheEntry{
			value:   cv.Interface(),
			expires: expires,
		}
	} else {

		b.memory[key] = batchCacheEntry{
			value:   value,
			expires: expires,
		}
	}
	return nil
}

func (b batchCache) Delete(ctx context.Context, key string) error {
	delete(b.memory, key)
	return nil
}

func (b batchCache) Flush(ctx context.Context) error {
	for key, entry := range b.memory {
		err := b.wrappedCache.Set(ctx, key, entry.value, entry.expires)
		if err != nil {
			return err
		}
	}
	return nil
}
