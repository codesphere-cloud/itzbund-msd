package cache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/resilience"
	"golang.org/x/sync/singleflight"
)

type serializer[T any] interface {
	Serialize(T) ([]byte, error)
	Deserialize([]byte) (T, error)
}

type circuitBreaker interface {
	Run(func() (any, error)) (any, error)
}
type redisCache[T any] struct {
	client *redis.Client
	cb     circuitBreaker

	memoryCache       memory[T]
	singleflightGroup singleflight.Group
	serializer        serializer[T]
}

func (r *redisCache[T]) Get(ctx context.Context, key string) (T, error) {
	// check if the value is in memory
	if val, err := r.memoryCache.Get(ctx, key); err == nil {
		return val, nil
	}
	res, err, _ := r.singleflightGroup.Do(key, func() (interface{}, error) {
		// first check in memory
		if val, err := r.memoryCache.Get(ctx, key); err == nil {
			return val, nil
		}

		res, err := r.cb.Run(func() (any, error) {
			res, err := r.client.Get(ctx, key).Result()
			if err == redis.Nil {
				return *new(T), nil
			}
			return res, err
		})

		if err != nil {
			return *new(T), err
		}

		if res == "" || res == nil {
			// make sure to return an error
			return *new(T), NewCacheMissError(key)
		}

		// deserialize the result from redis
		return r.serializer.Deserialize([]byte(res.(string)))
	})

	if err != nil {
		return *new(T), err
	}

	// keep it only in memory for 10 minutes
	r.memoryCache.Set(ctx, key, res.(T), 10*time.Minute) // nolint // will never fail
	// now we can finally cast the result to the correct type
	return res.(T), err
}

func (r *redisCache[T]) Set(ctx context.Context, key string, value T, expires time.Duration) error {
	// set in memory
	r.memoryCache.Set(ctx, key, value, expires) // nolint // will never fail

	_, err := r.cb.Run(func() (any, error) {
		valueStr, err := r.serializer.Serialize(value)
		if err != nil {
			return nil, err
		}
		return nil, r.client.Set(ctx, key, valueStr, expires).Err()
	})

	return err
}

func (r *redisCache[T]) Delete(ctx context.Context, key string) error {
	_, err := r.cb.Run(func() (any, error) { return nil, r.client.Del(ctx, key).Err() })
	return err
}

// support request deduplication and concurrent access
// will debounce set request to avoid concurrent set
func NewRedisCache[T any](addr, password string, db int, serializer serializer[T]) (*redisCache[T], error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	err := rdb.Ping(context.TODO()).Err()
	if err != nil {
		return nil, err
	}

	return &redisCache[T]{
		client:            rdb,
		memoryCache:       NewMemoryCache[T](),
		cb:                resilience.NewCircuitBreaker(resilience.DefaultClock{}, 10),
		singleflightGroup: singleflight.Group{},
		serializer:        serializer,
	}, nil
}
