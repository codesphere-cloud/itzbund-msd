package cache

import (
	"context"
	"testing"
	"time"
)

func TestRefreshCache(t *testing.T) {
	memoryCache := NewMemoryCache[string]()

	refreshCache := NewRefreshCache[string](memoryCache)

	// Set a value in the underlying cache
	memoryCache.Set(context.Background(), "foo", "bar", 1*time.Hour) // nolint

	// Get the value from the refresh cache
	_, err := refreshCache.Get(context.Background(), "foo")

	// This should be a cache miss
	if err == nil {
		t.Fatal(err)
	}

	// Set the value in the refresh cache
	refreshCache.Set(context.Background(), "foo", "bar1", 1*time.Hour) // nolint

	// Get the value from the real cache - now it should have been refreshed
	value, err := memoryCache.Get(context.Background(), "foo")
	if err != nil {
		t.Fatal(err)
	}

	if value != "bar1" {
		t.Fatal("value should be bar1")
	}
}
