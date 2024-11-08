package cache

import (
	"testing"
	"time"
)

func TestMaxMemoryMapSet(t *testing.T) {
	m := NewMaxMemoryMap[string, string](10)
	m.Set("foo", "bar")
	if v, ok := m.Get("foo"); !ok || v != "bar" {
		t.Errorf("expected foo to be bar, got %v", v)
	}
}

func TestMaxMemoryMapPrune(t *testing.T) {
	m := NewMaxMemoryMap[string, string](10)
	m.Set("foo", "bar")
	m.Set("foo2", "bar2")
	if v, ok := m.Get("foo"); ok || v != "" {
		t.Errorf("expected foo to be empty, got %v", v)
	}
	if v, ok := m.Get("foo2"); !ok || v != "bar2" {
		t.Errorf("expected foo2 to be bar2, got %v", v)
	}
}

func TestMaxMemoryKeepLatest(t *testing.T) {
	m := NewMaxMemoryMap[string, string](20)
	m.Set("foo", "barrrr")  // 10 bytes
	m.Set("foo1", "barrrr") // another 10 bytes.
	time.Sleep(100 * time.Millisecond)
	// now use the foo one
	m.Get("foo")
	// if we set a new one, it should prune the old one
	m.Set("foo2", "barrrr") // another 10 bytes.
	if v, ok := m.Get("foo"); !ok || v != "barrrr" {
		t.Errorf("expected foo to be barrrr, got %v", v)
	}

	// foo2 should exist as well
	if v, ok := m.Get("foo2"); !ok || v != "barrrr" {
		t.Errorf("expected foo2 to be bar2, got %v", v)
	}

	// foo1 should not exist
	if v, ok := m.Get("foo1"); ok || v != "" {
		t.Errorf("expected foo1 to be empty, got %v", v)
	}
}
