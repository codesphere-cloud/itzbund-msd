package cache

import (
	"bytes"
	"encoding/gob"
	"sync"
	"time"
)

type mapEntry[Value any] struct {
	value      Value
	lastUsed   time.Time
	memorySize int
}

type maxMemoryMap[Key comparable, Value any] struct {
	internalMap       map[Key]mapEntry[Value]
	currentMemorySize int
	maxMemorySize     int

	cleanupRunning bool

	lock sync.Mutex
}

func NewMaxMemoryMap[Key comparable, Value any](maxMemorySize int) maxMemoryMap[Key, Value] {
	return maxMemoryMap[Key, Value]{
		internalMap:       make(map[Key]mapEntry[Value]),
		currentMemorySize: 0,
		maxMemorySize:     maxMemorySize,
		lock:              sync.Mutex{},
	}
}

func (m *maxMemoryMap[Key, Value]) Get(key Key) (Value, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	v, ok := m.internalMap[key]
	if ok {
		v.lastUsed = time.Now()
		m.internalMap[key] = v
	}
	return v.value, ok
}

func (m *maxMemoryMap[Key, Value]) Set(key Key, value Value) {
	size, err := getSizeOf(value)
	if err != nil {
		return
	}
	m.lock.Lock()
	m.internalMap[key] = mapEntry[Value]{
		value:      value,
		lastUsed:   time.Now(),
		memorySize: size,
	}
	m.currentMemorySize += size
	m.lock.Unlock()
	if !m.cleanupRunning {
		m.cleanUp()
	}
}

func (m *maxMemoryMap[Key, Value]) cleanUp() {
	m.lock.Lock()
	m.cleanupRunning = true

	defer func() {
		m.cleanupRunning = false
		m.lock.Unlock()
	}()

	if m.currentMemorySize < m.maxMemorySize {
		return
	}
	for m.currentMemorySize > m.maxMemorySize {
		var oldestKey Key
		var oldestValue mapEntry[Value]
		for k, v := range m.internalMap {
			if oldestValue.lastUsed.IsZero() || v.lastUsed.Before(oldestValue.lastUsed) {
				oldestKey = k
				oldestValue = v
			}
		}
		delete(m.internalMap, oldestKey)
		m.currentMemorySize -= oldestValue.memorySize
	}
}

func getSizeOf(v any) (int, error) {
	b := new(bytes.Buffer)
	if err := gob.NewEncoder(b).Encode(v); err != nil {
		return 0, err
	}
	return b.Len(), nil
}
