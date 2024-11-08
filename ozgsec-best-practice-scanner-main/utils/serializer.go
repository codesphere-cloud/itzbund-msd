package utils

import "encoding/json"

type JsonSerializer[T any] struct {
}

func (s JsonSerializer[T]) Serialize(t T) ([]byte, error) {
	return json.Marshal(t)
}

func (s JsonSerializer[T]) Deserialize(bytes []byte) (T, error) {
	var t T
	err := json.Unmarshal(bytes, &t)
	return t, err
}
