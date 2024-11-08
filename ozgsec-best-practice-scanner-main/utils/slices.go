package utils

import (
	"fmt"
	"strings"
)

func Includes[T comparable](s []T, e T) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func IncludesSubset[T comparable](universe []T, subset []T) bool {
	for _, e := range subset {
		if !Includes(universe, e) {
			return false
		}
	}
	return true
}

func Join[T any](s []T, sep string) string {
	var b strings.Builder
	for i, e := range s {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(fmt.Sprint(e))
	}
	return b.String()
}

func Every[T any](s []T, f func(T) bool) bool {
	for _, e := range s {
		if !f(e) {
			return false
		}
	}
	return true
}

func Some[T any](s []T, f func(T) bool) bool {
	for _, e := range s {
		if f(e) {
			return true
		}
	}
	return false
}

func Filter[T any](s []T, f func(T) bool) []T {
	res := make([]T, 0)
	for _, e := range s {
		if f(e) {
			res = append(res, e)
		}
	}
	return res
}

func Map[T, U any](s []T, f func(T) U) []U {
	res := make([]U, len(s))
	for i, e := range s {
		res[i] = f(e)
	}
	return res
}
