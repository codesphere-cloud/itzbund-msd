package utils

import (
	"time"
)

func Throttle[Param any](f func(param Param) interface{}, d time.Duration) func(Param) {
	var last time.Time
	return func(param Param) {
		if time.Since(last) > d {
			f(param)
			last = time.Now()

		}
	}
}

func CollectParams[Param any](f func(params []Param), window time.Duration) func(Param) {
	params := make([]Param, 0)
	var start time.Time
	return func(p Param) {
		params = append(params, p)
		if start.IsZero() {
			start = time.Now()
		}
		if time.Since(start) > window {
			f(params)
			params = []Param{}
			start = time.Now()
		}
	}
}
