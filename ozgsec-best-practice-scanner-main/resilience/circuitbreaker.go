package resilience

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type state string

const (
	closed state = "closed"
	open   state = "open"
	half   state = "half"
)

const timeout = 30 * time.Second

type circuitBreaker struct {
	timer      clock
	state      state
	lock       sync.Mutex
	tryingFlag bool

	currentFailureCount int

	closeAfterFailure int
}

func (c *circuitBreaker) State() state {
	return c.state
}

type clock interface {
	After(d time.Duration) <-chan time.Time
}

type DefaultClock struct {
}

func (c DefaultClock) After(dur time.Duration) <-chan time.Time {
	return time.After(dur)
}

func NewCircuitBreaker(timer clock, closeAfterFailure int) *circuitBreaker {
	return &circuitBreaker{state: closed, timer: timer, closeAfterFailure: closeAfterFailure, currentFailureCount: 0}
}

func (c *circuitBreaker) registerHalfOpen() {
	slog.Debug("Circuit breaker is open, waiting for timeout")
	<-c.timer.After(timeout)
	c.lock.Lock()
	c.state = half
	slog.Debug("Circuit breaker is half open")
	c.lock.Unlock()
}

func (c *circuitBreaker) Run(f func() (any, error)) (any, error) {
	switch c.state {
	case open:
		// log.Warning("Not executing since circuit breaker is open")
		return nil, fmt.Errorf("circuit is open")
	case half:
		if c.tryingFlag {
			// 	log.Warning("Not executing since circuit breaker is half open and trying")
			return nil, fmt.Errorf("circuit is half open and trying")
		}
		// set the tryingReq flag
		c.tryingFlag = true
		defer func() {
			c.tryingFlag = false
		}()
		// execute the function
		res, err := f()
		// check if the function returned an error
		if err != nil {
			slog.Warn("circuit breaker function returned an error", "err", err)
			// set the circuit to open state
			c.lock.Lock()
			c.state = open
			c.lock.Unlock()
			// set the timeout
			go c.registerHalfOpen()
			// return the error
			return nil, err
		}
		// set the circuit to closed state
		c.lock.Lock()
		c.currentFailureCount = 0
		c.state = closed
		c.lock.Unlock()
		// return the result
		return res, nil
	default:
		// execute the function
		res, err := f()
		// check if the function returned an error
		if err != nil {
			slog.Warn("circuit breaker function returned an error", "err", err)
			c.lock.Lock()
			c.currentFailureCount++
			if c.currentFailureCount >= c.closeAfterFailure {
				c.state = open
				// set the timeout
				go c.registerHalfOpen()
			}
			// set the circuit to open state
			c.lock.Unlock()
			// return the error
			return nil, err
		}
		if c.currentFailureCount > 0 {
			c.lock.Lock()
			c.currentFailureCount = 0
			c.lock.Unlock()
		}
		// return the result
		return res, nil
	}
}
