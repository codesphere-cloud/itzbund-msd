package resilience

import (
	"fmt"
	"testing"
	"time"
)

type fakeClock struct {
	ping chan time.Time
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	return c.ping
}

func (c *fakeClock) Ping() {
	// never block
	c.ping <- time.Now()
}

func TestInitClosedState(t *testing.T) {
	// should init a circuit breaker in closed state
	c := NewCircuitBreaker(nil, 1)
	if c.State() != closed {
		t.Errorf("Expected circuit breaker to be in closed state, got %s", c.State())
	}
}

func TestRunSuccess(t *testing.T) {
	// should init a circuit breaker in closed state
	c := NewCircuitBreaker(nil, 1)
	// should execute the function and return the result if the circuit breaker is in closed state
	res, err := c.Run(func() (interface{}, error) {
		return "Hello World", nil
	})
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}
	if res != "Hello World" {
		t.Errorf("Expected result to be 'Hello World', got %s", res)
	}
}

func TestOpenStateOnError(t *testing.T) {
	// should init a circuit breaker in closed state
	clock := &fakeClock{ping: make(chan time.Time)}
	c := NewCircuitBreaker(clock, 1)
	// should execute the function and return the result if the circuit breaker is in closed state
	res, err := c.Run(func() (interface{}, error) {
		return nil, fmt.Errorf("error")
	})

	if err == nil {
		t.Errorf("Expected error, got %s", err)
	}
	if res != nil {
		t.Errorf("Expected result to be nil, got %s", res)
	}
	// should set the circuit breaker to open state
	if c.State() != open {
		t.Errorf("Expected circuit breaker to be in open state, got %s", c.State())
	}

	// now it should return an error without executing the function
	_, err = c.Run(func() (interface{}, error) {
		return "Hello World", nil
	})
	if err == nil {
		t.Errorf("Expected error, got %s", err)
	}
}

func TestTransitionInHalfOpenState(t *testing.T) {
	// should init a circuit breaker in closed state
	clock := &fakeClock{ping: make(chan time.Time)}
	c := NewCircuitBreaker(clock, 1)
	// should execute the function and return the result if the circuit breaker is in closed state
	c.Run(func() (interface{}, error) { // nolint: errcheck
		return nil, fmt.Errorf("error")
	})

	// should set the circuit breaker to open state
	if c.State() != open {
		t.Errorf("Expected circuit breaker to be in open state, got %s", c.State())
	}

	// should set the circuit breaker to half open state after the timeout
	clock.Ping()
	if c.State() != half {
		t.Errorf("Expected circuit breaker to be in half open state, got %s", c.State())
	}

	// should execute the function and return the result if the circuit breaker is in half open state
	res, _ := c.Run(func() (interface{}, error) {
		return "Hello World", nil
	})
	if res != "Hello World" {
		t.Errorf("Expected result to be 'Hello World', got %s", res)
	}
	// it should now be in open state, since the function did not return an error
	if c.State() != closed {
		t.Errorf("Expected circuit breaker to be in open state, got %s", c.State())
	}
}

func TestShouldOnlyOpenTheCircuitAfterFailureCountReached(t *testing.T) {
	// should init a circuit breaker in closed state
	clock := &fakeClock{ping: make(chan time.Time)}
	c := NewCircuitBreaker(clock, 2)
	// should execute the function and return the result if the circuit breaker is in closed state
	c.Run(func() (interface{}, error) { // nolint: errcheck
		return nil, fmt.Errorf("error")
	})

	// should set the circuit breaker to open state
	if c.State() != closed {
		t.Errorf("Expected circuit breaker to be in closed state, got %s", c.State())
	}

	// now do another failure
	c.Run(func() (interface{}, error) { // nolint: errcheck
		return nil, fmt.Errorf("error")
	})

	// it should now be in open state, since the function did not return an error
	if c.State() != open {
		t.Errorf("Expected circuit breaker to be in open state, got %s", c.State())
	}
}

func TestShouldResetFailureCountAfterSuccess(t *testing.T) {
	// should init a circuit breaker in closed state
	clock := &fakeClock{ping: make(chan time.Time)}
	c := NewCircuitBreaker(clock, 2)
	// should execute the function and return the result if the circuit breaker is in closed state
	c.Run(func() (interface{}, error) { // nolint: errcheck
		return nil, fmt.Errorf("error")
	})

	// should set the circuit breaker to open state
	if c.State() != closed {
		t.Errorf("Expected circuit breaker to be in closed state, got %s", c.State())
	}

	// now do a success
	c.Run(func() (interface{}, error) { // nolint: errcheck
		return nil, nil
	})
	// failure count be zero after success
	c.Run(func() (interface{}, error) { // nolint: errcheck
		return nil, fmt.Errorf("error")
	})
	// now failure count should be 1

	// it should now be in open state, since the function did not return an error
	if c.State() != closed {
		t.Errorf("Expected circuit breaker to be in closed state, got %s", c.State())
	}
}
