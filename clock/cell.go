package clock

import "sync"

// A synchronized cell containing a value of type T.
//
// Data that has been stored in a muCell must not be modified thereafter,
// regardless of whether it is still in the cell.
type muCell[T any] struct {
	mu    sync.Mutex
	value T
}

// Constructs a new mutex cell with the given initial value.
func newCell[T any](value T) *muCell[T] {
	return &muCell[T]{
		mu:    sync.Mutex{},
		value: value,
	}
}

// Returns the value contained within the cell.
func (c *muCell[T]) Get() T {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.value
}

// Stores a new value in the cell, replacing the old value.
func (c *muCell[T]) Put(value T) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.value = value
}
