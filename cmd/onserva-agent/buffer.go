//go:build linux

package main

import "github.com/Onserva/onserva-agent/internal/collect"

// buffer is a bounded first-in-first-out queue of readings waiting to be sent.
//
// It is the reason a network outage costs you nothing: readings keep being
// taken and held here, and go out in order as soon as the platform is
// reachable again. When it is full the oldest reading is discarded — recent
// history is what matters when you are diagnosing a problem now.
//
// Deliberately not concurrent: everything runs on the single agent loop, so a
// mutex would be misleading noise.
type buffer struct {
	items    []collect.Sample
	capacity int
}

func newBuffer(capacity int) *buffer {
	return &buffer{items: make([]collect.Sample, 0, capacity), capacity: capacity}
}

// push appends a reading, reporting whether an older one had to be dropped.
func (b *buffer) push(sample collect.Sample) (dropped bool) {
	if len(b.items) >= b.capacity {
		b.items = b.items[1:]
		dropped = true
	}
	b.items = append(b.items, sample)
	return dropped
}

func (b *buffer) peek() (collect.Sample, bool) {
	if len(b.items) == 0 {
		return collect.Sample{}, false
	}
	return b.items[0], true
}

func (b *buffer) pop() {
	if len(b.items) > 0 {
		b.items = b.items[1:]
	}
}

func (b *buffer) len() int { return len(b.items) }
