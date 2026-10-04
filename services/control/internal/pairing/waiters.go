package pairing

import (
	"sync"

	"github.com/google/uuid"
)

// waiters lets approvals and cancellations wake long polls immediately
// (polling the database remains the source of truth).
type waiters struct {
	mu sync.Mutex
	m  map[uuid.UUID]map[chan struct{}]bool
}

func (w *waiters) get(id uuid.UUID) chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.m == nil {
		w.m = map[uuid.UUID]map[chan struct{}]bool{}
	}
	if w.m[id] == nil {
		w.m[id] = map[chan struct{}]bool{}
	}
	ch := make(chan struct{}, 1)
	w.m[id][ch] = true
	return ch
}

func (w *waiters) put(id uuid.UUID, ch chan struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.m[id], ch)
	if len(w.m[id]) == 0 {
		delete(w.m, id)
	}
}

func (w *waiters) wake(id uuid.UUID) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for ch := range w.m[id] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
