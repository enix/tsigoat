package dnsserver

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/enix/tsigoat/internal/backend"
)

// slowBackend fails its lookups after a delay, unless their context ends
// first, and counts them.
type slowBackend struct {
	delay   time.Duration
	mu      sync.Mutex
	lookups int
}

func (b *slowBackend) Lookup(ctx context.Context, _, _ string) ([]backend.RRset, error) {
	b.mu.Lock()
	b.lookups++
	b.mu.Unlock()
	select {
	case <-time.After(b.delay):
		return nil, errors.New("the backend is unavailable")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (*slowBackend) Apply(context.Context, string, []backend.Change) error {
	return nil
}

func (b *slowBackend) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lookups
}

// TestSOAFailureCachedFromTheEndOfTheRead checks that a failure to read the
// SOA, slower than the time for which the cache keeps it, is still cached
// when the next query arrives.
func TestSOAFailureCachedFromTheEndOfTheRead(t *testing.T) {
	t.Parallel()
	b := &slowBackend{delay: 200 * time.Millisecond}
	z := newServedZone(&Zone{Name: testZone, Backend: b})
	z.soaFailureTTL = 100 * time.Millisecond

	if _, fetched, err := z.cachedSOA(t.Context()); err == nil || !fetched {
		t.Fatalf("first query: fetched = %v, error %v, want a failure read from the backend", fetched, err)
	}
	if _, fetched, err := z.cachedSOA(t.Context()); err == nil || fetched {
		t.Errorf("second query: fetched = %v, error %v, want the cached failure", fetched, err)
	}
	if got := b.count(); got != 1 {
		t.Errorf("%d lookups for two queries, want 1", got)
	}
}

// TestSOAWaitHonoursTheDeadline checks that a query waiting for the read of
// another one gives up at its deadline.
func TestSOAWaitHonoursTheDeadline(t *testing.T) {
	t.Parallel()
	b := &slowBackend{delay: 10 * time.Second}
	z := newServedZone(&Zone{Name: testZone, Backend: b})

	readCtx, stopRead := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = z.cachedSOA(readCtx)
	}()
	t.Cleanup(func() {
		stopRead()
		<-done
	})
	for b.count() == 0 {
		time.Sleep(time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, fetched, err := z.cachedSOA(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || fetched {
		t.Errorf("cachedSOA() = fetched %v, error %v, want the deadline", fetched, err)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Errorf("the query waited %s for the read of another one", waited)
	}
}
