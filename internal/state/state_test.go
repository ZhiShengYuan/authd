package state

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestQuotaIncrementAndGet(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Stop)

	count, err := store.QuotaStore.Increment("192.168.1.0/24", 60*time.Second)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}

	count, err = store.QuotaStore.Increment("192.168.1.0/24", 60*time.Second)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 2 {
		t.Fatalf("expected count 2, got %d", count)
	}

	got := store.QuotaStore.Get("192.168.1.0/24")
	if got != 2 {
		t.Fatalf("expected get count 2, got %d", got)
	}
}

func TestQuotaConcurrentIncrementsAreRaceSafe(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Stop)

	const goroutines = 32
	const perGoroutine = 200

	var wg sync.WaitGroup
	var failed atomic.Bool

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				_, err := store.QuotaStore.Increment("2001:db8::/56", 60*time.Second)
				if err != nil {
					failed.Store(true)
					return
				}
			}
		}()
	}

	wg.Wait()

	if failed.Load() {
		t.Fatalf("unexpected error in concurrent increments")
	}

	expected := int64(goroutines * perGoroutine)
	got := store.QuotaStore.Get("2001:db8::/56")
	if got != expected {
		t.Fatalf("expected %d, got %d", expected, got)
	}
}

func TestNonceReplayDetection(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Stop)

	isNew, err := store.NonceStore.CheckAndLock("192.168.1.0/24", "nonce-1", 30*time.Second)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !isNew {
		t.Fatalf("expected first nonce use to be new")
	}

	isNew, err = store.NonceStore.CheckAndLock("192.168.1.0/24", "nonce-1", 30*time.Second)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if isNew {
		t.Fatalf("expected second nonce use to be replay")
	}
}

func TestNonceCanBeReusedAfterTTL(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Stop)

	isNew, err := store.NonceStore.CheckAndLock("192.168.1.0/24", "nonce-2", 10*time.Millisecond)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !isNew {
		t.Fatalf("expected first nonce use to be new")
	}

	time.Sleep(20 * time.Millisecond)

	isNew, err = store.NonceStore.CheckAndLock("192.168.1.0/24", "nonce-2", 10*time.Millisecond)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !isNew {
		t.Fatalf("expected nonce to be reusable after ttl")
	}
}

func TestCookieClaimOneTime(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Stop)

	if !store.CookieConsumptionStore.Claim("token-1") {
		t.Fatalf("expected first claim to succeed")
	}
	if store.CookieConsumptionStore.Claim("token-1") {
		t.Fatalf("expected second claim to fail")
	}
}

func TestCookieConcurrentClaimsAreRaceSafe(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Stop)

	const goroutines = 64

	var wg sync.WaitGroup
	var successes atomic.Int64

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if store.CookieConsumptionStore.Claim("token-concurrent") {
				successes.Add(1)
			}
		}()
	}

	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("expected exactly one successful claim, got %d", got)
	}
}

func TestCookieConcurrentClaimsSameTokenIDExactlyOneSucceeds(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Stop)

	const goroutines = 128

	var wg sync.WaitGroup
	var successes atomic.Int64

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if store.CookieConsumptionStore.Claim("token-race") {
				successes.Add(1)
			}
		}()
	}

	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("expected exactly one successful claim, got %d", got)
	}
}

func TestNonceCheckAndLockConcurrentOnlyFirstIsNew(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Stop)

	const goroutines = 128

	var wg sync.WaitGroup
	var newCount atomic.Int64

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			isNew, err := store.NonceStore.CheckAndLock("192.168.10.0/24", "nonce-race", time.Second)
			if err != nil {
				t.Errorf("CheckAndLock error: %v", err)
				return
			}
			if isNew {
				newCount.Add(1)
			}
		}()
	}

	wg.Wait()

	if got := newCount.Load(); got != 1 {
		t.Fatalf("expected exactly one isNew=true, got %d", got)
	}
}

func TestQuotaWindowResetsCounterAfterExpiry(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Stop)

	key := "192.168.50.0/24"
	window := 25 * time.Millisecond

	count, err := store.QuotaStore.Increment(key, window)
	if err != nil {
		t.Fatalf("first increment: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected first count to be 1, got %d", count)
	}

	count, err = store.QuotaStore.Increment(key, window)
	if err != nil {
		t.Fatalf("second increment: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected second count to be 2, got %d", count)
	}

	time.Sleep(40 * time.Millisecond)

	count, err = store.QuotaStore.Increment(key, window)
	if err != nil {
		t.Fatalf("increment after expiry: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected counter reset to 1 after window expiry, got %d", count)
	}
}

func TestQuotaStoreCleanupExpiredAndSize(t *testing.T) {
	q := &QuotaStore{entries: map[string]*quotaEntry{}}
	now := time.Now()

	q.entries["expired"] = &quotaEntry{windowStart: now.Add(-2 * time.Second), window: time.Second}
	q.entries["active"] = &quotaEntry{windowStart: now, window: 5 * time.Second}

	if got := q.Size(); got != 2 {
		t.Fatalf("size before cleanup = %d, want 2", got)
	}

	q.cleanupExpired(now)

	if got := q.Size(); got != 1 {
		t.Fatalf("size after cleanup = %d, want 1", got)
	}
	if _, exists := q.entries["expired"]; exists {
		t.Fatal("expected expired entry to be removed")
	}
	if _, exists := q.entries["active"]; !exists {
		t.Fatal("expected active entry to remain")
	}
}

func TestSizeMethodsOnNilStoresReturnZero(t *testing.T) {
	var q *QuotaStore
	var n *NonceStore
	var c *CookieConsumptionStore

	if got := q.Size(); got != 0 {
		t.Fatalf("nil quota size = %d, want 0", got)
	}
	if got := n.Size(); got != 0 {
		t.Fatalf("nil nonce size = %d, want 0", got)
	}
	if got := c.Size(); got != 0 {
		t.Fatalf("nil cookie size = %d, want 0", got)
	}
}

func TestNonceStoreCleanupExpiredAndSize(t *testing.T) {
	n := &NonceStore{}
	now := time.Now()

	n.locks.Store("expired", now.Add(-time.Second).UnixNano())
	n.locks.Store("active", now.Add(time.Second).UnixNano())
	n.locks.Store("bad-type", "not-int64")

	if got := n.Size(); got != 3 {
		t.Fatalf("size before cleanup = %d, want 3", got)
	}

	n.cleanupExpired(now)

	if got := n.Size(); got != 2 {
		t.Fatalf("size after cleanup = %d, want 2", got)
	}
	if _, exists := n.locks.Load("expired"); exists {
		t.Fatal("expected expired nonce lock to be removed")
	}
	if _, exists := n.locks.Load("active"); !exists {
		t.Fatal("expected active nonce lock to remain")
	}
	if _, exists := n.locks.Load("bad-type"); !exists {
		t.Fatal("expected invalid typed nonce lock entry to be ignored by cleanup")
	}
}

func TestCookieConsumptionStoreSizeTracksClaims(t *testing.T) {
	c := &CookieConsumptionStore{}

	if !c.Claim("a") {
		t.Fatal("expected first claim for a to succeed")
	}
	if !c.Claim("b") {
		t.Fatal("expected first claim for b to succeed")
	}
	if c.Claim("a") {
		t.Fatal("expected repeated claim for a to fail")
	}

	if got := c.Size(); got != 2 {
		t.Fatalf("cookie claim store size = %d, want 2", got)
	}
}

func TestNonceCheckAndLockInvalidTypeGuard(t *testing.T) {
	n := &NonceStore{}
	n.locks.Store("1.2.3.4:n1", "invalid")

	isNew, err := n.CheckAndLock("1.2.3.4", "n1", time.Second)
	if err == nil {
		t.Fatal("expected invalid type error")
	}
	if isNew {
		t.Fatal("expected isNew=false on invalid type")
	}
	if got := err.Error(); got != "state: invalid nonce lock entry type" {
		t.Fatalf("error = %q, want %q", got, "state: invalid nonce lock entry type")
	}
}

func TestQuotaIncrementAndGetGuardAndDefaults(t *testing.T) {
	q := &QuotaStore{entries: map[string]*quotaEntry{}}

	if _, err := q.Increment("", time.Second); !errors.Is(err, errEmptyKey) {
		t.Fatalf("expected errEmptyKey for empty subnet, got %v", err)
	}

	count, err := q.Increment("192.0.2.0/24", 0)
	if err != nil {
		t.Fatalf("increment with default window error: %v", err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}
	entry := q.entries["192.0.2.0/24"]
	if entry.window != DefaultQuotaWindow {
		t.Fatalf("entry window = %v, want default %v", entry.window, DefaultQuotaWindow)
	}

	count, err = q.Increment("192.0.2.0/24", 5*time.Second)
	if err != nil {
		t.Fatalf("increment with new window error: %v", err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
	if entry.window != 5*time.Second {
		t.Fatalf("updated entry window = %v, want %v", entry.window, 5*time.Second)
	}
}

func TestQuotaGetGuardMissingAndExpired(t *testing.T) {
	q := &QuotaStore{entries: map[string]*quotaEntry{}}
	now := time.Now()

	if got := q.Get(""); got != 0 {
		t.Fatalf("empty key get = %d, want 0", got)
	}
	if got := q.Get("missing"); got != 0 {
		t.Fatalf("missing key get = %d, want 0", got)
	}

	expired := &quotaEntry{windowStart: now.Add(-2 * time.Second), window: time.Second}
	expired.counter.Store(3)
	q.entries["expired"] = expired
	if got := q.Get("expired"); got != 0 {
		t.Fatalf("expired key get = %d, want 0", got)
	}
}

func TestNonceCheckAndLockGuardAndDefaultTTL(t *testing.T) {
	n := &NonceStore{}

	if _, err := n.CheckAndLock("", "nonce", time.Second); !errors.Is(err, errEmptyKey) {
		t.Fatalf("expected errEmptyKey for empty ip, got %v", err)
	}
	if _, err := n.CheckAndLock("ip", "", time.Second); !errors.Is(err, errEmptyKey) {
		t.Fatalf("expected errEmptyKey for empty nonce, got %v", err)
	}

	isNew, err := n.CheckAndLock("198.51.100.5", "n-default", 0)
	if err != nil {
		t.Fatalf("default ttl lock error: %v", err)
	}
	if !isNew {
		t.Fatal("expected first lock with default ttl to be new")
	}

	v, ok := n.locks.Load("198.51.100.5:n-default")
	if !ok {
		t.Fatal("expected lock entry to exist")
	}
	expiresAt, ok := v.(int64)
	if !ok {
		t.Fatalf("expected int64 expiresAt, got %T", v)
	}
	if time.Unix(0, expiresAt).Before(time.Now().Add(20 * time.Second)) {
		t.Fatalf("default ttl expiry too soon: %v", time.Unix(0, expiresAt))
	}
}

func TestCookieClaimGuardAndInvalidStoredType(t *testing.T) {
	c := &CookieConsumptionStore{}

	if c.Claim("") {
		t.Fatal("expected empty token claim to fail")
	}

	c.claims.Store("bad", "not-atomic-bool")
	if c.Claim("bad") {
		t.Fatal("expected invalid stored type claim to fail")
	}
}

func TestCleanupLoopRunsTickerCleanup(t *testing.T) {
	now := time.Now()
	s := &Store{
		QuotaStore: &QuotaStore{entries: map[string]*quotaEntry{
			"expired": {windowStart: now.Add(-2 * time.Second), window: time.Second},
		}},
		NonceStore: &NonceStore{},
		stopCh:     make(chan struct{}),
	}
	s.NonceStore.locks.Store("expired", now.Add(-time.Second).UnixNano())

	s.wg.Add(1)
	go s.cleanupLoop(time.Millisecond)

	time.Sleep(5 * time.Millisecond)
	close(s.stopCh)
	s.wg.Wait()

	if got := s.QuotaStore.Size(); got != 0 {
		t.Fatalf("quota size after ticker cleanup = %d, want 0", got)
	}
	if got := s.NonceStore.Size(); got != 0 {
		t.Fatalf("nonce size after ticker cleanup = %d, want 0", got)
	}
}
