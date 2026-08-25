package state

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mirror-guard/auth-backend/internal/expiry"
)

const (
	DefaultNonceTTL      = 30 * time.Second
	DefaultQuotaWindow   = 60 * time.Second
	DefaultCleanupTicker = 10 * time.Second
	ChallengeExpiryGrace = 10 * time.Second
)

var errEmptyKey = errors.New("state: empty key")

var (
	ErrChallengeNotFound      = errors.New("state: challenge not found")
	ErrChallengeExpired       = errors.New("state: challenge expired")
	ErrChallengeReplayed      = errors.New("state: challenge replayed")
	ErrChallengeAlreadyExists = errors.New("state: challenge already exists")
)

type quotaEntry struct {
	counter     atomic.Int64
	windowStart time.Time
	window      time.Duration
}

type QuotaStore struct {
	mu      sync.RWMutex
	entries map[string]*quotaEntry
}

type NonceStore struct {
	locks sync.Map
}

type CookieConsumptionStore struct {
	claims sync.Map
}

type ChallengeEntry struct {
	ChallengeID string
	Difficulty  int
	BindURL     string
	BindIP      string
	BindUA      string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Consumed    atomic.Bool
}

type ChallengeStore struct {
	challenges  sync.Map
	expirations *expiry.Queue
	size        atomic.Int64
	expiryOnce  sync.Once
}

type Store struct {
	QuotaStore             *QuotaStore
	NonceStore             *NonceStore
	CookieConsumptionStore *CookieConsumptionStore
	ChallengeStore         *ChallengeStore

	stopOnce sync.Once
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

func NewStore() *Store {
	s := &Store{
		QuotaStore: &QuotaStore{
			entries: make(map[string]*quotaEntry),
		},
		NonceStore:             &NonceStore{},
		CookieConsumptionStore: &CookieConsumptionStore{},
		ChallengeStore:         newChallengeStore(),
		stopCh:                 make(chan struct{}),
	}

	s.wg.Add(1)
	go s.cleanupLoop(DefaultCleanupTicker)
	s.ChallengeStore.expirations.Start()

	return s
}

func (s *Store) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		s.wg.Wait()
		s.ChallengeStore.expirations.Stop()
	})
}

func (s *Store) cleanupLoop(interval time.Duration) {
	defer s.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.QuotaStore.cleanupExpired(now)
			s.NonceStore.cleanupExpired(now)
		case <-s.stopCh:
			return
		}
	}
}

func newChallengeStore() *ChallengeStore {
	store := &ChallengeStore{}
	store.ensureExpirationQueue()
	return store
}

func (c *ChallengeStore) ensureExpirationQueue() {
	c.expiryOnce.Do(func() {
		c.expirations = expiry.New(c.expire)
		c.expirations.Start()
	})
}

func (c *ChallengeStore) Configure(challengeID string, difficulty int, bindURL, bindIP, bindUA string, ttl time.Duration) error {
	c.ensureExpirationQueue()
	if challengeID == "" {
		return errEmptyKey
	}
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}

	now := time.Now()
	entry := &ChallengeEntry{
		ChallengeID: challengeID,
		Difficulty:  difficulty,
		BindURL:     bindURL,
		BindIP:      bindIP,
		BindUA:      bindUA,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}

	_, loaded := c.challenges.LoadOrStore(challengeID, entry)
	if loaded {
		return ErrChallengeAlreadyExists
	}
	c.size.Add(1)
	if !c.expirations.Schedule(challengeID, entry.ExpiresAt.Add(ChallengeExpiryGrace)) {
		c.delete(challengeID, entry)
		return errors.New("state: challenge expiration queue stopped")
	}

	return nil
}

func (c *ChallengeStore) Lookup(challengeID string) (*ChallengeEntry, error) {
	if challengeID == "" {
		return nil, errEmptyKey
	}

	actual, ok := c.challenges.Load(challengeID)
	if !ok {
		return nil, ErrChallengeNotFound
	}

	entry, ok := actual.(*ChallengeEntry)
	if !ok {
		return nil, ErrChallengeNotFound
	}

	if time.Now().After(entry.ExpiresAt) {
		c.delete(challengeID, entry)
		return nil, ErrChallengeExpired
	}

	if entry.Consumed.Load() {
		return nil, ErrChallengeReplayed
	}

	return entry, nil
}

func (c *ChallengeStore) Consume(challengeID string) (*ChallengeEntry, error) {
	if challengeID == "" {
		return nil, errEmptyKey
	}

	actual, ok := c.challenges.Load(challengeID)
	if !ok {
		return nil, ErrChallengeNotFound
	}

	entry, ok := actual.(*ChallengeEntry)
	if !ok {
		return nil, ErrChallengeNotFound
	}

	if time.Now().After(entry.ExpiresAt) {
		c.delete(challengeID, entry)
		return nil, ErrChallengeExpired
	}

	if !entry.Consumed.CompareAndSwap(false, true) {
		return nil, ErrChallengeReplayed
	}

	return entry, nil
}

// Compact replaces a consumed challenge with a small replay tombstone. The
// signed prefix and bind matrix are no longer needed after the first attempt,
// but retaining the ID until expiry preserves the replay-specific response.
func (c *ChallengeStore) Compact(challengeID string) {
	actual, ok := c.challenges.Load(challengeID)
	if !ok {
		return
	}
	entry, ok := actual.(*ChallengeEntry)
	if !ok || !entry.Consumed.Load() || (entry.BindURL == "" && entry.BindIP == "" && entry.BindUA == "") {
		return
	}
	tombstone := &ChallengeEntry{
		ChallengeID: entry.ChallengeID,
		CreatedAt:   entry.CreatedAt,
		ExpiresAt:   entry.ExpiresAt,
	}
	tombstone.Consumed.Store(true)
	c.challenges.CompareAndSwap(challengeID, entry, tombstone)
}

func (c *ChallengeStore) Size() int64 {
	if c == nil {
		return 0
	}
	return c.size.Load()
}

func (c *ChallengeStore) delete(challengeID string, expected *ChallengeEntry) {
	if c.challenges.CompareAndDelete(challengeID, expected) {
		c.size.Add(-1)
	}
}

func (c *ChallengeStore) expire(challengeID string, expectedExpiry time.Time) {
	actual, ok := c.challenges.Load(challengeID)
	if !ok {
		return
	}
	entry, ok := actual.(*ChallengeEntry)
	deleteAt := entry.ExpiresAt.Add(ChallengeExpiryGrace)
	if !ok || !deleteAt.Equal(expectedExpiry) || time.Now().Before(deleteAt) {
		return
	}
	c.delete(challengeID, entry)
}

func (q *QuotaStore) Increment(subnetKey string, window time.Duration) (int64, error) {
	if subnetKey == "" {
		return 0, errEmptyKey
	}
	if window <= 0 {
		window = DefaultQuotaWindow
	}

	now := time.Now()

	q.mu.Lock()
	defer q.mu.Unlock()

	entry, ok := q.entries[subnetKey]
	if !ok || now.Sub(entry.windowStart) >= window {
		entry = &quotaEntry{
			windowStart: now,
			window:      window,
		}
		q.entries[subnetKey] = entry
	} else if entry.window != window {
		entry.window = window
	}

	return entry.counter.Add(1), nil
}

func (q *QuotaStore) Get(subnetKey string) int64 {
	if subnetKey == "" {
		return 0
	}

	now := time.Now()

	q.mu.RLock()
	entry, ok := q.entries[subnetKey]
	if !ok {
		q.mu.RUnlock()
		return 0
	}

	windowStart := entry.windowStart
	window := entry.window
	count := entry.counter.Load()
	q.mu.RUnlock()

	if now.Sub(windowStart) >= window {
		return 0
	}

	return count
}

func (q *QuotaStore) cleanupExpired(now time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for key, entry := range q.entries {
		if now.Sub(entry.windowStart) >= entry.window {
			delete(q.entries, key)
		}
	}
}

func (q *QuotaStore) Size() int {
	if q == nil {
		return 0
	}
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.entries)
}

func (n *NonceStore) CheckAndLock(ip string, nonce string, ttl time.Duration) (bool, error) {
	if ip == "" || nonce == "" {
		return false, errEmptyKey
	}
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}

	key := ip + ":" + nonce

	for {
		now := time.Now().UnixNano()
		expiresAt := time.Now().Add(ttl).UnixNano()

		actual, loaded := n.locks.LoadOrStore(key, expiresAt)
		if !loaded {
			return true, nil
		}

		currentExpiresAt, ok := actual.(int64)
		if !ok {
			return false, errors.New("state: invalid nonce lock entry type")
		}

		if now <= currentExpiresAt {
			return false, nil
		}

		if n.locks.CompareAndSwap(key, currentExpiresAt, expiresAt) {
			return true, nil
		}
	}
}

func (n *NonceStore) cleanupExpired(now time.Time) {
	nowNano := now.UnixNano()
	n.locks.Range(func(key, value any) bool {
		expiresAt, ok := value.(int64)
		if ok && nowNano > expiresAt {
			n.locks.Delete(key)
		}
		return true
	})
}

func (n *NonceStore) Size() int {
	if n == nil {
		return 0
	}
	size := 0
	n.locks.Range(func(_, _ any) bool {
		size++
		return true
	})
	return size
}

func (c *CookieConsumptionStore) Claim(tokenID string) bool {
	if tokenID == "" {
		return false
	}

	actual, _ := c.claims.LoadOrStore(tokenID, &atomic.Bool{})
	flag, ok := actual.(*atomic.Bool)
	if !ok {
		return false
	}

	return flag.CompareAndSwap(false, true)
}

func (c *CookieConsumptionStore) Size() int {
	if c == nil {
		return 0
	}
	size := 0
	c.claims.Range(func(_, _ any) bool {
		size++
		return true
	})
	return size
}
