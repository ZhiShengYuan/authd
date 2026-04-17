package handler

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mirror-guard/auth-backend/internal/policy"
)

func TestNewAuthInlineHandlerPolicyInitialization(t *testing.T) {
	t.Run("nil policy", func(t *testing.T) {
		h := NewAuthInlineHandler(nil)
		if got := h.policyRef.Load(); got != nil {
			t.Fatalf("expected nil policy, got %#v", got)
		}
	})

	t.Run("non-nil policy", func(t *testing.T) {
		pol := &policy.Set{Version: 1}
		h := NewAuthInlineHandler(pol)
		if got := h.policyRef.Load(); got != pol {
			t.Fatalf("expected stored policy pointer %p, got %p", pol, got)
		}
	})
}

func TestAuthInlineSetPolicyReplacesPolicy(t *testing.T) {
	h := NewAuthInlineHandler(nil)
	first := &policy.Set{Version: 1}
	second := &policy.Set{Version: 2}

	h.SetPolicy(first)
	if got := h.policyRef.Load(); got != first {
		t.Fatalf("expected first policy pointer %p, got %p", first, got)
	}

	h.SetPolicy(second)
	if got := h.policyRef.Load(); got != second {
		t.Fatalf("expected second policy pointer %p, got %p", second, got)
	}
}

func TestAuthInlineSetExecutorSetsAndReplaces(t *testing.T) {
	h := NewAuthInlineHandler(nil)

	first := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	second := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	h.SetExecutor(first)
	if h.executor == nil {
		t.Fatal("expected executor to be set")
	}

	h.SetExecutor(second)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected replacement executor status %d, got %d", http.StatusNoContent, rr.Code)
	}
}

func TestAuthInlineServeHTTPWithoutExecutorReturnsUnauthorized(t *testing.T) {
	h := NewAuthInlineHandler(nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth-inline", nil)

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestAuthInlineServeHTTPDelegatesToExecutor(t *testing.T) {
	h := NewAuthInlineHandler(nil)
	var called atomic.Int64
	h.SetExecutor(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.Header().Set("X-Delegated", r.URL.Path)
		w.WriteHeader(http.StatusCreated)
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/delegated", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, rr.Code)
	}
	if got := rr.Header().Get("X-Delegated"); got != "/delegated" {
		t.Fatalf("expected delegated header %q, got %q", "/delegated", got)
	}
	if called.Load() != 1 {
		t.Fatalf("expected executor to be called once, got %d", called.Load())
	}
}

func TestAuthInlineServeHTTPConcurrentAccess(t *testing.T) {
	h := NewAuthInlineHandler(nil)

	execA := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	execB := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	h.SetExecutor(execA)

	const workers = 32
	const iterations = 50

	start := make(chan struct{})
	errCh := make(chan int, workers*iterations)
	var wg sync.WaitGroup
	wg.Add(workers * 2)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				if j%2 == 0 {
					h.SetExecutor(execA)
				} else {
					h.SetExecutor(execB)
				}
			}
		}()

		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				rr := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/concurrent", nil)
				h.ServeHTTP(rr, req)
				if rr.Code != http.StatusAccepted && rr.Code != http.StatusNoContent {
					errCh <- rr.Code
				}
			}
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)

	for status := range errCh {
		t.Fatalf("unexpected status code during concurrent ServeHTTP: %d", status)
	}
}
