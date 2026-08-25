package expiry

import (
	"sync"
	"testing"
	"time"
)

func TestQueueExpiresInDeadlineOrder(t *testing.T) {
	var mu sync.Mutex
	var expired []string
	done := make(chan struct{}, 2)
	queue := New(func(key string, _ time.Time) {
		mu.Lock()
		expired = append(expired, key)
		mu.Unlock()
		done <- struct{}{}
	})
	queue.Start()
	t.Cleanup(queue.Stop)

	now := time.Now()
	queue.Schedule("later", now.Add(40*time.Millisecond))
	queue.Schedule("sooner", now.Add(10*time.Millisecond))
	for range 2 {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("expiration timed out")
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(expired) != 2 || expired[0] != "sooner" || expired[1] != "later" {
		t.Fatalf("unexpected expiration order: %v", expired)
	}
}

func TestQueueStopIsIdempotent(t *testing.T) {
	queue := New(nil)
	queue.Start()
	queue.Stop()
	queue.Stop()
	if queue.Schedule("ignored", time.Now()) {
		t.Fatal("schedule succeeded after stop")
	}
}
