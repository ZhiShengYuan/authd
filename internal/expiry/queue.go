// Package expiry provides a single-timer expiration queue.
package expiry

import (
	"container/heap"
	"sync"
	"time"
)

type item struct {
	key       string
	expiresAt time.Time
}

type itemHeap []item

func (h itemHeap) Len() int           { return len(h) }
func (h itemHeap) Less(i, j int) bool { return h[i].expiresAt.Before(h[j].expiresAt) }
func (h itemHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *itemHeap) Push(value any)    { *h = append(*h, value.(item)) }
func (h *itemHeap) Pop() any {
	old := *h
	value := old[len(old)-1]
	*h = old[:len(old)-1]
	return value
}

// Queue schedules key expiration with one goroutine and one timer regardless
// of the number of live entries. The callback must confirm that the key still
// has the scheduled expiry, because a key can be rescheduled before it fires.
type Queue struct {
	mu       sync.Mutex
	items    itemHeap
	wake     chan struct{}
	stop     chan struct{}
	done     chan struct{}
	onExpire func(string, time.Time)
	started  bool
	stopped  bool
}

func New(onExpire func(string, time.Time)) *Queue {
	return &Queue{
		wake:     make(chan struct{}, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		onExpire: onExpire,
	}
}

func (q *Queue) Start() {
	q.mu.Lock()
	if q.started || q.stopped {
		q.mu.Unlock()
		return
	}
	q.started = true
	q.mu.Unlock()
	go q.run()
}

func (q *Queue) Schedule(key string, expiresAt time.Time) bool {
	if key == "" || expiresAt.IsZero() {
		return false
	}
	q.mu.Lock()
	if q.stopped {
		q.mu.Unlock()
		return false
	}
	heap.Push(&q.items, item{key: key, expiresAt: expiresAt})
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return true
}

func (q *Queue) Stop() {
	q.mu.Lock()
	if q.stopped {
		started := q.started
		q.mu.Unlock()
		if started {
			<-q.done
		}
		return
	}
	q.stopped = true
	started := q.started
	close(q.stop)
	q.mu.Unlock()
	if started {
		<-q.done
	}
}

func (q *Queue) run() {
	defer close(q.done)
	var timer *time.Timer
	for {
		q.mu.Lock()
		if len(q.items) == 0 {
			q.mu.Unlock()
			select {
			case <-q.wake:
				continue
			case <-q.stop:
				return
			}
		}

		next := q.items[0]
		wait := time.Until(next.expiresAt)
		if wait <= 0 {
			heap.Pop(&q.items)
			q.mu.Unlock()
			if q.onExpire != nil {
				q.onExpire(next.key, next.expiresAt)
			}
			continue
		}
		q.mu.Unlock()

		if timer == nil {
			timer = time.NewTimer(wait)
		} else {
			timer.Reset(wait)
		}
		select {
		case <-timer.C:
		case <-q.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-q.stop:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		}
	}
}
