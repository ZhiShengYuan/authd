package ticket

import (
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIssueAndVerify(t *testing.T) {
	m := NewManager("secret", 60)
	t.Cleanup(m.Stop)

	bind := BindMatrix{URL: "/x", IP: "10.0.0.1", UA: "agent-a"}
	token, err := m.Issue(bind, 3)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	for i := 0; i < 3; i++ {
		ok, err := m.Verify(token, bind)
		if err != nil {
			t.Fatalf("verify %d err: %v", i, err)
		}
		if !ok {
			t.Fatalf("verify %d expected valid", i)
		}
	}
}

func TestVerifyDecrementsOnEveryCall(t *testing.T) {
	m := NewManager("secret", 60)
	t.Cleanup(m.Stop)

	bind := BindMatrix{URL: "/a", IP: "1.2.3.4", UA: "ua"}
	token, err := m.Issue(bind, 2)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	ok, err := m.Verify(token, bind)
	if err != nil || !ok {
		t.Fatalf("first verify: ok=%v err=%v", ok, err)
	}

	ok, err = m.Verify(token, bind)
	if err != nil || !ok {
		t.Fatalf("second verify: ok=%v err=%v", ok, err)
	}

	ok, err = m.Verify(token, bind)
	if err != ErrTicketExhausted {
		t.Fatalf("third verify expected exhausted, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyDecrementsEvenOnBindMismatch(t *testing.T) {
	m := NewManager("secret", 60)
	t.Cleanup(m.Stop)

	bind := BindMatrix{URL: "/path", IP: "5.6.7.8", UA: "ua-good"}
	token, err := m.Issue(bind, 2)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	wrong := BindMatrix{URL: "/wrong", IP: "5.6.7.8", UA: "ua-good"}
	ok, err := m.Verify(token, wrong)
	if err != nil {
		t.Fatalf("wrong bind verify err: %v", err)
	}
	if ok {
		t.Fatalf("wrong bind should be invalid")
	}

	ok, err = m.Verify(token, bind)
	if err != nil || !ok {
		t.Fatalf("correct bind after mismatch should still have one use: ok=%v err=%v", ok, err)
	}

	ok, err = m.Verify(token, bind)
	if err != ErrTicketExhausted {
		t.Fatalf("expected exhausted after two consumptions, got ok=%v err=%v", ok, err)
	}
}

func TestExpiredTicket(t *testing.T) {
	m := NewManager("secret", 1)
	t.Cleanup(m.Stop)

	bind := BindMatrix{URL: "/exp", IP: "9.9.9.9", UA: "ua-exp"}
	token, err := m.Issue(bind, 2)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	time.Sleep(1200 * time.Millisecond)
	ok, err := m.Verify(token, bind)
	if err != ErrTicketExpired {
		t.Fatalf("expected expired, got ok=%v err=%v", ok, err)
	}
}

func TestInvalidSignature(t *testing.T) {
	m := NewManager("secret", 60)
	t.Cleanup(m.Stop)

	bind := BindMatrix{URL: "/sig", IP: "3.3.3.3", UA: "ua-sig"}
	token, err := m.Issue(bind, 1)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	tampered := base64.RawURLEncoding.EncodeToString(raw)

	ok, err := m.Verify(tampered, bind)
	if err != ErrTicketInvalid {
		t.Fatalf("expected invalid signature, got ok=%v err=%v", ok, err)
	}
}

func TestConcurrentVerify(t *testing.T) {
	m := NewManager("secret", 60)
	t.Cleanup(m.Stop)

	bind := BindMatrix{URL: "/conc", IP: "8.8.8.8", UA: "ua-conc"}
	uses := 25
	token, err := m.Issue(bind, uses)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var successCount atomic.Int32
	workers := uses * 3
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			ok, err := m.Verify(token, bind)
			if err == nil && ok {
				successCount.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := int(successCount.Load()); got != uses {
		t.Fatalf("successful verifies mismatch: got %d want %d", got, uses)
	}
}

func TestZeroUses(t *testing.T) {
	m := NewManager("secret", 60)
	t.Cleanup(m.Stop)

	_, err := m.Issue(BindMatrix{URL: "/z", IP: "1.1.1.1", UA: "ua"}, 0)
	if err == nil {
		t.Fatalf("expected error for zero uses")
	}
}

func TestNegativeUses(t *testing.T) {
	m := NewManager("secret", 60)
	t.Cleanup(m.Stop)

	_, err := m.Issue(BindMatrix{URL: "/n", IP: "1.1.1.1", UA: "ua"}, -1)
	if err == nil {
		t.Fatalf("expected error for negative uses")
	}
}
