package ticket

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mirror-guard/auth-backend/internal/expiry"
)

const (
	defaultTTLSeconds = 15
	ticketExpiryGrace = 30 * time.Second
)

var (
	ErrTicketInvalid   = errors.New("ticket: invalid")
	ErrTicketNotFound  = errors.New("ticket: not found")
	ErrTicketExpired   = errors.New("ticket: expired")
	ErrTicketExhausted = errors.New("ticket: exhausted")
)

var randReadFn = rand.Read

type BindMatrix struct {
	URL string
	IP  string
	UA  string
}

type ticketState struct {
	remainingUses atomic.Int32
	expiresAt     time.Time
}

type TicketStore struct {
	states sync.Map
	size   atomic.Int64
}

type TicketManager struct {
	hmacKey     []byte
	ttlSeconds  int
	store       *TicketStore
	expirations *expiry.Queue
}

type parsedTicket struct {
	url       string
	ip        string
	uaDigest  string
	issuedAt  int64
	expiresAt int64
	uses      int32
	ticketID  string
}

func NewManager(globalSecret string, ttlSeconds int) *TicketManager {
	if ttlSeconds <= 0 {
		ttlSeconds = defaultTTLSeconds
	}

	runtimeTokenID, err := generateTokenID()
	if err != nil {
		runtimeTokenID = strconv.FormatInt(time.Now().UnixNano(), 10)
	}

	derived := sha512.Sum512([]byte(globalSecret + "|" + runtimeTokenID))

	manager := &TicketManager{
		hmacKey:    derived[:64],
		ttlSeconds: ttlSeconds,
		store:      &TicketStore{},
	}
	manager.expirations = expiry.New(manager.expire)
	return manager
}

func UADigest(userAgent string) string {
	sum := sha256.Sum256([]byte(userAgent))
	return hex.EncodeToString(sum[:16])
}

func (m *TicketManager) Issue(bind BindMatrix, uses int) (token string, err error) {
	if uses <= 0 {
		return "", ErrTicketExhausted
	}

	now := time.Now().Unix()
	expiresAt := now + int64(m.ttlSeconds)

	ticketID, err := generateTokenID()
	if err != nil {
		return "", err
	}

	canonicalUADigest := strings.ToLower(UADigest(bind.UA))

	payload := make([]byte, 0, len(bind.URL)+len(bind.IP)+len(canonicalUADigest)+len(ticketID)+64)
	payload = append(payload, []byte(bind.URL)...)
	payload = append(payload, '|')
	payload = append(payload, []byte(bind.IP)...)
	payload = append(payload, '|')
	payload = append(payload, []byte(canonicalUADigest)...)
	payload = append(payload, '|')

	var issuedAtBytes [8]byte
	binary.BigEndian.PutUint64(issuedAtBytes[:], uint64(now))
	payload = append(payload, issuedAtBytes[:]...)
	payload = append(payload, '|')

	var expiresAtBytes [8]byte
	binary.BigEndian.PutUint64(expiresAtBytes[:], uint64(expiresAt))
	payload = append(payload, expiresAtBytes[:]...)
	payload = append(payload, '|')

	var usesBytes [4]byte
	binary.BigEndian.PutUint32(usesBytes[:], uint32(int32(uses)))
	payload = append(payload, usesBytes[:]...)
	payload = append(payload, '|')
	payload = append(payload, []byte(ticketID)...)

	sig := hmacSHA256(payload, m.hmacKey)
	raw := make([]byte, 0, len(payload)+1+len(sig)*2)
	raw = append(raw, payload...)
	raw = append(raw, '|')
	raw = append(raw, []byte(hex.EncodeToString(sig))...)

	state := &ticketState{expiresAt: time.Unix(expiresAt, 0)}
	state.remainingUses.Store(int32(uses))
	m.store.states.Store(ticketID, state)
	m.store.size.Add(1)
	if !m.expirations.Schedule(ticketID, state.expiresAt.Add(ticketExpiryGrace)) {
		m.delete(ticketID, state)
		return "", errors.New("ticket: expiration queue stopped")
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (m *TicketManager) Verify(token string, bind BindMatrix) (valid bool, err error) {
	pt, err := m.parseAndVerify(token)
	if err != nil {
		return false, err
	}

	actual, ok := m.store.states.Load(pt.ticketID)
	if !ok {
		return false, ErrTicketNotFound
	}

	state, ok := actual.(*ticketState)
	if !ok {
		return false, ErrTicketNotFound
	}

	remaining := state.remainingUses.Add(-1)
	if remaining < 0 {
		return false, ErrTicketExhausted
	}

	now := time.Now().Unix()
	if now >= pt.expiresAt || now >= state.expiresAt.Unix() {
		return false, ErrTicketExpired
	}

	expectedUADigest := strings.ToLower(UADigest(bind.UA))
	if bind.URL != pt.url || bind.IP != pt.ip || expectedUADigest != pt.uaDigest {
		return false, nil
	}

	return true, nil
}

func (m *TicketManager) StartCleanup(interval time.Duration) {
	_ = interval
	m.expirations.Start()
}

func (m *TicketManager) Stop() {
	m.expirations.Stop()
}

func (m *TicketManager) Size() int64 {
	if m == nil || m.store == nil {
		return 0
	}
	return m.store.size.Load()
}

func (m *TicketManager) delete(ticketID string, expected *ticketState) {
	if m.store.states.CompareAndDelete(ticketID, expected) {
		m.store.size.Add(-1)
	}
}

func (m *TicketManager) expire(ticketID string, expectedExpiry time.Time) {
	actual, ok := m.store.states.Load(ticketID)
	if !ok {
		return
	}
	state, ok := actual.(*ticketState)
	if !ok {
		m.store.states.Delete(ticketID)
		return
	}
	deleteAt := state.expiresAt.Add(ticketExpiryGrace)
	if !deleteAt.Equal(expectedExpiry) || time.Now().Before(deleteAt) {
		return
	}
	m.delete(ticketID, state)
}

func (m *TicketManager) parseAndVerify(token string) (*parsedTicket, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, ErrTicketInvalid
	}

	parts := strings.Split(string(raw), "|")
	if len(parts) != 8 {
		return nil, ErrTicketInvalid
	}

	payloadLen := len(raw) - len(parts[7]) - 1
	if payloadLen <= 0 {
		return nil, ErrTicketInvalid
	}
	payload := raw[:payloadLen]

	providedSig, err := hex.DecodeString(parts[7])
	if err != nil {
		return nil, ErrTicketInvalid
	}
	computedSig := hmacSHA256(payload, m.hmacKey)
	if !hmac.Equal(providedSig, computedSig) {
		return nil, ErrTicketInvalid
	}

	issuedAtBytes := []byte(parts[3])
	expiresAtBytes := []byte(parts[4])
	usesBytes := []byte(parts[5])
	if len(issuedAtBytes) != 8 || len(expiresAtBytes) != 8 || len(usesBytes) != 4 {
		return nil, ErrTicketInvalid
	}

	issuedAt := int64(binary.BigEndian.Uint64(issuedAtBytes))
	expiresAt := int64(binary.BigEndian.Uint64(expiresAtBytes))
	uses := int32(binary.BigEndian.Uint32(usesBytes))
	if expiresAt <= issuedAt || parts[6] == "" || uses <= 0 {
		return nil, ErrTicketInvalid
	}

	return &parsedTicket{
		url:       parts[0],
		ip:        parts[1],
		uaDigest:  strings.ToLower(parts[2]),
		issuedAt:  issuedAt,
		expiresAt: expiresAt,
		uses:      uses,
		ticketID:  parts[6],
	}, nil
}

func hmacSHA256(message, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil)
}

func generateTokenID() (string, error) {
	b := make([]byte, 16)
	if _, err := randReadFn(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
