package cookie

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mirror-guard/auth-backend/internal/state"
)

type failingReader struct{}

func (f failingReader) Read(_ []byte) (int, error) {
	return 0, errors.New("forced random read failure")
}

func setRandReadFn(t *testing.T, fn func([]byte) (int, error)) {
	t.Helper()
	original := randReadFn
	randReadFn = fn
	t.Cleanup(func() {
		randReadFn = original
	})
}

func encodeTokenWithPayload(m *Manager, payload []byte) string {
	sig := hmacSHA256(payload, m.hmacKey)
	raw := make([]byte, 0, len(payload)+1+len(sig))
	raw = append(raw, payload...)
	raw = append(raw, '|')
	raw = append(raw, sig...)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestIssueValidateRoundTrip(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	ua := UADigest("Mozilla/5.0")

	token, tokenID, err := m.Issue("192.168.1.0/24", ua, "/repo/file.iso?token=1")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if tokenID == "" {
		t.Fatal("Issue returned empty tokenID")
	}

	validatedTokenID, ok := m.Validate(token, "192.168.1.0/24", ua, "/repo/file.iso")
	if !ok {
		t.Fatal("Validate should succeed for matching bindings")
	}
	if validatedTokenID != tokenID {
		t.Fatalf("Validate tokenID mismatch: got %q want %q", validatedTokenID, tokenID)
	}
}

func TestValidateRejectsWrongPath(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	ua := UADigest("Mozilla/5.0")

	token, _, err := m.Issue("192.168.1.0/24", ua, "/repo/file.iso")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	if _, ok := m.Validate(token, "192.168.1.0/24", ua, "/repo/other.iso"); ok {
		t.Fatal("Validate should reject different path")
	}
}

func TestValidateRejectsWrongUA(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	ua := UADigest("Mozilla/5.0")

	token, _, err := m.Issue("192.168.1.0/24", ua, "/repo/file.iso")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	if _, ok := m.Validate(token, "192.168.1.0/24", UADigest("curl/8.0"), "/repo/file.iso"); ok {
		t.Fatal("Validate should reject wrong UA digest")
	}
}

func TestValidateRejectsWrongSubnetKey(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	ua := UADigest("Mozilla/5.0")

	token, _, err := m.Issue("192.168.1.0/24", ua, "/repo/file.iso")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	if _, ok := m.Validate(token, "192.168.2.0/24", ua, "/repo/file.iso"); ok {
		t.Fatal("Validate should reject wrong subnet key")
	}
}

func TestValidateRejectsExpiredCookie(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 1)
	ua := UADigest("Mozilla/5.0")

	token, _, err := m.Issue("192.168.1.0/24", ua, "/repo/file.iso")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	time.Sleep(1100 * time.Millisecond)

	if _, ok := m.Validate(token, "192.168.1.0/24", ua, "/repo/file.iso"); ok {
		t.Fatal("Validate should reject expired cookie")
	}
}

func TestTokenIDReturnedForOneTimeConsumption(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	ua := UADigest("Mozilla/5.0")
	store := &state.CookieConsumptionStore{}

	token, tokenID, err := m.Issue("192.168.1.0/24", ua, "/repo/file.iso")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	validatedTokenID, ok := m.Validate(token, "192.168.1.0/24", ua, "/repo/file.iso")
	if !ok {
		t.Fatal("Validate should succeed for first use")
	}
	if validatedTokenID != tokenID {
		t.Fatalf("Validate tokenID mismatch: got %q want %q", validatedTokenID, tokenID)
	}

	if !store.Claim(validatedTokenID) {
		t.Fatal("first Claim should succeed")
	}
	if store.Claim(validatedTokenID) {
		t.Fatal("second Claim should fail (reused tokenID detected)")
	}
}

func TestValidateRejectsCookieWithFutureIssuedAt(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	ua := UADigest("Mozilla/5.0")

	token, _, err := m.Issue("192.168.1.0/24", ua, "/repo/file.iso")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}

	sigStart := len(raw) - 32
	payload := append([]byte(nil), raw[:sigStart-1]...)

	separators := make([]int, 0, 4)
	for i := 0; i < len(payload); i++ {
		if payload[i] == '|' {
			separators = append(separators, i)
			if len(separators) == 3 {
				break
			}
		}
	}
	if len(separators) != 3 {
		t.Fatalf("unexpected token payload format")
	}

	issuedStart := separators[2] + 1
	binary.BigEndian.PutUint64(payload[issuedStart:issuedStart+8], uint64(time.Now().Add(90*time.Second).Unix()))
	newSig := hmacSHA256(payload, m.hmacKey)

	mutated := append(append(payload, '|'), newSig...)
	mutatedToken := base64.RawURLEncoding.EncodeToString(mutated)

	if _, ok := m.Validate(mutatedToken, "192.168.1.0/24", ua, "/repo/file.iso"); ok {
		t.Fatal("Validate should reject cookie with future issuedAt")
	}
}

func TestValidateRejectsMalformedBase64(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	ua := UADigest("Mozilla/5.0")

	if _, ok := m.Validate("###not-base64###", "192.168.1.0/24", ua, "/repo/file.iso"); ok {
		t.Fatal("Validate should reject malformed base64 token")
	}
}

func TestValidateRejectsTamperedHMAC(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	ua := UADigest("Mozilla/5.0")

	token, _, err := m.Issue("192.168.1.0/24", ua, "/repo/file.iso")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}

	raw[len(raw)-1] ^= 0x01
	tampered := base64.RawURLEncoding.EncodeToString(raw)

	if _, ok := m.Validate(tampered, "192.168.1.0/24", ua, "/repo/file.iso"); ok {
		t.Fatal("Validate should reject token with tampered HMAC")
	}
}

func TestNormalizePathStripsQueryStrings(t *testing.T) {
	if got := normalizePath("/repo/file.iso?download=1&range=bytes=0-100"); got != "/repo/file.iso" {
		t.Fatalf("expected normalized path /repo/file.iso, got %q", got)
	}
}

func TestNormalizePathEmptyBecomesSlash(t *testing.T) {
	if got := normalizePath(""); got != "/" {
		t.Fatalf("expected empty path to normalize to /, got %q", got)
	}
}

func TestCookieBecomesInvalidAfterManagerRestart(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	ua := UADigest("Mozilla/5.0")

	m1 := NewManager(secret, "mg", 15)
	token, _, err := m1.Issue("192.168.1.0/24", ua, "/repo/file.iso")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	m2 := NewManager(secret, "mg", 15)
	if _, ok := m2.Validate(token, "192.168.1.0/24", ua, "/repo/file.iso"); ok {
		t.Fatal("cookie issued before restart should be invalid after restart")
	}
}

func TestNewManagerDefaultsTTLWhenNonPositive(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 0)
	if got := m.TTLSeconds(); got != defaultTTLSeconds {
		t.Fatalf("expected default TTL %d, got %d", defaultTTLSeconds, got)
	}
}

func TestNewManagerFallsBackWhenTokenGenerationFails(t *testing.T) {
	setRandReadFn(t, failingReader{}.Read)

	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if len(m.hmacKey) != 64 {
		t.Fatalf("expected hmac key length 64, got %d", len(m.hmacKey))
	}
}

func TestCookieNameGetter(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mirror_guard", 15)
	if got := m.CookieName(); got != "mirror_guard" {
		t.Fatalf("CookieName mismatch: got %q want %q", got, "mirror_guard")
	}
}

func TestTTLSecondsGetter(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 42)
	if got := m.TTLSeconds(); got != 42 {
		t.Fatalf("TTLSeconds mismatch: got %d want %d", got, 42)
	}
}

func TestIssueCanonicalizesUADigestAndNormalizesPath(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	uaLower := UADigest("Mozilla/5.0")
	uaUpper := strings.ToUpper(uaLower)

	token, tokenID, err := m.Issue("192.168.1.0/24", uaUpper, "https://example.com/repo/file.iso?download=1")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if tokenID == "" {
		t.Fatal("Issue returned empty tokenID")
	}

	validatedTokenID, ok := m.Validate(token, "192.168.1.0/24", uaLower, "/repo/file.iso")
	if !ok {
		t.Fatal("Validate should accept lowercase UA and normalized path")
	}
	if validatedTokenID != tokenID {
		t.Fatalf("Validate tokenID mismatch: got %q want %q", validatedTokenID, tokenID)
	}
}

func TestValidateRejectsTooShortRawPayload(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	token := base64.RawURLEncoding.EncodeToString([]byte("short"))

	if _, ok := m.Validate(token, "subnet", "ua", "/path"); ok {
		t.Fatal("Validate should reject too-short raw payload")
	}
}

func TestValidateRejectsMissingSignatureSeparator(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	raw := append([]byte{'x'}, make([]byte, 32)...)
	token := base64.RawURLEncoding.EncodeToString(raw)

	if _, ok := m.Validate(token, "subnet", "ua", "/path"); ok {
		t.Fatal("Validate should reject missing signature separator")
	}
}

func TestValidateRejectsMissingFirstSeparatorInPayload(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	token := encodeTokenWithPayload(m, []byte("noseparators"))

	if _, ok := m.Validate(token, "subnet", "ua", "/path"); ok {
		t.Fatal("Validate should reject payload missing first separator")
	}
}

func TestValidateRejectsMissingSecondSeparatorInPayload(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	token := encodeTokenWithPayload(m, []byte("subnet|uaonly"))

	if _, ok := m.Validate(token, "subnet", "ua", "/path"); ok {
		t.Fatal("Validate should reject payload missing second separator")
	}
}

func TestValidateRejectsMissingThirdSeparatorInPayload(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	token := encodeTokenWithPayload(m, []byte("subnet|ua|pathonly"))

	if _, ok := m.Validate(token, "subnet", "ua", "/path"); ok {
		t.Fatal("Validate should reject payload missing third separator")
	}
}

func TestValidateRejectsInvalidIssuedAtDelimiterOrLength(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	token := encodeTokenWithPayload(m, []byte("subnet|ua|path|"))

	if _, ok := m.Validate(token, "subnet", "ua", "/path"); ok {
		t.Fatal("Validate should reject invalid issuedAt segment")
	}
}

func TestValidateRejectsInvalidExpiresAtDelimiterOrLength(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	issued := make([]byte, 8)
	payload := append([]byte("subnet|ua|path|"), issued...)
	payload = append(payload, '|')
	token := encodeTokenWithPayload(m, payload)

	if _, ok := m.Validate(token, "subnet", "ua", "/path"); ok {
		t.Fatal("Validate should reject invalid expiresAt segment")
	}
}

func TestValidateRejectsEmptyTokenID(t *testing.T) {
	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	now := time.Now().Unix()
	issued := make([]byte, 8)
	expires := make([]byte, 8)
	binary.BigEndian.PutUint64(issued, uint64(now-1))
	binary.BigEndian.PutUint64(expires, uint64(now+60))

	payload := append([]byte("subnet|ua|path|"), issued...)
	payload = append(payload, '|')
	payload = append(payload, expires...)
	payload = append(payload, '|')
	token := encodeTokenWithPayload(m, payload)

	if _, ok := m.Validate(token, "subnet", "ua", "path"); ok {
		t.Fatal("Validate should reject empty tokenID")
	}
}

func TestGenerateTokenIDSuccess(t *testing.T) {
	tokenID, err := generateTokenID()
	if err != nil {
		t.Fatalf("generateTokenID returned error: %v", err)
	}
	if len(tokenID) != 32 {
		t.Fatalf("expected tokenID length 32, got %d", len(tokenID))
	}
}

func TestGenerateTokenIDError(t *testing.T) {
	setRandReadFn(t, failingReader{}.Read)

	tokenID, err := generateTokenID()
	if err == nil {
		t.Fatal("expected generateTokenID to fail")
	}
	if tokenID != "" {
		t.Fatalf("expected empty tokenID on error, got %q", tokenID)
	}
}

func TestIssueReturnsErrorWhenTokenIDGenerationFails(t *testing.T) {
	setRandReadFn(t, failingReader{}.Read)

	m := NewManager("0123456789abcdef0123456789abcdef", "mg", 15)
	token, tokenID, err := m.Issue("192.168.1.0/24", UADigest("Mozilla/5.0"), "/repo/file.iso")
	if err == nil {
		t.Fatal("expected Issue to fail when token generation fails")
	}
	if token != "" || tokenID != "" {
		t.Fatalf("expected empty token and tokenID, got token=%q tokenID=%q", token, tokenID)
	}
}

func TestNormalizePathURLWithPath(t *testing.T) {
	if got := normalizePath("https://example.com/a/b/c?x=1"); got != "/a/b/c" {
		t.Fatalf("expected /a/b/c, got %q", got)
	}
}

func TestNormalizePathQueryOnlyInput(t *testing.T) {
	if got := normalizePath("?download=1"); got != "/" {
		t.Fatalf("expected / for query-only input, got %q", got)
	}
}

func TestNormalizePathRawPathWithoutQuery(t *testing.T) {
	if got := normalizePath("/repo/file.iso"); got != "/repo/file.iso" {
		t.Fatalf("expected unchanged raw path, got %q", got)
	}
}

func TestNormalizePathFallbackTrimsQueryWhenURLParseFails(t *testing.T) {
	if got := normalizePath("%zz?download=1"); got != "%zz" {
		t.Fatalf("expected fallback trim to %%zz, got %q", got)
	}
}

func TestNormalizePathReturnsInputWhenNoPathAndNoQuery(t *testing.T) {
	input := "https://example.com"
	if got := normalizePath(input); got != input {
		t.Fatalf("expected input %q, got %q", input, got)
	}
}

func TestIndexByteFoundAndNotFoundWithOffset(t *testing.T) {
	b := []byte("a|b|c")

	if got := indexByte(b, '|', 0); got != 1 {
		t.Fatalf("expected first separator at index 1, got %d", got)
	}
	if got := indexByte(b, '|', 2); got != 3 {
		t.Fatalf("expected second separator at index 3 from offset 2, got %d", got)
	}
	if got := indexByte(b, '|', 4); got != -1 {
		t.Fatalf("expected -1 when separator not found, got %d", got)
	}
}
