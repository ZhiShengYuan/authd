package cookie

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultTTLSeconds = 15

var randReadFn = rand.Read

type Manager struct {
	cookieName string
	ttlSeconds int
	hmacKey    []byte
}

func NewManager(globalSecret string, cookieName string, ttlSeconds int) *Manager {
	if ttlSeconds <= 0 {
		ttlSeconds = defaultTTLSeconds
	}

	runtimeTokenID, err := generateTokenID()
	if err != nil {
		runtimeTokenID = strconv.FormatInt(time.Now().UnixNano(), 10)
	}

	derived := sha512.Sum512([]byte(globalSecret + "|" + runtimeTokenID))

	return &Manager{
		cookieName: cookieName,
		ttlSeconds: ttlSeconds,
		hmacKey:    derived[:64],
	}
}

func (m *Manager) CookieName() string {
	return m.cookieName
}

func (m *Manager) TTLSeconds() int {
	return m.ttlSeconds
}

func UADigest(userAgent string) string {
	sum := sha256.Sum256([]byte(userAgent))
	return hex.EncodeToString(sum[:16])
}

func (m *Manager) Issue(subnetKey, uaDigest, path string) (token string, tokenID string, err error) {
	now := time.Now().Unix()
	expiresAt := now + int64(m.ttlSeconds)

	normalizedPath := normalizePath(path)
	canonicalUADigest := strings.ToLower(uaDigest)

	tokenID, err = generateTokenID()
	if err != nil {
		return "", "", err
	}

	payload := make([]byte, 0, len(subnetKey)+len(canonicalUADigest)+len(normalizedPath)+len(tokenID)+32)
	payload = append(payload, []byte(subnetKey)...)
	payload = append(payload, '|')
	payload = append(payload, []byte(canonicalUADigest)...)
	payload = append(payload, '|')
	payload = append(payload, []byte(normalizedPath)...)
	payload = append(payload, '|')

	var issuedAtBytes [8]byte
	binary.BigEndian.PutUint64(issuedAtBytes[:], uint64(now))
	payload = append(payload, issuedAtBytes[:]...)
	payload = append(payload, '|')

	var expiresAtBytes [8]byte
	binary.BigEndian.PutUint64(expiresAtBytes[:], uint64(expiresAt))
	payload = append(payload, expiresAtBytes[:]...)
	payload = append(payload, '|')
	payload = append(payload, []byte(tokenID)...)

	sig := hmacSHA256(payload, m.hmacKey)
	raw := make([]byte, 0, len(payload)+1+len(sig))
	raw = append(raw, payload...)
	raw = append(raw, '|')
	raw = append(raw, sig...)

	return base64.RawURLEncoding.EncodeToString(raw), tokenID, nil
}

func (m *Manager) Validate(token string, subnetKey, uaDigest, path string) (tokenID string, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", false
	}

	if len(raw) < 32+1 {
		return "", false
	}

	sigStart := len(raw) - 32
	if sigStart <= 0 || raw[sigStart-1] != '|' {
		return "", false
	}

	payload := raw[:sigStart-1]
	providedSig := raw[sigStart:]
	computedSig := hmacSHA256(payload, m.hmacKey)
	if !hmac.Equal(providedSig, computedSig) {
		return "", false
	}

	first := indexByte(payload, '|', 0)
	if first < 0 {
		return "", false
	}
	second := indexByte(payload, '|', first+1)
	if second < 0 {
		return "", false
	}
	third := indexByte(payload, '|', second+1)
	if third < 0 {
		return "", false
	}

	parsedSubnet := string(payload[:first])
	parsedUADigest := strings.ToLower(string(payload[first+1 : second]))
	parsedPath := string(payload[second+1 : third])

	issuedStart := third + 1
	if issuedStart+8 >= len(payload) || payload[issuedStart+8] != '|' {
		return "", false
	}
	issuedAt := int64(binary.BigEndian.Uint64(payload[issuedStart : issuedStart+8]))

	expiresStart := issuedStart + 9
	if expiresStart+8 >= len(payload) || payload[expiresStart+8] != '|' {
		return "", false
	}
	expiresAt := int64(binary.BigEndian.Uint64(payload[expiresStart : expiresStart+8]))

	parsedTokenID := string(payload[expiresStart+9:])
	if parsedTokenID == "" {
		return "", false
	}

	now := time.Now().Unix()
	if issuedAt > now || now >= expiresAt {
		return "", false
	}

	if parsedSubnet != subnetKey {
		return "", false
	}
	if parsedUADigest != strings.ToLower(uaDigest) {
		return "", false
	}
	if parsedPath != normalizePath(path) {
		return "", false
	}

	return parsedTokenID, true
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

func normalizePath(input string) string {
	if input == "" {
		return "/"
	}

	if u, err := url.Parse(input); err == nil {
		if u.Path != "" {
			return u.Path
		}
	}

	if idx := strings.IndexByte(input, '?'); idx >= 0 {
		if idx == 0 {
			return "/"
		}
		return input[:idx]
	}

	return input
}

func indexByte(b []byte, c byte, start int) int {
	for i := start; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}
