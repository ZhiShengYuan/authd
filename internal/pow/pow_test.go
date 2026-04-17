package pow

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func findNonce(t *testing.T, prefix string, difficulty int) string {
	t.Helper()
	for i := 0; i < 2_000_000; i++ {
		nonce := fmt.Sprintf("%d", i)
		if Verify(prefix, nonce, difficulty) {
			return nonce
		}
	}
	t.Fatalf("failed to find nonce for prefix=%q difficulty=%d", prefix, difficulty)
	return ""
}

func TestVerifyValidPoW(t *testing.T) {
	prefix := "test"
	nonce := findNonce(t, prefix, 4)
	if !Verify(prefix, nonce, 4) {
		t.Fatal("Verify should accept valid nonce")
	}
}

func TestVerifyInsufficientDifficulty(t *testing.T) {
	prefix := "test"
	nonce := findNonce(t, prefix, 2)
	if Verify(prefix, nonce, 4) {
		t.Fatal("Verify should reject nonce for higher difficulty")
	}
}

func TestVerifyDifficultyZero(t *testing.T) {
	if !Verify("anything", "anything", 0) {
		t.Fatal("Verify should pass immediately for difficulty=0")
	}
}

func TestVerifyDifficultyZeroAlwaysTrueRegardlessOfNonce(t *testing.T) {
	prefix := "hard-prefix"
	nonces := []string{"", "0", "abc", "!@#-non-standard"}
	for _, nonce := range nonces {
		if !Verify(prefix, nonce, 0) {
			t.Fatalf("expected difficulty=0 to always verify, nonce=%q", nonce)
		}
	}
}

func TestVerifyDifficultyExceedsHashLengthReturnsFalse(t *testing.T) {
	if Verify("prefix", "nonce", 65) {
		t.Fatal("expected verify false when difficulty exceeds sha256 hex length")
	}
}

func TestGeneratePrefixDeterministic(t *testing.T) {
	secret := []byte("super-secret")
	timestamp := int64(1_700_000_000)
	salt := []byte{0x01, 0x02, 0x03, 0x04}

	p1 := GeneratePrefix(secret, "/repo/file.iso", "192.168.1.0/24", timestamp, salt)
	p2 := GeneratePrefix(secret, "/repo/file.iso", "192.168.1.0/24", timestamp, salt)

	if p1 != p2 {
		t.Fatalf("GeneratePrefix should be deterministic, got %q != %q", p1, p2)
	}
}

func TestVerifyPrefixIntegrityValid(t *testing.T) {
	secret := []byte("super-secret")
	timestamp := time.Now().Unix()
	salt := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	prefix := GeneratePrefix(secret, "/repo/file.iso", "192.168.1.0/24", timestamp, salt)

	data, err := VerifyPrefixIntegrity(prefix, secret, 30)
	if err != nil {
		t.Fatalf("VerifyPrefixIntegrity returned error: %v", err)
	}

	if data.TargetURI != "/repo/file.iso" || data.SubnetKey != "192.168.1.0/24" || data.Timestamp != timestamp {
		t.Fatalf("unexpected parsed data: %+v", data)
	}
}

func TestVerifyPrefixIntegrityTampered(t *testing.T) {
	secret := []byte("super-secret")
	timestamp := time.Now().Unix()
	salt := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	prefix := GeneratePrefix(secret, "/repo/file.iso", "192.168.1.0/24", timestamp, salt)

	tampered := strings.Replace(prefix, "/repo/file.iso", "/repo/other.iso", 1)
	if _, err := VerifyPrefixIntegrity(tampered, secret, 30); err == nil {
		t.Fatal("VerifyPrefixIntegrity should fail for tampered prefix")
	}
}

func TestVerifyPrefixIntegrityRejectsWrongSubnetKeySecret(t *testing.T) {
	correctSecret := []byte("super-secret-a")
	wrongSecret := []byte("super-secret-b")
	prefix := GeneratePrefix(correctSecret, "/repo/file.iso", "192.168.1.0/24", time.Now().Unix(), []byte{0x10, 0x20, 0x30, 0x40})

	if _, err := VerifyPrefixIntegrity(prefix, wrongSecret, 30); err == nil {
		t.Fatal("expected VerifyPrefixIntegrity to reject prefix verified with wrong subnet-bound key")
	}
}

func TestVerifyPrefixIntegrityFutureTimestampRejected(t *testing.T) {
	secret := []byte("super-secret")
	future := time.Now().Add(5 * time.Second).Unix()
	prefix := GeneratePrefix(secret, "/repo/file.iso", "192.168.1.0/24", future, []byte{0xaa, 0xbb, 0xcc, 0xdd})

	if _, err := VerifyPrefixIntegrity(prefix, secret, 30); err == nil {
		t.Fatal("expected VerifyPrefixIntegrity to reject future timestamp")
	}
}

func TestVerifyPrefixIntegrityExpired(t *testing.T) {
	secret := []byte("super-secret")
	timestamp := time.Now().Add(-2 * time.Second).Unix()
	salt := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	prefix := GeneratePrefix(secret, "/repo/file.iso", "192.168.1.0/24", timestamp, salt)

	if _, err := VerifyPrefixIntegrity(prefix, secret, 1); err == nil {
		t.Fatal("VerifyPrefixIntegrity should fail for expired prefix")
	}
}

func TestVerifyPrefixIntegrityInvalidPrefixFormat(t *testing.T) {
	secret := []byte("super-secret")
	if _, err := VerifyPrefixIntegrity("/repo/file.iso|192.168.1.0/24|1700000000|aabbccdd", secret, 30); err == nil || err.Error() != "invalid prefix format" {
		t.Fatalf("expected invalid prefix format error, got: %v", err)
	}
}

func TestVerifyPrefixIntegrityInvalidTimestampParse(t *testing.T) {
	secret := []byte("super-secret")
	prefix := "/repo/file.iso|192.168.1.0/24|not-a-timestamp|aabbccdd|" + strings.Repeat("0", 64)

	if _, err := VerifyPrefixIntegrity(prefix, secret, 30); err == nil || !strings.HasPrefix(err.Error(), "invalid timestamp:") {
		t.Fatalf("expected invalid timestamp prefix, got: %v", err)
	}
}

func TestVerifyPrefixIntegrityInvalidSaltHex(t *testing.T) {
	secret := []byte("super-secret")
	prefix := "/repo/file.iso|192.168.1.0/24|1700000000|zz-not-hex|" + strings.Repeat("0", 64)

	if _, err := VerifyPrefixIntegrity(prefix, secret, 30); err == nil || !strings.HasPrefix(err.Error(), "invalid salt hex:") {
		t.Fatalf("expected invalid salt hex prefix, got: %v", err)
	}
}

func TestVerifyPrefixIntegrityInvalidSignatureHex(t *testing.T) {
	secret := []byte("super-secret")
	prefix := "/repo/file.iso|192.168.1.0/24|1700000000|aabbccdd|not-hex-signature"

	if _, err := VerifyPrefixIntegrity(prefix, secret, 30); err == nil || !strings.HasPrefix(err.Error(), "invalid signature hex:") {
		t.Fatalf("expected invalid signature hex prefix, got: %v", err)
	}
}

func TestVerifyPrefixIntegrityInvalidSignatureLength(t *testing.T) {
	secret := []byte("super-secret")
	prefix := "/repo/file.iso|192.168.1.0/24|1700000000|aabbccdd|abcd"

	if _, err := VerifyPrefixIntegrity(prefix, secret, 30); err == nil || err.Error() != "invalid signature length" {
		t.Fatalf("expected invalid signature length error, got: %v", err)
	}
}

func TestVerifyPrefixIntegrityTTLDiabledAllowsOldValidPrefix(t *testing.T) {
	secret := []byte("super-secret")
	timestamp := int64(1_600_000_000)
	salt := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	prefix := GeneratePrefix(secret, "/repo/file.iso", "192.168.1.0/24", timestamp, salt)

	data, err := VerifyPrefixIntegrity(prefix, secret, -1)
	if err != nil {
		t.Fatalf("expected old-but-valid prefix to pass when TTL disabled: %v", err)
	}
	if data.Timestamp != timestamp {
		t.Fatalf("unexpected timestamp parsed: got %d, want %d", data.Timestamp, timestamp)
	}
}

func TestDifficulty(t *testing.T) {
	min := 4
	max := 10

	if got := Difficulty(0, min, max); got != min {
		t.Fatalf("Difficulty(0) = %d, want %d", got, min)
	}
	if got := Difficulty(7, min, max); got != min+3 {
		t.Fatalf("Difficulty(7) = %d, want %d", got, min+3)
	}
	if got := Difficulty(1<<20, min, max); got != max {
		t.Fatalf("Difficulty cap failed: got %d, want %d", got, max)
	}
}

func TestDifficultyMinGreaterThanMax(t *testing.T) {
	if got := Difficulty(8, 7, 4); got != 4 {
		t.Fatalf("Difficulty should clamp min to max when min>max, got %d want %d", got, 4)
	}
}

func TestDifficultyNegativeRequestsInWindow(t *testing.T) {
	if got := Difficulty(-10, 4, 10); got != 4 {
		t.Fatalf("Difficulty should treat negative requests as zero, got %d want %d", got, 4)
	}
}

func TestDifficultyNonCappedNormalReturn(t *testing.T) {
	if got := Difficulty(3, 4, 10); got != 6 {
		t.Fatalf("Difficulty normal return mismatch: got %d want %d", got, 6)
	}
}
