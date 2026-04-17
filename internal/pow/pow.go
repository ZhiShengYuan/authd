package pow

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

type Challenge struct {
	Prefix     string `json:"prefix"`
	Difficulty int    `json:"difficulty"`
	NonceTTL   int    `json:"nonce_ttl_seconds"`
}

type PrefixData struct {
	TargetURI string
	SubnetKey string
	Timestamp int64
	Salt      []byte
}

func Verify(prefix, nonce string, difficulty int) bool {
	if difficulty <= 0 {
		return true
	}

	h := sha256.Sum256([]byte(prefix + nonce))
	hexHash := hex.EncodeToString(h[:])
	if difficulty > len(hexHash) {
		return false
	}

	for i := 0; i < difficulty; i++ {
		if hexHash[i] != '0' {
			return false
		}
	}

	return true
}

func GeneratePrefix(secret []byte, targetURI, subnetKey string, timestamp int64, salt []byte) string {
	ts := strconv.FormatInt(timestamp, 10)
	saltHex := hex.EncodeToString(salt)
	msg := targetURI + "|" + subnetKey + "|" + ts + "|" + saltHex

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(msg))
	sig := mac.Sum(nil)

	return msg + "|" + hex.EncodeToString(sig)
}

func VerifyPrefixIntegrity(prefix string, secret []byte, prefixTTLSeconds int) (PrefixData, error) {
	parts := strings.Split(prefix, "|")
	if len(parts) != 5 {
		return PrefixData{}, errors.New("invalid prefix format")
	}

	targetURI := parts[0]
	subnetKey := parts[1]
	timestampStr := parts[2]
	saltHex := parts[3]
	providedSigHex := parts[4]

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return PrefixData{}, fmt.Errorf("invalid timestamp: %w", err)
	}

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return PrefixData{}, fmt.Errorf("invalid salt hex: %w", err)
	}

	providedSig, err := hex.DecodeString(providedSigHex)
	if err != nil {
		return PrefixData{}, fmt.Errorf("invalid signature hex: %w", err)
	}
	if len(providedSig) != 32 {
		return PrefixData{}, errors.New("invalid signature length")
	}

	msg := targetURI + "|" + subnetKey + "|" + timestampStr + "|" + saltHex
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(msg))
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(expectedSig, providedSig) {
		return PrefixData{}, errors.New("signature mismatch")
	}

	now := time.Now().Unix()
	if timestamp > now {
		return PrefixData{}, errors.New("timestamp is in the future")
	}
	if prefixTTLSeconds >= 0 && now-timestamp > int64(prefixTTLSeconds) {
		return PrefixData{}, errors.New("prefix expired")
	}

	return PrefixData{
		TargetURI: targetURI,
		SubnetKey: subnetKey,
		Timestamp: timestamp,
		Salt:      salt,
	}, nil
}

func Difficulty(requestsInWindow int64, minDifficulty, maxDifficulty int) int {
	if minDifficulty > maxDifficulty {
		minDifficulty = maxDifficulty
	}

	if requestsInWindow < 0 {
		requestsInWindow = 0
	}

	value := minDifficulty + int(math.Floor(math.Log2(float64(requestsInWindow+1))))
	if value > maxDifficulty {
		return maxDifficulty
	}
	return value
}
