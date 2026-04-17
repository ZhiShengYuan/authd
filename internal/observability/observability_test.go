package observability

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func metricValue(t *testing.T, metrics, metricLine string) float64 {
	t.Helper()
	for _, line := range strings.Split(metrics, "\n") {
		if strings.HasPrefix(line, metricLine+" ") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				t.Fatalf("unexpected metric line format %q", line)
			}
			v, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				t.Fatalf("parse metric value from %q: %v", line, err)
			}
			return v
		}
	}
	t.Fatalf("metric line %q not found", metricLine)
	return 0
}

func scrapeMetrics(t *testing.T) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(rr, req)
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

func TestMetricsHandlerReturnsPrometheusTextFormat(t *testing.T) {
	Init("test-service", "test-version")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Fatalf("expected Prometheus text format, got %q", contentType)
	}
}

func TestRecordAuthDecisionIncrementsCounter(t *testing.T) {
	Init("test-service", "test-version")
	RecordAuthDecision("allow", "browser", "protected")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(rr, req)

	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	metrics := string(body)
	if !strings.Contains(metrics, `auth_requests_total{action="allow",client_class="browser",route_family="protected"}`) {
		t.Fatalf("expected auth_requests_total sample for allow/browser/protected")
	}
}

func TestRecordHandlerLatencyRecordsObservation(t *testing.T) {
	Init("test-service", "test-version")
	RecordHandlerLatency("pipeline", "allow", 45*time.Millisecond)

	metrics := scrapeMetrics(t)
	if !strings.Contains(metrics, `auth_handler_duration_seconds_count{action="allow",handler="pipeline"}`) {
		t.Fatalf("expected auth_handler_duration_seconds_count sample for pipeline/allow")
	}
}

func TestRecordReplayCountersAndSetStateStoreSize(t *testing.T) {
	Init("test-service", "test-version")

	before := scrapeMetrics(t)
	nonceBefore := metricValue(t, before, "auth_nonce_replay_total")
	cookieBefore := metricValue(t, before, "auth_cookie_replay_total")

	RecordNonceReplay()
	RecordCookieReplay()
	SetStateStoreSize("quota", 7)
	SetStateStoreSize("", 5)

	after := scrapeMetrics(t)
	nonceAfter := metricValue(t, after, "auth_nonce_replay_total")
	cookieAfter := metricValue(t, after, "auth_cookie_replay_total")
	quotaSize := metricValue(t, after, `auth_state_store_size{store_type="quota"}`)
	unknownSize := metricValue(t, after, `auth_state_store_size{store_type="unknown"}`)

	if nonceAfter != nonceBefore+1 {
		t.Fatalf("nonce replay counter delta = %v, want 1", nonceAfter-nonceBefore)
	}
	if cookieAfter != cookieBefore+1 {
		t.Fatalf("cookie replay counter delta = %v, want 1", cookieAfter-cookieBefore)
	}
	if quotaSize != 7 {
		t.Fatalf("quota gauge = %v, want 7", quotaSize)
	}
	if unknownSize != 5 {
		t.Fatalf("unknown gauge = %v, want 5", unknownSize)
	}
}

func TestLogAuthDecisionHandlesFieldCombinations(t *testing.T) {
	var buf bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() {
		slog.SetDefault(original)
	})

	LogAuthDecision(context.Background(), "   ", "203.0.113.7", "subnet-a", "browser", "protected", "challenge", "risk", 5, true)
	LogAuthDecision(context.Background(), "req-123", "", "", "", "", "allow", "", 0, false)

	logs := buf.String()
	if !strings.Contains(logs, "request_id=unknown") {
		t.Fatalf("expected unknown request_id in logs, got %q", logs)
	}
	if !strings.Contains(logs, "request_id=req-123") {
		t.Fatalf("expected explicit request_id in logs, got %q", logs)
	}
	if !strings.Contains(logs, "fallback_mode=true") || !strings.Contains(logs, "fallback_mode=false") {
		t.Fatalf("expected fallback mode values in logs, got %q", logs)
	}
}
