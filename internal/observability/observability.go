package observability

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

var (
	initMu      sync.Mutex
	initialized bool

	metricsRegistry *prometheus.Registry
	authRequests    *prometheus.CounterVec
	httpRequests    *prometheus.CounterVec
	httpInFlight    *prometheus.GaugeVec
	handlerDuration *prometheus.HistogramVec
	stateStoreSize  *prometheus.GaugeVec
	buildInfo       *prometheus.GaugeVec
	nonceReplay     prometheus.Counter
	cookieReplay    prometheus.Counter

	tracerProvider *sdktrace.TracerProvider
)

func Init(serviceName, version string) {
	initMu.Lock()
	defer initMu.Unlock()
	initLocked(serviceName, version)
}

func initLocked(serviceName, version string) {
	if initialized {
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	metricsRegistry = prometheus.NewRegistry()
	authRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_requests_total",
		Help: "Total number of auth decisions by action, client class, and route family.",
	}, []string{"action", "client_class", "route_family"})
	handlerDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "auth_handler_duration_seconds",
		Help:    "Auth handler latency in seconds by handler and action.",
		Buckets: prometheus.DefBuckets,
	}, []string{"handler", "action"})
	httpRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_http_requests_total",
		Help: "Total internal API requests by handler, method, and status.",
	}, []string{"handler", "method", "status"})
	httpInFlight = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "auth_http_requests_in_flight",
		Help: "Current internal API requests by handler.",
	}, []string{"handler"})
	stateStoreSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "auth_state_store_size",
		Help: "Current size of in-memory state stores.",
	}, []string{"store_type"})
	buildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "auth_build_info",
		Help: "Build information for the auth gateway.",
	}, []string{"service", "version"})
	nonceReplay = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "auth_nonce_replay_total",
		Help: "Total number of replayed PoW nonces.",
	})
	cookieReplay = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "auth_cookie_replay_total",
		Help: "Total number of replayed auth cookies.",
	})

	metricsRegistry.MustRegister(
		authRequests,
		httpRequests,
		httpInFlight,
		handlerDuration,
		stateStoreSize,
		buildInfo,
		nonceReplay,
		cookieReplay,
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)
	buildInfo.WithLabelValues(serviceName, version).Set(1)
	stateStoreSize.WithLabelValues("quota").Set(0)
	stateStoreSize.WithLabelValues("nonce").Set(0)
	stateStoreSize.WithLabelValues("cookie").Set(0)

	res := resource.NewWithAttributes(
		"",
		attribute.String("service.name", serviceName),
		attribute.String("service.version", version),
	)
	tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(1.0))),
	)
	otel.SetTracerProvider(tracerProvider)

	initialized = true
}

func MetricsHandler() http.Handler {
	initMu.Lock()
	defer initMu.Unlock()
	initLocked("mirror-guard-auth-gateway", "dev")
	return promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

// InstrumentHandler records bounded-label request, concurrency, and latency
// metrics. Handler names are fixed at route registration time and status is a
// three-digit integer, so these metrics cannot grow with attacker input.
func InstrumentHandler(name string, next http.Handler) http.Handler {
	Init("mirror-guard-auth-gateway", "dev")
	name = normalizeLabel(name, "unknown")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		httpInFlight.WithLabelValues(name).Inc()
		defer httpInFlight.WithLabelValues(name).Dec()

		wrapped := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(wrapped, r)
		if wrapped.status == 0 {
			wrapped.status = http.StatusOK
		}
		status := strconv.Itoa(wrapped.status)
		httpRequests.WithLabelValues(name, r.Method, status).Inc()
		handlerDuration.WithLabelValues(name, status).Observe(time.Since(started).Seconds())
	})
}

func RecordAuthDecision(action, clientClass, routeFamily string) {
	initMu.Lock()
	defer initMu.Unlock()
	initLocked("mirror-guard-auth-gateway", "dev")
	authRequests.WithLabelValues(normalizeLabel(action, "unknown"), normalizeLabel(clientClass, "unknown"), normalizeLabel(routeFamily, "unknown")).Inc()
}

func RecordHandlerLatency(handler, action string, duration time.Duration) {
	initMu.Lock()
	defer initMu.Unlock()
	initLocked("mirror-guard-auth-gateway", "dev")
	handlerDuration.WithLabelValues(normalizeLabel(handler, "unknown"), normalizeLabel(action, "unknown")).Observe(duration.Seconds())
}

func RecordNonceReplay() {
	initMu.Lock()
	defer initMu.Unlock()
	initLocked("mirror-guard-auth-gateway", "dev")
	nonceReplay.Inc()
}

func RecordCookieReplay() {
	initMu.Lock()
	defer initMu.Unlock()
	initLocked("mirror-guard-auth-gateway", "dev")
	cookieReplay.Inc()
}

func SetStateStoreSize(storeType string, size int) {
	initMu.Lock()
	defer initMu.Unlock()
	initLocked("mirror-guard-auth-gateway", "dev")
	stateStoreSize.WithLabelValues(normalizeLabel(storeType, "unknown")).Set(float64(size))
}

func LogAuthDecision(
	ctx context.Context,
	requestID string,
	clientIP string,
	subnetKey string,
	clientClass string,
	routeFamily string,
	action string,
	decisionReason string,
	difficulty int,
	fallbackMode bool,
) {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		requestID = "unknown"
	}
	slog.InfoContext(ctx, "auth decision",
		"request_id", requestID,
		"client_ip", clientIP,
		"subnet_key", subnetKey,
		"client_class", clientClass,
		"route_family", routeFamily,
		"action", action,
		"decision_reason", decisionReason,
		"difficulty", difficulty,
		"fallback_mode", fallbackMode,
	)
}

func normalizeLabel(value, fallback string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return fallback
	}
	return v
}
