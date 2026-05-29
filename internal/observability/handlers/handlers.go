package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/runtime/status"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewMetricsHandler returns an http.Handler for Prometheus scraping.
func NewMetricsHandler() http.Handler {
	return promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	})
}

// StatuszHandler returns the current system status in JSON format.
func StatuszHandler(collector *status.Collector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res, err := collector.Collect()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	}
}

// HealthzHandler returns 200 OK if the process is running.
func HealthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// ReadyzHandler returns 200 OK if the process is ready to serve.
func ReadyzHandler(w http.ResponseWriter, r *http.Request) {
	// For a daemon, ready means it has initialized its stores and is starting loops.
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("READY"))
}
