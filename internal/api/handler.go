// Package api exposes the fingerprint engine over HTTP.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/twolate0101/hw_demo/internal/fingerprint"
	"github.com/twolate0101/hw_demo/internal/model"
)

const (
	DefaultMaxBodyBytes = int64(4 << 20)
	DefaultMaxBatchSize = 10_000
)

// Handler serves the health and fingerprint endpoints.
type Handler struct {
	engine       fingerprint.Engine
	maxBodyBytes int64
	maxBatchSize int
	logger       *slog.Logger
}

// NewHandler returns a production-ready HTTP handler with conservative limits.
func NewHandler(engine fingerprint.Engine, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &Handler{
		engine:       engine,
		maxBodyBytes: DefaultMaxBodyBytes,
		maxBatchSize: DefaultMaxBatchSize,
		logger:       logger,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("POST /fingerprint", h.fingerprint)
	return h.recoverPanic(mux)
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	if h.engine == nil {
		writeError(w, http.StatusServiceUnavailable, "fingerprint engine is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) fingerprint(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		writeError(w, http.StatusServiceUnavailable, "fingerprint engine is unavailable")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	var inputs []model.ScanInput
	if err := decoder.Decode(&inputs); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusBadRequest, "request body is too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return
	}
	if inputs == nil {
		writeError(w, http.StatusBadRequest, "request body must be a JSON array")
		return
	}
	if err := requireEOF(decoder); err != nil {
		writeError(w, http.StatusBadRequest, "request body must contain one JSON value")
		return
	}
	if len(inputs) > h.maxBatchSize {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("batch exceeds maximum of %d items", h.maxBatchSize))
		return
	}

	results := make([]model.FingerprintResult, len(inputs))
	for i, input := range inputs {
		results[i] = h.engine.Identify(input)
	}
	writeJSON(w, http.StatusOK, results)
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("additional JSON value")
	}
	return err
}

func (h *Handler) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				h.logger.Error("recovered HTTP handler panic", "panic", recovered, "method", r.Method, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
