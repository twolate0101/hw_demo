package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/twolate0101/hw_demo/internal/model"
)

type fakeEngine struct{}

func (fakeEngine) Identify(input model.ScanInput) model.FingerprintResult {
	protocol := "unknown"
	if strings.HasPrefix(input.Banner, "SSH-") {
		protocol = "SSH"
	}
	return model.FingerprintResult{IP: input.IP, Port: input.Port, Protocol: protocol}
}

func TestHealth(t *testing.T) {
	handler := NewHandler(fakeEngine{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
}

func TestFingerprintPreservesOrderAndUnknown(t *testing.T) {
	handler := NewHandler(fakeEngine{}, nil)
	body := `[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-test"},{"ip":"1.2.3.5","port":9999,"banner":"mystery"}]`
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var results []model.FingerprintResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].IP != "1.2.3.4" || results[0].Protocol != "SSH" || results[1].Protocol != "unknown" {
		t.Fatalf("unexpected results: %#v", results)
	}
}

func TestFingerprintRejectsInvalidInput(t *testing.T) {
	handler := NewHandler(fakeEngine{}, nil)
	tests := []struct {
		name string
		body string
	}{
		{"invalid JSON", `[`},
		{"not an array", `{}`},
		{"trailing value", `[] {}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(tt.body)))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestFingerprintRejectsOversizedBody(t *testing.T) {
	handler := NewHandler(fakeEngine{}, nil)
	body := bytes.Repeat([]byte(" "), int(DefaultMaxBodyBytes)+1)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/fingerprint", bytes.NewReader(body)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	handler := NewHandler(fakeEngine{}, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/fingerprint", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
}
