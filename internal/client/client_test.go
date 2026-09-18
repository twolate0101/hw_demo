package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/twolate0101/hw_demo/internal/model"
)

func TestFingerprint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/fingerprint" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var inputs []model.ScanInput
		if err := json.NewDecoder(r.Body).Decode(&inputs); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode([]model.FingerprintResult{{IP: inputs[0].IP, Port: inputs[0].Port, Protocol: "SSH"}})
	}))
	defer server.Close()

	results, err := New(server.URL+"/", server.Client()).Fingerprint(context.Background(), []model.ScanInput{{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-test"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Protocol != "SSH" {
		t.Fatalf("unexpected results: %#v", results)
	}
}

func TestFingerprintServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad input", http.StatusBadRequest)
	}))
	defer server.Close()
	_, err := New(server.URL, server.Client()).Fingerprint(context.Background(), []model.ScanInput{})
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("error = %v, want status error", err)
	}
}

func TestDecodeInputs(t *testing.T) {
	inputs, err := DecodeInputs(strings.NewReader(`[{"ip":"127.0.0.1","port":80,"banner":"HTTP/1.1 200 OK"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 1 || inputs[0].Port != 80 {
		t.Fatalf("unexpected inputs: %#v", inputs)
	}
	for _, invalid := range []string{`{}`, `null`, `[] []`} {
		if _, err := DecodeInputs(strings.NewReader(invalid)); err == nil {
			t.Errorf("DecodeInputs(%q) succeeded, want error", invalid)
		}
	}
}
