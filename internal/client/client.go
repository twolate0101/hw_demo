// Package client calls the fingerprint HTTP API.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/twolate0101/hw_demo/internal/model"
)

const maxResponseBytes = int64(16 << 20)

// Client is a small HTTP client for the fingerprint service.
type Client struct {
	baseURL string
	http    *http.Client
}

// New constructs a Client. baseURL may optionally end with a slash.
func New(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

// Fingerprint submits inputs and returns results in server order.
func (c *Client) Fingerprint(ctx context.Context, inputs []model.ScanInput) ([]model.FingerprintResult, error) {
	payload, err := json.Marshal(inputs)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/fingerprint", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call fingerprint server: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(body)) > maxResponseBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var results []model.FingerprintResult
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return results, nil
}

// DecodeInputs decodes a standard JSON array from a reader.
func DecodeInputs(r io.Reader) ([]model.ScanInput, error) {
	var inputs []model.ScanInput
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&inputs); err != nil {
		return nil, fmt.Errorf("decode input file: %w", err)
	}
	if inputs == nil {
		return nil, fmt.Errorf("decode input file: root value must be an array")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode input file: multiple JSON values")
		}
		return nil, fmt.Errorf("decode input file: trailing data: %w", err)
	}
	return inputs, nil
}
