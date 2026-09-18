// Package fingerprint identifies protocols and products from scan banners.
package fingerprint

import "github.com/twolate0101/hw_demo/internal/model"

// Engine is the stable boundary used by the HTTP API.
// Implementations must return an unknown result instead of failing when a
// banner cannot be identified.
type Engine interface {
	Identify(model.ScanInput) model.FingerprintResult
}
