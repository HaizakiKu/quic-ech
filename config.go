package ech

import (
	"errors"
	"strings"
	"time"
)

const (
	DefaultRotateInterval = 24 * time.Hour
	DefaultRetainCount    = 2
)

// Config holds options for a Provider.
type Config struct {
	// PublicName is the outer SNI visible to observers (e.g. "cloudflare.com").
	// Must be a valid multi-label DNS name. Required.
	PublicName string

	// KeyFile is the path to persist keys across restarts.
	// Optional. If empty, keys are memory-only.
	KeyFile string

	// RotateInterval controls how often new keys are generated.
	// Optional. Default: 24h
	RotateInterval time.Duration

	// RetainCount is the number of old keys to keep alongside the current key.
	// Clients that cached a previous ECHConfig can still complete handshakes.
	// Optional. Default: 2
	RetainCount int

	// OnRotateError, if non-nil, is called with any error from the background
	// rotation goroutine. Use this to log or alert on rotation failures.
	// Optional.
	OnRotateError func(error)
}

func (c *Config) fill() {
	if c.RotateInterval == 0 {
		c.RotateInterval = DefaultRotateInterval
	}
	if c.RetainCount == 0 {
		c.RetainCount = DefaultRetainCount
	}
}

func (c *Config) validate() error {
	if c.PublicName == "" {
		return errors.New("quic-ech: PublicName is required")
	}
	if !validPublicName(c.PublicName) {
		return errors.New("quic-ech: PublicName must be a multi-label DNS name (e.g. \"example.com\"); single-label names like \"localhost\" are rejected by Go's TLS stack")
	}
	return nil
}

// validPublicName reports whether name is a valid multi-label DNS name.
// Go's TLS stack silently rejects single-label names as ECH public names.
func validPublicName(name string) bool {
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" {
			return false
		}
	}
	return true
}
