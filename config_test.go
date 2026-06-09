package ech

import (
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	t.Run("missing PublicName", func(t *testing.T) {
		c := Config{}
		if err := c.validate(); err == nil {
			t.Fatal("expected error for empty PublicName")
		}
	})

	t.Run("valid config", func(t *testing.T) {
		c := Config{PublicName: "example.com"}
		if err := c.validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid PublicName single-label", func(t *testing.T) {
		c := Config{PublicName: "localhost"}
		if err := c.validate(); err == nil {
			t.Fatal("expected error for single-label PublicName, got nil")
		}
	})
}

func TestConfigFill(t *testing.T) {
	c := Config{PublicName: "example.com"}
	c.fill()
	if c.RotateInterval != DefaultRotateInterval {
		t.Errorf("RotateInterval = %v, want %v", c.RotateInterval, DefaultRotateInterval)
	}
	if c.RetainCount != DefaultRetainCount {
		t.Errorf("RetainCount = %d, want %d", c.RetainCount, DefaultRetainCount)
	}

	c2 := Config{PublicName: "example.com", RotateInterval: time.Hour, RetainCount: 5}
	c2.fill()
	if c2.RotateInterval != time.Hour {
		t.Error("fill() should not override non-zero RotateInterval")
	}
	if c2.RetainCount != 5 {
		t.Error("fill() should not override non-zero RetainCount")
	}
}
