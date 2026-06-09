package ech

import (
	"os"
	"testing"
	"time"
)

func TestNewProvider(t *testing.T) {
	p, err := NewProvider(Config{PublicName: "example.com"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	defer p.Close()

	keys := p.Keys()
	if len(keys) != 1 {
		t.Errorf("Keys() len = %d, want 1", len(keys))
	}
}

func TestRotation(t *testing.T) {
	p, err := NewProvider(Config{
		PublicName:     "example.com",
		RotateInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	defer p.Close()

	if err := p.rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	keys := p.Keys()
	if len(keys) != 2 {
		t.Errorf("after rotate, Keys() len = %d, want 2", len(keys))
	}
}

func TestRetainCount(t *testing.T) {
	retain := 2
	p, err := NewProvider(Config{
		PublicName:     "example.com",
		RotateInterval: time.Hour,
		RetainCount:    retain,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	defer p.Close()

	for i := 0; i < retain+2; i++ {
		if err := p.rotate(); err != nil {
			t.Fatalf("rotate %d: %v", i, err)
		}
	}

	keys := p.Keys()
	want := retain + 1
	if len(keys) != want {
		t.Errorf("Keys() len = %d, want %d", len(keys), want)
	}
}

func TestPersist(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "ech-*.key")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	keyFile := f.Name()
	os.Remove(keyFile)

	p, err := NewProvider(Config{
		PublicName:     "example.com",
		KeyFile:        keyFile,
		RotateInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	// Capture keys before Close() zeros the private key bytes.
	origKeys := p.Keys()
	p.Close()

	p2, err := NewProvider(Config{
		PublicName:     "example.com",
		KeyFile:        keyFile,
		RotateInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewProvider (reload): %v", err)
	}
	defer p2.Close()

	reloaded := p2.Keys()
	if len(reloaded) != len(origKeys) {
		t.Fatalf("reloaded key count %d, want %d", len(reloaded), len(origKeys))
	}
	for i := range origKeys {
		if string(reloaded[i].Config) != string(origKeys[i].Config) {
			t.Errorf("key[%d] Config mismatch after reload", i)
		}
		if string(reloaded[i].PrivateKey) != string(origKeys[i].PrivateKey) {
			t.Errorf("key[%d] PrivateKey mismatch after reload", i)
		}
	}
}

func TestCloseIdempotent(t *testing.T) {
	p, err := NewProvider(Config{PublicName: "example.com"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	p.Close()
	p.Close() // must not panic
}
