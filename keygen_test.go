package ech

import (
	"crypto/tls"
	"encoding/binary"
	"testing"
)

func TestMarshalECHConfig(t *testing.T) {
	pubKey := make([]byte, 32) // dummy 32-byte X25519 public key
	cfg := marshalECHConfig(42, "example.com", pubKey)

	if len(cfg) < 4 {
		t.Fatal("ECHConfig too short")
	}

	version := binary.BigEndian.Uint16(cfg[0:2])
	if version != echVersion {
		t.Errorf("version = 0x%04x, want 0x%04x", version, echVersion)
	}

	contentsLen := int(binary.BigEndian.Uint16(cfg[2:4]))
	if len(cfg) != 4+contentsLen {
		t.Errorf("declared contentsLen %d, actual %d", contentsLen, len(cfg)-4)
	}

	contents := cfg[4:]
	// config_id
	if contents[0] != 42 {
		t.Errorf("config_id = %d, want 42", contents[0])
	}
	// kem_id
	kemID := binary.BigEndian.Uint16(contents[1:3])
	if kemID != kemX25519 {
		t.Errorf("kem_id = 0x%04x, want 0x%04x", kemID, kemX25519)
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := generateKey("example.com")
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	if len(key.Config) == 0 {
		t.Error("Config is empty")
	}
	if len(key.PrivateKey) != 32 {
		t.Errorf("PrivateKey length = %d, want 32", len(key.PrivateKey))
	}
}

func TestMarshalECHConfigList(t *testing.T) {
	key1, _ := generateKey("example.com")
	key2, _ := generateKey("example.com")

	list := marshalECHConfigList([]tls.EncryptedClientHelloKey{key1, key2})
	if len(list) < 2 {
		t.Fatal("list too short")
	}

	totalLen := int(binary.BigEndian.Uint16(list[0:2]))
	if len(list) != 2+totalLen {
		t.Errorf("declared len %d, actual payload %d", totalLen, len(list)-2)
	}
	expectedPayload := len(key1.Config) + len(key2.Config)
	if totalLen != expectedPayload {
		t.Errorf("payload len = %d, want %d", totalLen, expectedPayload)
	}
}
