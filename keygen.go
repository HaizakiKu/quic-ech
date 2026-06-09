package ech

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
)

const (
	echVersion    = 0xfe0d
	kemX25519     = 0x0020
	kdfHKDFSHA256 = 0x0001
	aeadAES128GCM = 0x0001
)

// generateKey creates a new ECH key pair for the given publicName.
func generateKey(publicName string) (tls.EncryptedClientHelloKey, error) {
	curve := ecdh.X25519()
	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return tls.EncryptedClientHelloKey{}, err
	}

	var configIDBuf [1]byte
	if _, err := rand.Read(configIDBuf[:]); err != nil {
		return tls.EncryptedClientHelloKey{}, err
	}

	pubKeyBytes := key.PublicKey().Bytes()
	echConfig := marshalECHConfig(configIDBuf[0], publicName, pubKeyBytes)

	return tls.EncryptedClientHelloKey{
		Config:     echConfig,
		PrivateKey: key.Bytes(),
	}, nil
}

// marshalECHConfig serializes a single ECHConfig per draft-ietf-tls-esni.
func marshalECHConfig(configID uint8, publicName string, publicKeyBytes []byte) []byte {
	var contents []byte

	// key_config
	contents = append(contents, configID)
	contents = binary.BigEndian.AppendUint16(contents, kemX25519)
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(publicKeyBytes)))
	contents = append(contents, publicKeyBytes...)
	// cipher_suites: one entry of {kdf_id, aead_id} = 4 bytes
	contents = binary.BigEndian.AppendUint16(contents, 4)
	contents = binary.BigEndian.AppendUint16(contents, kdfHKDFSHA256)
	contents = binary.BigEndian.AppendUint16(contents, aeadAES128GCM)

	// maximum_name_length
	contents = append(contents, 0)
	// public_name: uint8 length-prefixed
	contents = append(contents, uint8(len(publicName)))
	contents = append(contents, publicName...)
	// extensions: empty
	contents = binary.BigEndian.AppendUint16(contents, 0)

	var cfg []byte
	cfg = binary.BigEndian.AppendUint16(cfg, echVersion)
	cfg = binary.BigEndian.AppendUint16(cfg, uint16(len(contents)))
	cfg = append(cfg, contents...)
	return cfg
}

// marshalECHConfigList wraps one or more ECHConfigs into an ECHConfigList.
// ECHConfigList = uint16(total_len) || ECHConfig*
func marshalECHConfigList(keys []tls.EncryptedClientHelloKey) []byte {
	var configs []byte
	for _, k := range keys {
		configs = append(configs, k.Config...)
	}
	var list []byte
	list = binary.BigEndian.AppendUint16(list, uint16(len(configs)))
	list = append(list, configs...)
	return list
}
