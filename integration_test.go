//go:build integration

package ech_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	ech "github.com/HaizakiKu/quic-ech"
	"github.com/quic-go/quic-go"
)

// genCert generates a self-signed cert and returns (serverTLS, clientTLS) sharing the same CA.
func genCert(t *testing.T) (server *tls.Config, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	tlsCert := tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}
	server = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"test"},
	}
	client = &tls.Config{
		RootCAs:    pool,
		NextProtos: []string{"test"},
		ServerName: "localhost",
	}
	return server, client
}

func TestECHHandshake(t *testing.T) {
	// PublicName must be a valid multi-label DNS name; Go's validDNSName rejects single-label names.
	provider, err := ech.NewProvider(ech.Config{PublicName: "public.example.com"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	defer provider.Close()

	serverTLS, clientTLS := genCert(t)
	serverTLS.EncryptedClientHelloKeys = provider.Keys()
	clientTLS.EncryptedClientHelloConfigList = provider.ECHConfigList()

	ln, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
	if err != nil {
		t.Fatalf("ListenAddr: %v", err)
	}
	defer ln.Close()

	type result struct {
		accepted bool
		err      error
	}
	serverDone := make(chan result, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			serverDone <- result{err: err}
			return
		}
		defer conn.CloseWithError(0, "")
		serverDone <- result{accepted: conn.ConnectionState().TLS.ECHAccepted}
	}()

	conn, err := quic.DialAddr(context.Background(), ln.Addr().String(), clientTLS, nil)
	if err != nil {
		t.Fatalf("DialAddr: %v", err)
	}
	defer conn.CloseWithError(0, "")

	res := <-serverDone
	if res.err != nil {
		t.Fatalf("server error: %v", res.err)
	}
	if !res.accepted {
		t.Fatal("ECH was not accepted by the server")
	}
	if !conn.ConnectionState().TLS.ECHAccepted {
		t.Fatal("ECH was not accepted on the client side")
	}
}
