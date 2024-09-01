package server_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/newgrp/timekey/server"
)

// Long enough away from now to be definitively in the past or the future.
const longEnough = 10 * time.Second

// NTS server for testing. Cloudflare seems like it should usually be reachable.
var ntsServers = []string{"time.cloudflare.com"}

// Initialize the HTTP handlers once, since they apparently have to be global.
func init() {
	secretsDir, err := os.MkdirTemp(os.TempDir(), "*")
	if err != nil {
		log.Fatalf("Failed to create temporary directory for secrets: %+v", err)
	}

	server, err := server.NewServer(server.Options{
		NTSServers: ntsServers,
		SecretsDir: secretsDir,
	})
	if err != nil {
		log.Fatalf("Failed to initialize server: %+v", err)
	}
	server.RegisterHandlers(http.DefaultServeMux)
}

// Construct an HTTP URL with the given parameters.
func createURL(host string, path string, query url.Values) string {
	url := url.URL{
		Scheme:   "http",
		Host:     host,
		Path:     path,
		RawQuery: query.Encode(),
	}
	return url.String()
}

// Wrapper around http.Get that automatically parses the body.
func httpGet(url string) (status int, body string, err error) {
	resp, err := http.Get(url)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}

	return resp.StatusCode, string(b), nil
}

// As httpGet, but returns an error if the status isn't 200 OK.
func httpGetOK(url string) (string, error) {
	status, body, err := httpGet(url)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("%s: %s", http.StatusText(status), string(body))
	}
	return string(body), nil
}

// Parses a PEM-encoded ECDH public key.
func parsePEMPublicKey(s string) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("Not a PEM-encoded string")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("Not a public key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse ASN.1: %w", err)
	}
	switch k := key.(type) {
	case *ecdh.PublicKey:
		return k, nil
	case *ecdsa.PublicKey:
		return k.ECDH()
	default:
		return nil, fmt.Errorf("Key is not an ECDH key, instead %T", key)
	}
}

// Parses a PEM-encoded ECDH private key.
func parsePEMPrivateKey(s string) (*ecdh.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("Not a PEM-encoded string")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("Not a private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse ASN.1: %w", err)
	}
	switch k := key.(type) {
	case *ecdh.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k.ECDH()
	default:
		return nil, fmt.Errorf("Key is not an ECDH key, instead %T", key)
	}
}

// Starts an HTTP server and returns its address.
//
// The server will automatically forcibly shut down when the test finishes.
func setupServer(t *testing.T) string {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to listen on any port: %+v", err)
	}
	addr := listener.Addr().String()

	httpServer := http.Server{Addr: addr}
	go httpServer.Serve(listener)
	t.Cleanup(func() { httpServer.Close() })

	t.Logf("Running test server at %s", addr)
	return addr
}

func TestGetPublicKey(t *testing.T) {
	addr := setupServer(t)
	target := time.Now().Add(-longEnough)
	url := createURL(addr, "/v0/get_public_key", url.Values{
		"time": []string{fmt.Sprint(target.Unix())},
	})

	body, err := httpGetOK(url)
	if err != nil {
		t.Fatalf("Failed to get public key for %s: %+v", target.Format(time.RFC3339), err)
	}
	t.Logf("GET %s returned %s", url, body)
	_, err = parsePEMPublicKey(body)
	if err != nil {
		t.Errorf("get_public_key returned invalid key: %+v", err)
	}
}

func TestGetPublicKeyRFC3339(t *testing.T) {
	addr := setupServer(t)
	target := time.Now().Add(-longEnough)
	url := createURL(addr, "/v0/get_public_key", url.Values{
		"time": []string{target.Format(time.RFC3339)},
	})

	body, err := httpGetOK(url)
	if err != nil {
		t.Fatalf("Failed to get public key for %s: %+v", target.Format(time.RFC3339), err)
	}
	t.Logf("GET %s returned %s", url, body)
	_, err = parsePEMPublicKey(body)
	if err != nil {
		t.Errorf("get_public_key returned invalid key: %+v", err)
	}
}

func TestGetPrivateKey(t *testing.T) {
	addr := setupServer(t)
	target := time.Now().Add(-longEnough)
	url := createURL(addr, "/v0/get_private_key", url.Values{
		"time": []string{fmt.Sprint(target.Unix())},
	})

	body, err := httpGetOK(url)
	if err != nil {
		t.Fatalf("Failed to get private key for %s: %+v", target.Format(time.RFC3339), err)
	}
	t.Logf("GET %s returned %s", url, body)
	_, err = parsePEMPrivateKey(body)
	if err != nil {
		t.Errorf("get_private_key returned invalid key: %+v", err)
	}
}

func TestGetPrivateKeyRFC3339(t *testing.T) {
	addr := setupServer(t)
	target := time.Now().Add(-longEnough)
	url := createURL(addr, "/v0/get_private_key", url.Values{
		"time": []string{target.Format(time.RFC3339)},
	})

	body, err := httpGetOK(url)
	if err != nil {
		t.Fatalf("Failed to get private key for %s: %+v", target.Format(time.RFC3339), err)
	}
	t.Logf("GET %s returned %s", url, body)
	_, err = parsePEMPrivateKey(body)
	if err != nil {
		t.Errorf("get_private_key returned invalid key: %+v", err)
	}
}

func TestGetPrivateKeyForbidden(t *testing.T) {
	addr := setupServer(t)
	target := time.Now().Add(longEnough)
	url := createURL(addr, "/v0/get_private_key", url.Values{
		"time": []string{fmt.Sprint(target.Unix())},
	})

	status, body, err := httpGet(url)
	if err != nil {
		t.Fatalf("Failed to get private key for %s: %s: %+v", target.Format(time.RFC3339), http.StatusText(status), err)
	}
	if status != http.StatusForbidden {
		t.Errorf("Private key was provided for %s, but it shouldn't have been: %s", target.Format(time.RFC3339), string(body))
	}
}

func TestGetKeyPair(t *testing.T) {
	addr := setupServer(t)
	target := time.Now().Add(-longEnough)
	pubUrl := createURL(addr, "/v0/get_public_key", url.Values{
		"time": []string{fmt.Sprint(target.Unix())},
	})
	privUrl := createURL(addr, "/v0/get_private_key", url.Values{
		"time": []string{fmt.Sprint(target.Unix())},
	})

	body, err := httpGetOK(pubUrl)
	if err != nil {
		t.Fatalf("Failed to get public key for %s: %+v", target.Format(time.RFC3339), err)
	}
	t.Logf("GET %s returned %s", pubUrl, body)
	pub, err := parsePEMPublicKey(body)
	if err != nil {
		t.Fatalf("get_public_key returned invalid key: %+v", err)
	}

	body, err = httpGetOK(privUrl)
	if err != nil {
		t.Fatalf("Failed to get private key for %s: %+v", target.Format(time.RFC3339), err)
	}
	t.Logf("GET %s returned %s", privUrl, body)
	priv, err := parsePEMPrivateKey(body)
	if err != nil {
		t.Fatalf("get_private_key returned invalid key: %+v", err)
	}

	if !priv.PublicKey().Equal(pub) {
		t.Errorf("Private key for %s does not correspond to public key for %s", target.Format(time.RFC3339), target.Format(time.RFC3339))
	}
}
