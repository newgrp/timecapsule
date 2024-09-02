package server_test

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/newgrp/timecapsule/keys"
	"github.com/newgrp/timecapsule/server"
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
		PKIOptions: keys.PKIOptions{
			Name: "Test Server",
		},
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
func httpGetOK[T any](url string) (*T, error) {
	status, body, err := httpGet(url)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", http.StatusText(status), string(body))
	}

	ret := new(T)
	d := json.NewDecoder(strings.NewReader(body))
	d.DisallowUnknownFields()
	if err = d.Decode(ret); err != nil {
		return nil, fmt.Errorf("failed to decode body as %T: %w", ret, err)
	}
	return ret, nil
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

	resp, err := httpGetOK[server.GetPublicKeyResp](url)
	if err != nil {
		t.Fatalf("Failed to get public key for %s: %+v", target.Format(time.RFC3339), err)
	}
	t.Logf("GET %s returned %+v", url, resp)

	_, err = keys.ParseECDHPublicKeyAsSPKIDER(resp.SPKI)
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

	resp, err := httpGetOK[server.GetPublicKeyResp](url)
	if err != nil {
		t.Fatalf("Failed to get public key for %s: %+v", target.Format(time.RFC3339), err)
	}
	t.Logf("GET %s returned %+v", url, resp)

	_, err = keys.ParseECDHPublicKeyAsSPKIDER(resp.SPKI)
	if err != nil {
		t.Errorf("get_public_key returned invalid key: %+v", err)
	}
}

func TestGetPublicKeyWrongPKIID(t *testing.T) {
	var pkiID = uuid.NewString()

	addr := setupServer(t)
	target := time.Now().Add(-longEnough)
	url := createURL(addr, "/v0/get_public_key", url.Values{
		"pki_id": []string{pkiID},
		"time":   []string{fmt.Sprint(target.Unix())},
	})

	status, _, err := httpGet(url)
	if err != nil {
		t.Fatalf("Network error in get_public_key: %+v", err)
	}
	if status != http.StatusNotFound {
		t.Errorf("Public key was provided for PKI %s, but it shouldn't have been", pkiID)
	}
}

func TestGetPrivateKey(t *testing.T) {
	addr := setupServer(t)
	target := time.Now().Add(-longEnough)
	url := createURL(addr, "/v0/get_private_key", url.Values{
		"time": []string{fmt.Sprint(target.Unix())},
	})

	resp, err := httpGetOK[server.GetPrivateKeyResp](url)
	if err != nil {
		t.Fatalf("Failed to get private key for %s: %+v", target.Format(time.RFC3339), err)
	}
	t.Logf("GET %s returned %+v", url, resp)

	_, err = keys.ParseECDHPrivateKeyAsPKCS8DER(resp.PKCS8)
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

	resp, err := httpGetOK[server.GetPrivateKeyResp](url)
	if err != nil {
		t.Fatalf("Failed to get private key for %s: %+v", target.Format(time.RFC3339), err)
	}
	t.Logf("GET %s returned %+v", url, resp)

	_, err = keys.ParseECDHPrivateKeyAsPKCS8DER(resp.PKCS8)
	if err != nil {
		t.Errorf("get_private_key returned invalid key: %+v", err)
	}
}

func TestGetPrivateKeyWrongPKIID(t *testing.T) {
	var pkiID = uuid.NewString()

	addr := setupServer(t)
	target := time.Now().Add(-longEnough)
	url := createURL(addr, "/v0/get_private_key", url.Values{
		"pki_id": []string{pkiID},
		"time":   []string{fmt.Sprint(target.Unix())},
	})

	status, _, err := httpGet(url)
	if err != nil {
		t.Fatalf("Network error in get_private_key: %+v", err)
	}
	if status != http.StatusNotFound {
		t.Errorf("Private key was provided for PKI %s, but it shouldn't have been", pkiID)
	}
}

func TestGetPrivateKeyForbidden(t *testing.T) {
	addr := setupServer(t)
	target := time.Now().Add(longEnough)
	url := createURL(addr, "/v0/get_private_key", url.Values{
		"time": []string{fmt.Sprint(target.Unix())},
	})

	status, _, err := httpGet(url)
	if err != nil {
		t.Fatalf("Network error in get_private_key: %+v", err)
	}
	if status != http.StatusForbidden {
		t.Errorf("Private key was provided for %s, but it shouldn't have been", target.Format(time.RFC3339))
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

	pubResp, err := httpGetOK[server.GetPublicKeyResp](pubUrl)
	if err != nil {
		t.Fatalf("Failed to get public key for %s: %+v", target.Format(time.RFC3339), err)
	}
	t.Logf("GET %s returned %+v", pubUrl, pubResp)
	pub, err := keys.ParseECDHPublicKeyAsSPKIDER(pubResp.SPKI)
	if err != nil {
		t.Errorf("get_public_key returned invalid key: %+v", err)
	}

	privResp, err := httpGetOK[server.GetPrivateKeyResp](privUrl)
	if err != nil {
		t.Fatalf("Failed to get private key for %s: %+v", target.Format(time.RFC3339), err)
	}
	t.Logf("GET %s returned %+v", privUrl, privResp)
	priv, err := keys.ParseECDHPrivateKeyAsPKCS8DER(privResp.PKCS8)
	if err != nil {
		t.Errorf("get_private_key returned invalid key: %+v", err)
	}

	if !priv.PublicKey().Equal(pub) {
		t.Errorf("Private key for %s does not correspond to public key for %s", target.Format(time.RFC3339), target.Format(time.RFC3339))
	}
}
