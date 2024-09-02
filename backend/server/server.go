package server

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/newgrp/timekey/clock"
	"github.com/newgrp/timekey/keys"
)

const (
	// Request parameter names.
	argTime = "time"

	// REST method names.
	methodGetPublicKey  = "get_public_key"
	methodGetPrivateKey = "get_private_key"
)

type GetPublicKeyResp struct {
	PKIName string `json:"pkiName"`
	PKIID   string `json:"pkiID"`
	SPKI    []byte `json:"spki"`
}

type GetPrivateKeyResp struct {
	PKIName string `json:"pkiName"`
	PKIID   string `json:"pkiID"`
	PKCS8   []byte `json:"pkcs8"`
}

// Parses a time string, which may be either:
//
//   - integer seconds since Unix epoch
//   - RFC 3339 formatted time string
func parseTime(s string) (time.Time, error) {
	var sec int64
	if _, err := fmt.Sscanf(s, "%d", &sec); err == nil {
		return time.Unix(sec, 0), nil
	}

	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("time must be given either as integer seconds since the Unix epoch or RFC 3339 string")
}

// HTTP handler that only depends on URL parameters. Returns (JSON-encodable value, HTTP status
// code, error message).
type simpleHandler = func(url.Values) (any, int, string)

// makeHandler converts a simpleHandler to an http.HandlerFunc.
func makeHandler(h simpleHandler) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		query, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(fmt.Sprintf("Could not parse request parameters: %v\n", err)))
			return
		}

		value, status, message := h(query)

		var body string
		if status == http.StatusOK {
			b := &strings.Builder{}
			e := json.NewEncoder(b)
			e.SetEscapeHTML(false)
			if err = e.Encode(value); err != nil {
				log.Printf("ERROR: Failed to encode value of type %T as JSON: %v", value, err)
				resp.WriteHeader(http.StatusInternalServerError)
				return
			}
			body = b.String()
		} else {
			body = message
		}
		if len(body) != 0 && body[len(body)-1] != '\n' {
			body = fmt.Sprintf("%s\n", body)
		}

		resp.WriteHeader(status)
		resp.Write([]byte(body))
	}
}

// Server options.
type Options struct {
	// Addresses of permitted NTS servers.
	NTSServers []string
	// PKI options.
	PKIOptions keys.PKIOptions
	// Working directory for root secrets.
	SecretsDir string
}

// Server that handles HTTP requests for time keys.
type Server struct {
	clock *clock.SecureClock
	keys  *keys.KeyManager
}

func NewServer(opts Options) (*Server, error) {
	clock, err := clock.NewSecureClock(opts.NTSServers)
	if err != nil {
		return nil, err
	}

	keys, err := keys.NewKeyManager(opts.PKIOptions, opts.SecretsDir)
	if err != nil {
		return nil, err
	}

	return &Server{clock, keys}, nil
}

// Simple handler for public key requests.
func (s *Server) getPublicKey(query url.Values) (*GetPublicKeyResp, int, string) {
	if !query.Has(argTime) {
		return nil, http.StatusBadRequest, fmt.Sprintf("%q parameter is required", argTime)
	}
	t, err := parseTime(query.Get(argTime))
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Sprintf("Invalid %q paremter: %v", argTime, err)
	}

	// Don't expose internal error details to clients. Instead, log the full error but return a
	// generic message.
	const internalError = "Server failed to retrieve public key"

	priv, err := s.keys.GetKeyForTime(t)
	if err != nil {
		log.Printf("ERROR: Failed to retrieve key for time %s: %+v", t.Format(time.RFC3339), err)
		return nil, http.StatusInternalServerError, internalError
	}

	der, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
	if err != nil {
		log.Printf("ERROR: Failed to marshal public key for time %s: %+v", t.Format(time.RFC3339), err)
		return nil, http.StatusInternalServerError, internalError
	}
	return &GetPublicKeyResp{
		PKIName: s.keys.Name(),
		PKIID:   s.keys.PKIID().String(),
		SPKI:    der,
	}, http.StatusOK, ""
}

// Simple handler for private key requests.
func (s *Server) getPrivateKey(query url.Values) (*GetPrivateKeyResp, int, string) {
	if !query.Has(argTime) {
		return nil, http.StatusBadRequest, fmt.Sprintf("%q parameter is required", argTime)
	}
	t, err := parseTime(query.Get(argTime))
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Sprintf("Invalid %q paremter: %v", argTime, err)
	}

	now, err := s.clock.Now()
	if err != nil {
		return nil, http.StatusInternalServerError, "Server could securely determine the current time"
	}
	if t.After(now) {
		return nil, http.StatusForbidden, "Server does not disclose private keys for future timestamps"
	}

	// Don't expose internal error details to clients. Instead, log the full error but return a
	// generic message.
	const internalError = "Server failed to retrieve private key"

	priv, err := s.keys.GetKeyForTime(t)
	if err != nil {
		log.Printf("ERROR: Failed to retrieve key for time %s: %+v", t.Format(time.RFC3339), err)
		return nil, http.StatusInternalServerError, internalError
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Printf("ERROR: Failed to marshal private key for time %s: %+v", t.Format(time.RFC3339), err)
		return nil, http.StatusInternalServerError, internalError
	}
	return &GetPrivateKeyResp{
		PKIName: s.keys.Name(),
		PKIID:   s.keys.PKIID().String(),
		PKCS8:   der,
	}, http.StatusOK, ""
}

// Registers handlers for the following methods:
//
//   - GET /v0/get_public_key
//   - GET /v0/get_private_key
func (s *Server) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc(fmt.Sprintf("GET /v0/%s", methodGetPublicKey), makeHandler(func(query url.Values) (any, int, string) {
		return s.getPublicKey(query)
	}))
	mux.HandleFunc(fmt.Sprintf("GET /v0/%s", methodGetPrivateKey), makeHandler(func(query url.Values) (any, int, string) {
		return s.getPrivateKey(query)
	}))
}
