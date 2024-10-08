package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/newgrp/timecapsule/server"
)

const (
	// Environment variables.
	envServerAddress = "SERVER_ADDRESS"
	envServerCert    = "SERVER_CERT"
	envServerKey     = "SERVER_KEY"
	envNTSServers    = "NTS_SERVERS"
	envSecretsDir    = "SECRETS_DIR"
)

var (
	// Time parameter bounds.
	minTime = time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	maxTime = time.Date(2049, time.December, 31, 23, 59, 59, 0, time.UTC)
)

// Infers HTTP server configuration from environment variables.
//
// Returns (server address, TLS enabled, cert file, key file). Cert file and key
// file are non-empty if and only if TLS is enabled.
//
// Server address is inferred as follows:
//
//   - if the environment provides a custom address, use that
//   - if TLS is enabled, use ":443"
//   - otherwise, use ":80"
//
// TLS is inferred as enabled if and only if both the server cert and server key
// environment variables are populated.
func getServerConfig() (string, bool, string, string) {
	addr := ":80"
	s, customAddr := os.LookupEnv(envServerAddress)
	if customAddr {
		addr = s
	}

	certFile, ok := os.LookupEnv(envServerCert)
	if !ok {
		return addr, false, "", ""
	}
	keyFile, ok := os.LookupEnv(envServerKey)
	if !ok {
		return addr, false, "", ""
	}

	if !customAddr {
		addr = ":443"
	}
	return addr, true, certFile, keyFile
}

func main() {
	var opts server.Options

	servers, ok := os.LookupEnv(envNTSServers)
	if !ok {
		log.Fatalf("No NTS server provided")
	}
	opts.NTSServers = strings.Split(servers, ",")

	opts.PKIOptions.MinTime = minTime
	opts.PKIOptions.MaxTime = maxTime

	opts.SecretsDir, ok = os.LookupEnv(envSecretsDir)
	if !ok {
		log.Fatalf("No secrets directory provided")
	}

	server, err := server.NewServer(opts)
	if err != nil {
		log.Fatalf("Failed to start server: %+v", err)
	}
	log.Println("Server dependencies initialized")
	server.RegisterHandlers(http.DefaultServeMux)

	addr, tls, certFile, keyFile := getServerConfig()
	if tls {
		log.Printf("Running HTTPS server at %s", addr)
		log.Fatal(http.ListenAndServeTLS(addr, certFile, keyFile, nil))
	} else {
		log.Printf("Running HTTP server at %s", addr)
		log.Fatal(http.ListenAndServe(addr, nil))
	}
}
