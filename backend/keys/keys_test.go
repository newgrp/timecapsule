package keys_test

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/newgrp/timecapsule/keys"
)

func TestDeterminism(t *testing.T) {
	ks, err := keys.NewKeyManager(
		keys.PKIOptions{
			Name:    "Determinism Test",
			MinTime: time.Now().Add(-2 * time.Hour),
			MaxTime: time.Now().Add(2 * time.Hour),
		},
		t.TempDir(),
	)
	if err != nil {
		t.Fatalf("Failed to initialize key manager: %+v", err)
	}

	now := time.Now()

	k1, err := ks.GetKeyForTime(now)
	if err != nil {
		t.Fatalf("Failed to get key for now: %+v", err)
	}
	k2, err := ks.GetKeyForTime(now)
	if err != nil {
		t.Fatalf("Failed to get key for now: %+v", err)
	}
	if !k1.Equal(k2) {
		t.Errorf("Derived two different keys for now: %v and %v", k1, k2)
	}
}

func TestStability(t *testing.T) {
	const (
		uuidStr = "aa625eb2-d75d-4a64-8f5c-22cd4a06db22"

		timeStr = "2024-09-01T16:29:33-07:00"
		pubPem  = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExVW5oMPcttINe6ZtyfHJ7p1SQOrX
zBkII7T3C0onq4q6kpqYgi3I1UT7bTVJLYscqgQTD5oTHYhw5M87B1az2g==
-----END PUBLIC KEY-----`
	)

	pkiID, err := uuid.Parse(uuidStr)
	if err != nil {
		t.Fatalf("Test PKI ID is improperly formatted: %+v", err)
	}
	tm, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		t.Fatalf("Test time is improperly formatted: %+v", err)
	}
	wantKey, err := keys.ParseECDHPublicKeyAsSPKIPEM(pubPem)
	if err != nil {
		t.Fatalf("Test key is improperly formatted: %+v", err)
	}

	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("./testdata")); err != nil {
		t.Fatalf("Failed to copy test PKI: %+v", err)
	}
	ks, err := keys.NewKeyManager(
		keys.PKIOptions{
			Name: "Stability Test", ID: pkiID,
			MinTime: tm.Add(-time.Hour),
			MaxTime: tm.Add(time.Hour),
		},
		dir,
	)
	if err != nil {
		t.Fatalf("Failed to initialize key manager: %+v", err)
	}

	k, err := ks.GetKeyForTime(tm)
	if err != nil {
		t.Fatalf("Failed to get key for test time: %+v", err)
	}
	gotPem, err := keys.FormatPublicKeyAsSPKIPEM(k.Public())
	if err != nil {
		t.Fatalf("Failed to format derived key as PEM SubjectPublicKeyInfo: %+v", err)
	}

	if !k.PublicKey().Equal(wantKey) {
		t.Errorf(`Key generation has changed: got
%v
want
%v`, gotPem, pubPem)
	}
}
