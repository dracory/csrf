package csrf

import (
	"testing"
	"time"
)

func TestTokenGenerate_NumericSecret_Valid(t *testing.T) {
	secret := "123"
	token := TokenGenerate(secret)
	if !TokenValidate(token, secret) {
		t.Fatalf("numeric secret token failed validation: %s", token)
	}
	// t.Logf("numeric secret token: %s", token)
}

func TestTokenGenerate_AlphaNumeric_Valid(t *testing.T) {
	secret := "123abc"
	token := TokenGenerate(secret)
	if !TokenValidate(token, secret) {
		t.Fatalf("alphanumeric secret token failed validation: %s", token)
	}
	// t.Logf("alphanumeric secret token: %s", token)
}

func TestTokenGenerate_LongSecret_Valid(t *testing.T) {
	secret := "1234567890abcdefghijklmnopqrstuvwxyz_!@#$%^&*()-+="
	token := TokenGenerate(secret)
	if !TokenValidate(token, secret) {
		t.Fatalf("long secret token failed validation: %s", token)
	}
}

func TestTokenGenerate_EmptySecret_Valid(t *testing.T) {
	secret := ""
	token := TokenGenerate(secret)
	if !TokenValidate(token, secret) {
		t.Fatalf("empty secret token failed validation: %s", token)
	}
}

func TestTokenGenerate_CustomExpiry_Future_Valid(t *testing.T) {
	secret := "abc"
	opts := &Options{ExpiresAt: time.Now().Add(2 * time.Minute)}
	token := TokenGenerate(secret, opts)
	if !TokenValidate(token, secret, opts) {
		t.Fatalf("future expiry token failed validation: %s", token)
	}
}

func TestTokenGenerate_CustomExpiry_Past_Fails(t *testing.T) {
	secret := "abc"
	opts := &Options{ExpiresAt: time.Now().Add(-1 * time.Minute)}
	token := TokenGenerate(secret, opts)
	if TokenValidate(token, secret, opts) {
		t.Fatalf("past expiry token unexpectedly validated: %s", token)
	}
}
