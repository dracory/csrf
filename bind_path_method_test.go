package csrf

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestBindPath_SamePath_Valid(t *testing.T) {
	secret := "s3cr3t"
	r := httptest.NewRequest("POST", "/submit", nil)
	opts := &Options{Request: r, BindPath: true, ExpiresAt: time.Now().Add(2 * time.Minute)}

	token := TokenGenerate(secret, opts)
	if !TokenValidate(token, secret, opts) {
		t.Fatalf("token should validate when BindPath is true and path matches: %s", token)
	}
}

func TestBindPath_DifferentPath_Invalid(t *testing.T) {
	secret := "s3cr3t"
	genReq := httptest.NewRequest("POST", "/submit", nil)
	genOpts := &Options{Request: genReq, BindPath: true, ExpiresAt: time.Now().Add(2 * time.Minute)}

	token := TokenGenerate(secret, genOpts)

	// Validate with a different path
	valReq := httptest.NewRequest("POST", "/other", nil)
	valOpts := &Options{Request: valReq, BindPath: true, ExpiresAt: genOpts.ExpiresAt}
	if TokenValidate(token, secret, valOpts) {
		t.Fatalf("token should NOT validate when BindPath is true and path differs: %s", token)
	}
}

func TestBindMethod_SameMethod_Valid(t *testing.T) {
	secret := "s3cr3t"
	r := httptest.NewRequest("POST", "/submit", nil)
	opts := &Options{Request: r, BindMethod: true, ExpiresAt: time.Now().Add(2 * time.Minute)}

	token := TokenGenerate(secret, opts)
	if !TokenValidate(token, secret, opts) {
		t.Fatalf("token should validate when BindMethod is true and method matches: %s", token)
	}
}

func TestBindMethod_DifferentMethod_Invalid(t *testing.T) {
	secret := "s3cr3t"
	genReq := httptest.NewRequest("POST", "/submit", nil)
	genOpts := &Options{Request: genReq, BindMethod: true, ExpiresAt: time.Now().Add(2 * time.Minute)}

	token := TokenGenerate(secret, genOpts)

	// Validate with a different method
	valReq := httptest.NewRequest("GET", "/submit", nil)
	valOpts := &Options{Request: valReq, BindMethod: true, ExpiresAt: genOpts.ExpiresAt}
	if TokenValidate(token, secret, valOpts) {
		t.Fatalf("token should NOT validate when BindMethod is true and method differs: %s", token)
	}
}
