package csrf

import (
	"net/http"
	"testing"
	"time"
)

func TestBindUserAgent_SameRequest_Valid(t *testing.T) {
	secret := "bind-ua"
	req, _ := http.NewRequest("POST", "http://example.com/form", nil)
	req.Header.Set("User-Agent", "TestUA/1.0")
	opts := &Options{Request: req, BindUserAgent: true, ExpiresAt: time.Now().Add(2 * time.Minute)}
	token := TokenGenerate(secret, opts)
	if !TokenValidate(token, secret, opts) {
		t.Fatalf("same UA token failed validation")
	}
}

func TestBindUserAgent_DifferentRequest_Fails(t *testing.T) {
	secret := "bind-ua"
	req1, _ := http.NewRequest("POST", "http://example.com/form", nil)
	req1.Header.Set("User-Agent", "TestUA/1.0")
	genOpts := &Options{Request: req1, BindUserAgent: true, ExpiresAt: time.Now().Add(2 * time.Minute)}
	token := TokenGenerate(secret, genOpts)

	req2, _ := http.NewRequest("POST", "http://example.com/form", nil)
	req2.Header.Set("User-Agent", "DifferentUA/2.0")
	valOpts := &Options{Request: req2, BindUserAgent: true}

	if TokenValidate(token, secret, valOpts) {
		t.Fatalf("token validated with different User-Agent; expected failure")
	}
}
