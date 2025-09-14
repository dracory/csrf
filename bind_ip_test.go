package csrf

import (
	"net/http"
	"testing"
	"time"
)

func newReqWith(addr string, xff string, xri string) *http.Request {
	req, _ := http.NewRequest("POST", "http://example.com/submit", nil)
	req.RemoteAddr = addr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	if xri != "" {
		req.Header.Set("X-Real-IP", xri)
	}
	return req
}

func TestBindIP_XForwardedFor_SameIP_Valid(t *testing.T) {
	secret := "ip-test"
	req := newReqWith("10.0.0.1:1234", "203.0.113.10, 198.51.100.5", "")
	opts := &Options{Request: req, BindIP: true, ExpiresAt: time.Now().Add(2 * time.Minute)}
	token := TokenGenerate(secret, opts)
	if !TokenValidate(token, secret, opts) {
		t.Fatalf("token with same XFF failed validation")
	}
}

func TestBindIP_XForwardedFor_DifferentIP_Fails(t *testing.T) {
	secret := "ip-test"
	// Generate with one client IP
	genReq := newReqWith("10.0.0.1:1234", "203.0.113.10, 198.51.100.5", "")
	genOpts := &Options{Request: genReq, BindIP: true, ExpiresAt: time.Now().Add(2 * time.Minute)}
	token := TokenGenerate(secret, genOpts)

	// Validate with a different client IP in XFF
	valReq := newReqWith("10.0.0.2:5678", "203.0.113.11, 198.51.100.7", "")
	valOpts := &Options{Request: valReq, BindIP: true}
	if TokenValidate(token, secret, valOpts) {
		t.Fatalf("token validated with different XFF client IP; expected failure")
	}
}

func TestBindIP_XRealIP_UsedWhenNoXFF(t *testing.T) {
	secret := "ip-test"
	genReq := newReqWith("10.0.0.1:1234", "", "198.51.100.42")
	genOpts := &Options{Request: genReq, BindIP: true, ExpiresAt: time.Now().Add(2 * time.Minute)}
	token := TokenGenerate(secret, genOpts)

	valReq := newReqWith("10.0.0.2:5678", "", "198.51.100.42")
	valOpts := &Options{Request: valReq, BindIP: true}
	if !TokenValidate(token, secret, valOpts) {
		t.Fatalf("token failed validation when X-Real-IP matched")
	}
}

func TestBindIP_RemoteAddr_Fallback(t *testing.T) {
	secret := "ip-test"
	genReq := newReqWith("192.0.2.10:3456", "", "")
	genOpts := &Options{Request: genReq, BindIP: true, ExpiresAt: time.Now().Add(2 * time.Minute)}
	token := TokenGenerate(secret, genOpts)

	valReqSame := newReqWith("192.0.2.10:9999", "", "")
	valOptsSame := &Options{Request: valReqSame, BindIP: true}
	if !TokenValidate(token, secret, valOptsSame) {
		t.Fatalf("token failed validation when RemoteAddr host matched")
	}

	valReqDiff := newReqWith("192.0.2.11:9999", "", "")
	valOptsDiff := &Options{Request: valReqDiff, BindIP: true}
	if TokenValidate(token, secret, valOptsDiff) {
		t.Fatalf("token validated with different RemoteAddr host; expected failure")
	}
}
