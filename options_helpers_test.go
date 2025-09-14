package csrf

import (
	"testing"
	"time"
)

func withinDuration(t *testing.T, got time.Time, target time.Duration, tolerance time.Duration) {
	t.Helper()
	delta := got.Sub(time.Now().UTC())
	if delta < target-tolerance || delta > target+tolerance {
		t.Fatalf("ExpiresAt delta = %v, want around %v ± %v", delta, target, tolerance)
	}
}

func TestGetOptionsOrDefault_NoArgs_SetsDefaultExpiry(t *testing.T) {
	o := getOptionsOrDefault()
	if o == nil {
		t.Fatalf("getOptionsOrDefault() returned nil")
	}
	if o.ExpiresAt.IsZero() {
		t.Fatalf("ExpiresAt should be set by default")
	}
	withinDuration(t, o.ExpiresAt, DefaultPackagedExpiry, 2*time.Minute)
}

func TestGetOptionsOrDefault_ExplicitNil_SetsDefaultExpiry(t *testing.T) {
	var in *Options = nil
	o := getOptionsOrDefault(in)
	if o == nil {
		t.Fatalf("getOptionsOrDefault(nil) returned nil")
	}
	if o.ExpiresAt.IsZero() {
		t.Fatalf("ExpiresAt should be set by default for explicit nil")
	}
	withinDuration(t, o.ExpiresAt, DefaultPackagedExpiry, 2*time.Minute)
}

func TestGetOptionsOrDefault_ZeroExpiry_SetsDefault(t *testing.T) {
	in := &Options{}
	o := getOptionsOrDefault(in)
	if o.ExpiresAt.IsZero() {
		t.Fatalf("ExpiresAt should be set when input has zero ExpiresAt")
	}
	withinDuration(t, o.ExpiresAt, DefaultPackagedExpiry, 2*time.Minute)
}

func TestGetOptionsOrDefault_NonZeroExpiry_Preserved(t *testing.T) {
	future := time.Now().UTC().Add(42 * time.Minute)
	in := &Options{ExpiresAt: future}
	o := getOptionsOrDefault(in)
	if !o.ExpiresAt.Equal(future) {
		t.Fatalf("ExpiresAt changed: got %v, want %v", o.ExpiresAt, future)
	}
}
