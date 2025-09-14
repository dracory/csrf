package csrf

import (
	"testing"
)

func TestBuildAugmentedSecret_NoRequest(t *testing.T) {
	// When no request and no flags, it should be just secret + mixin
	secret := "base"
	got := buildAugmentedSecret(secret, nil)
	wantPrefix := secret + CSRF_TOKEN_MIXIN
	if got != wantPrefix {
		t.Errorf("buildAugmentedSecret() = %q, want %q", got, wantPrefix)
	}
}
