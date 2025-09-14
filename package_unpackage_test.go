package csrf

import (
	"testing"
	"time"
)

func TestBox(t *testing.T) {
	h := "$2a$10$ABCDEFGHIJKLMNOPQRSTUV"
	exp := time.Unix(1736534400, 0).UTC()
	got := packageToken(h, exp)
	want := h + ":1736534400"
	if got != want {
		t.Fatalf("box() = %q, want %q", got, want)
	}
}

func TestUnbox_OK(t *testing.T) {
	packaged := "$2a$10$ABCDEFGHIJKLMNOPQRSTUV:1736534400"
	h, expAt, err := unpackageToken(packaged)
	if err != nil {
		t.Fatalf("unbox() err = %v, want nil", err)
	}
	if h != "$2a$10$ABCDEFGHIJKLMNOPQRSTUV" {
		t.Errorf("unbox() hash = %q, want %q", h, "$2a$10$ABCDEFGHIJKLMNOPQRSTUV")
	}
	if expAt.Unix() != 1736534400 {
		t.Errorf("unbox() exp = %d, want %d", expAt.Unix(), 1736534400)
	}
}

func TestUnbox_ErrFormat(t *testing.T) {
	cases := []string{
		"no-colon",
		":123",
		"abc:",
	}
	for _, c := range cases {
		if _, _, err := unpackageToken(c); err == nil {
			t.Errorf("unbox(%q) expected error, got nil", c)
		}
	}
}

func TestUnbox_ErrParse(t *testing.T) {
	if _, _, err := unpackageToken("abc:xyz"); err == nil {
		t.Errorf("unbox('abc:xyz') expected error, got nil")
	}
}
