package csrf

import "testing"

func TestTokenGenerate(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		want   bool
	}{
		{
			name:   "Test Numeric Secret",
			secret: "123",
			want:   true,
		},
		{
			name:   "Test Alpha Numeric Secret",
			secret: "123abc",
			want:   true,
		},
		{
			name:   "Test Long Alpha Numeric Secret",
			secret: "1234567890abcdefghijklmnopqrstuvwxyz_!@#$%^&*()-+=",
			want:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := TokenGenerate(tt.secret)
			isValid := TokenValidate(token, tt.secret)

			t.Log(token)

			if !isValid {
				t.Error("TokenGenerate() = ", token, " cannot validate")
			}
		})
	}
}
