package csrf

import (
	"encoding/base32"
	"strings"
)

// Crockford Base32 encoding (no padding), per https://www.crockford.com/base32.html
// Alphabet excludes I, L, O, U and is case-insensitive on decode.
var crockfordEncoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// encodeCrockford encodes the given bytes using Crockford's Base32 without padding.
func encodeCrockford(b []byte) string {
	return crockfordEncoding.EncodeToString(b)
}

// decodeCrockford decodes a Crockford Base32 string. It is lenient and:
//  - ignores hyphens
//  - uppercases input
//  - maps I and L to 1, and O to 0
func decodeCrockford(s string) ([]byte, error) {
	// Normalize per Crockford recommendations
	n := strings.ToUpper(s)
	n = strings.ReplaceAll(n, "-", "")
	n = strings.Map(func(r rune) rune {
		switch r {
		case 'I', 'L':
			return '1'
		case 'O':
			return '0'
		default:
			return r
		}
	}, n)
	return crockfordEncoding.DecodeString(n)
}
