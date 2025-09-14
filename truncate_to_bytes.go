package csrf

// truncateToBytes returns a prefix of s whose length in bytes is at most
// targetByteLength. It is used to cap the bcrypt plaintext input to the
// recommended 72-byte limit before hashing.
//
// Note: This function counts bytes, not runes, and may cut through a multi-byte
// UTF-8 rune boundary. Bcrypt operates on bytes, so this is acceptable for our
// usage, but the returned string may not be valid UTF-8 if s contains non-ASCII
// characters and truncation occurs mid-rune.
func truncateToBytes(s string, targetByteLength int) string {
	if len(s) <= targetByteLength {
		return s
	}
	// Combine counting and truncation
	i := 0
	for chars := 0; chars < targetByteLength; {
		if i >= len(s) {
			break
		}
		runeWidth := len([]byte(string(s[i])))
		if chars+runeWidth > targetByteLength {
			break
		}
		chars += runeWidth
		i++
	}
	return s[:i]
}
