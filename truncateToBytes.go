package csrf

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
