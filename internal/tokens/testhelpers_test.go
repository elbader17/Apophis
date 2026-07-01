package tokens

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// verifyHMACForTest is a test-only convenience that returns the HMAC tag
// over the supplied signing input with the given secret. It mirrors what
// the JWT HS256 verifier does internally.
func verifyHMACForTest(alg, signing, secret string) ([]byte, error) {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(signing))
	return h.Sum(nil), nil
}

func base64RawURLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
