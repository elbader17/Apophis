package tokens

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// verifyHMAC returns true when the signature over `signing` matches
// HMAC(secret, signing) using the JWT algorithm `alg`. Supported: HS256,
// HS384, HS512.
func verifyHMAC(alg, signing, secret string, sig []byte) (bool, error) {
	var h hash.Hash
	switch alg {
	case "HS256":
		h = hmac.New(sha256.New, []byte(secret))
	case "HS384":
		h = hmac.New(sha512.New384, []byte(secret))
	case "HS512":
		h = hmac.New(sha512.New, []byte(secret))
	default:
		return false, errUnsupportedAlg{alg: alg}
	}
	h.Write([]byte(signing))
	return hmac.Equal(h.Sum(nil), sig), nil
}

type errUnsupportedAlg struct{ alg string }

func (e errUnsupportedAlg) Error() string { return "unsupported JWT alg: " + e.alg }
