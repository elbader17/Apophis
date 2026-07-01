package ldap

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// BER encoder/decoder helpers — just enough LDAP wire protocol for our
// anonymous bind + root DSE search. We support the tag families we actually
// emit: integer, octet string, sequence, enumerated, application-bind and
// application-search.

func berLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	case n < 0x10000:
		return []byte{0x82, byte(n >> 8), byte(n)}
	default:
		return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func berInteger(v int) []byte {
	b := []byte{0x02, 0x01, byte(v)}
	return b
}

func berEnum(v int) []byte {
	return []byte{0x0a, 0x01, byte(v)}
}

func berOctet(s string) []byte {
	l := berLen(len(s))
	return append(append([]byte{0x04}, l...), []byte(s)...)
}

func berSequenceStart(tag byte, bodyLen int) []byte {
	l := berLen(bodyLen)
	return append([]byte{tag}, l...)
}

func berAppend(tag byte, payload []byte) []byte {
	l := berLen(len(payload))
	return append(append([]byte{tag}, l...), payload...)
}

func berIntegerBytes(v int) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	if v < 0 {
		// Two's complement; we don't emit negative integers in this package.
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(int32(v)))
		return buf
	}
	if v < 0x80 {
		return []byte{byte(v)}
	}
	if v < 0x8000 {
		return []byte{byte(v >> 8), byte(v)}
	}
	if v < 0x800000 {
		return []byte{byte(v >> 16), byte(v >> 8), byte(v)}
	}
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func berIntegerExplicit(v int) []byte {
	b := berIntegerBytes(v)
	return append([]byte{0x02, byte(len(b))}, b...)
}

// buildBindRequest emits a minimal LDAPv3 anonymous bind.
func buildBindRequest(msgID int, dn, password string) []byte {
	bind := []byte{0x60, 0x05 + byte(len(dn)+len(password))}
	bind = append(bind, 0x02, 0x01, 0x03) // LDAPv3
	bind = append(bind, berOctet(dn)...)
	bind = append(bind, 0x80, byte(len(password)))
	bind = append(bind, []byte(password)...)
	msg := berIntegerExplicit(msgID)
	body := append(msg, bind...)
	return append(berSequenceStart(0x30, len(body)), body...)
}

// buildSearchRequest emits a base-scope search for (objectClass=*) which is
// the canonical root DSE request.
func buildSearchRequest(msgID int, base, filter string) []byte {
	filterBER := berAppend(0xa0, berOctet(filter)) // present filter
	body := berOctet(base)
	body = append(body, 0x0a, 0x01, 0x00)         // scope: base
	body = append(body, 0x0a, 0x01, 0x00)         // deref: never
	body = append(body, berIntegerExplicit(0)...) // sizeLimit
	body = append(body, berIntegerExplicit(0)...) // timeLimit
	body = append(body, 0x01, 0x01, 0x00)         // typesOnly = false
	body = append(body, filterBER...)
	body = append(body, 0x30, 0x00) // attribute list (empty = all attrs)

	// SearchRequest [APPLICATION 3]
	search := []byte{0x63}
	l := berLen(len(body))
	search = append(search, l...)
	search = append(search, body...)

	msg := berIntegerExplicit(msgID)
	envelope := append(msg, search...)
	return append(berSequenceStart(0x30, len(envelope)), envelope...)
}

// walkAttributes walks the bytes from a SearchResultEntry + subsequent
// SearchResultReference messages and invokes fn(attrName, attrValues) for
// each attribute decoded. It is tolerant of malformed input.
func walkAttributes(b []byte, fn func(name string, vals []string)) {
	for i := 0; i < len(b); {
		if i+2 > len(b) {
			return
		}
		tag := b[i]
		if tag == 0x65 {
			// SearchResultDone — stop.
			return
		}
		length, hdr := decodeLen(b[i+1:])
		if length < 0 {
			return
		}
		total := 1 + hdr + length
		if i+total > len(b) {
			return
		}
		inner := b[i+1+hdr : i+total]
		if tag == 0x64 {
			// SearchResultEntry [APPLICATION 4]
			walkSearchResultEntry(inner, fn)
		}
		i += total
	}
}

func walkSearchResultEntry(b []byte, fn func(name string, vals []string)) {
	// objectName (octet string), then PartialAttributeList (sequence).
	i := 0
	if i < len(b) && b[i] == 0x04 {
		_, hdr := decodeLen(b[i+1:])
		i += 1 + hdr
	}
	if i >= len(b) {
		return
	}
	if b[i] != 0x30 {
		return
	}
	seqLen, hdr := decodeLen(b[i+1:])
	seq := b[i+1+hdr : i+1+hdr+seqLen]
	if seqLen+hdr+1 > len(b) {
		seq = b[i+1+hdr:]
	}
	walkPartialAttrs(seq, fn)
}

func walkPartialAttrs(b []byte, fn func(name string, vals []string)) {
	i := 0
	for i < len(b) {
		if b[i] != 0x30 {
			return
		}
		l, hdr := decodeLen(b[i+1:])
		seqEnd := i + 1 + hdr + l
		seq := b[i+1+hdr : seqEnd]
		if i+1+hdr+l > len(b) {
			seq = b[i+1+hdr:]
		}
		// seq = name OCTET STRING, SET OF vals
		ni := 0
		if ni >= len(seq) || seq[ni] != 0x04 {
			i = seqEnd
			continue
		}
		nmLen, nmHdr := decodeLen(seq[ni+1:])
		nmEnd := ni + 1 + nmHdr + nmLen
		if nmEnd > len(seq) {
			i = seqEnd
			continue
		}
		name := strings.ToLower(string(seq[ni+1+nmHdr : nmEnd]))
		// SET OF values
		vi := nmEnd
		var vals []string
		if vi < len(seq) && seq[vi] == 0x31 {
			vl, vh := decodeLen(seq[vi+1:])
			vend := vi + 1 + vh + vl
			if vend > len(seq) {
				vend = len(seq)
			}
			vals = readStrings(seq[vi+1+vh : vend])
			vi = vend
		}
		fn(name, vals)
		i = seqEnd
	}
}

func readStrings(b []byte) []string {
	out := []string{}
	i := 0
	for i < len(b) {
		if b[i] != 0x04 {
			return out
		}
		l, hdr := decodeLen(b[i+1:])
		if l < 0 {
			return out
		}
		end := i + 1 + hdr + l
		if end > len(b) {
			return out
		}
		out = append(out, string(b[i+1+hdr:end]))
		i = end
	}
	return out
}

// decodeLen returns the length value and the number of bytes consumed from
// the start of the length field. length==-1 indicates an indefinite or
// malformed length which the caller must treat as a parse stop.
func decodeLen(b []byte) (length, hdr int) {
	if len(b) == 0 {
		return -1, 0
	}
	if b[0] < 0x80 {
		return int(b[0]), 1
	}
	n := int(b[0] & 0x7f)
	if n == 0 || n > 4 || len(b) < 1+n {
		return -1, 1
	}
	length = 0
	for j := 1; j <= n; j++ {
		length = length<<8 | int(b[j])
	}
	return length, 1 + n
}

// ensure unused import when removing debug code
var _ = fmt.Sprint
