package poc

import (
	"bytes"
	"context"
	"reflect"
	"testing"
)

func TestMSFRPCURLValid(t *testing.T) {
	cases := []struct {
		url   string
		valid bool
	}{
		{"http://127.0.0.1:55553", true},
		{"https://msf.lan:55553", true},
		{"ftp://nope", false},
		{"", false},
		{"http://", false},
		{"http://localhost:55553", true},
	}
	for _, c := range cases {
		m := &MSFRPC{URL: c.url}
		err := m.URLValid()
		if (err == nil) != c.valid {
			t.Errorf("URLValid(%q) valid=%v err=%v", c.url, c.valid, err)
		}
	}
}

func TestMsgpackRoundTripPrimitives(t *testing.T) {
	cases := []any{
		nil,
		true,
		false,
		uint8(7),
		uint16(258),
		uint32(65537),
		uint64(4294967297),
		int8(-5),
		int16(-258),
		int32(-65537),
		int64(-4294967297),
		int(42),
		"hello world",
		"",
		[]byte{0xde, 0xad, 0xbe, 0xef},
		[]any{1, "two", 3.0, nil, true},
		map[string]any{"a": 1, "b": "two", "c": []any{1, 2, 3}},
	}
	for _, v := range cases {
		enc, err := msgpackEncode(v)
		if err != nil {
			t.Fatalf("encode %v: %v", v, err)
		}
		dec, _, err := msgpackDecode(enc)
		if err != nil {
			t.Fatalf("decode %v: %v", v, err)
		}
		// Normalize for comparison: msgpack always returns map[string]any
		// with string keys (we coerce non-string map keys in the decoder).
		if !valueEqual(v, dec) {
			t.Errorf("round-trip mismatch:\n in=%v (%T)\nout=%v (%T)", v, v, dec, dec)
		}
	}
}

func valueEqual(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
		if reflect.TypeOf(a) != reflect.TypeOf(b) {
			// Allow int to come back as int64
			if ai, ok := a.(int); ok {
				if bi, ok := b.(int64); ok {
					return int64(ai) == bi
				}
			}
			return false
		}
	switch av := a.(type) {
	case []any:
		bv := b.([]any)
		if len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !valueEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		bv := b.(map[string]any)
		if len(av) != len(bv) {
			return false
		}
		for k, v := range av {
			if !valueEqual(v, bv[k]) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}

func TestMsgpackEncodeAuthLoginShape(t *testing.T) {
	// Reconstruct what MSFRPC.call sends for auth.login
	msg := []any{uint8(0), uint64(1), "auth.login", []any{"user", "pass"}}
	enc, err := msgpackEncode(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) < 10 {
		t.Fatalf("encoded msg too short: %d", len(enc))
	}
	// Decode the first array element
	v, n, err := msgpackDecode(enc)
	if err != nil {
		t.Fatal(err)
	}
	arr, ok := v.([]any)
	if !ok || len(arr) != 4 {
		t.Fatalf("expected 4-element array, got %v (n=%d)", v, n)
	}
	if arr[2] != "auth.login" {
		t.Fatalf("expected method 'auth.login', got %v", arr[2])
	}
	params, ok := arr[3].([]any)
	if !ok || len(params) != 2 {
		t.Fatalf("expected 2-element params, got %v", arr[3])
	}
	if params[0] != "user" || params[1] != "pass" {
		t.Fatalf("params mismatch: %v", params)
	}
}

func TestMSFRPCCallInvalidURL(t *testing.T) {
	m := NewMSFRPC(MSFRPCOptions{URL: "not-a-url"})
	if err := m.URLValid(); err == nil {
		t.Fatal("expected URL validation to fail")
	}
}

func TestMsgpackEncodeEmptyMap(t *testing.T) {
	b, err := msgpackEncode(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte{0x80}) {
		t.Fatalf("expected 0x80 for empty map, got %x", b)
	}
}

func TestMsgpackEncodeEmptyArray(t *testing.T) {
	b, err := msgpackEncode([]any{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte{0x90}) {
		t.Fatalf("expected 0x90 for empty array, got %x", b)
	}
}

func TestNucleiIsInstalled(t *testing.T) {
	n := DefaultNucleiDispatcher()
	_ = n.IsInstalled()
}

func TestNucleiDispatchNotInstalled(t *testing.T) {
	n := NucleiDispatcher{
		Binary:  "/nonexistent/nuclei-binary",
		Timeout: 1000,
	}
	if _, err := n.Dispatch(context.Background(), "/tmp/template.yaml", "10.10.10.5", nil); err == nil {
		t.Fatal("expected error when nuclei binary is missing")
	}
}

func TestBoofuzzIsInstalled(t *testing.T) {
	b := DefaultBoofuzzDispatcher()
	_ = b.IsInstalled()
}

func TestBoofuzzDispatchNotInstalled(t *testing.T) {
	b := BoofuzzDispatcher{
		Python:  "/nonexistent/python-binary",
		Timeout: 1000,
	}
	if _, err := b.Dispatch(context.Background(), "/tmp/fuzz.py", "10.10.10.5"); err == nil {
		t.Fatal("expected error when python binary is missing")
	}
}

func TestResolveDispatcher(t *testing.T) {
	cases := []struct {
		src     string
		want    string
	}{
		{"metasploit", "msfrpc"},
		{"Metasploit", "msfrpc"},
		{"msf", "msfrpc"},
		{"msfconsole", "msfrpc"},
		{"nuclei", "nuclei"},
		{"NUCLEI", "nuclei"},
		{"fuzz", "boofuzz"},
		{"boofuzz", "boofuzz"},
		{"exploitdb", ""},
		{"ghsa", ""},
		{"", ""},
	}
	for _, c := range cases {
		kind, _ := resolveDispatcher(c.src, nil, NucleiDispatcher{}, BoofuzzDispatcher{})
		if kind != c.want {
			t.Errorf("resolveDispatcher(%q) = %q, want %q", c.src, kind, c.want)
		}
	}
}

func TestParseModulePath(t *testing.T) {
	cases := map[string]struct{ a, b string }{
		"exploit/windows/smb/ms17_010_eternalblue": {"exploit", "windows/smb/ms17_010_eternalblue"},
		"auxiliary/scanner/http/":                    {"auxiliary", "scanner/http/"},
		"single":                                     {"", ""},
		"":                                           {"", ""},
	}
	for in, want := range cases {
		a, b := parseModulePath(in)
		if a != want.a || b != want.b {
			t.Errorf("parseModulePath(%q) = (%q,%q), want (%q,%q)", in, a, b, want.a, want.b)
		}
	}
}

func TestSplitKV(t *testing.T) {
	cases := map[string]struct {
		k, v string
		ok   bool
	}{
		"RHOSTS=10.10.10.5": {"RHOSTS", "10.10.10.5", true},
		"=value":            {"", "value", true},
		"noequals":          {"", "", false},
		"":                  {"", "", false},
	}
	for in, want := range cases {
		k, v, ok := splitKV(in)
		if k != want.k || v != want.v || ok != want.ok {
			t.Errorf("splitKV(%q) = (%q,%q,%v), want (%q,%q,%v)", in, k, v, ok, want.k, want.v, want.ok)
		}
	}
}
