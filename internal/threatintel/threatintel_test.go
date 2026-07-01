package threatintel

import "testing"

func TestIsIP(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"1.2.3.4", true},
		{"example.com", false},
		{"not / valid", false},
		{"127.0.0.1", true},
	}
	for _, c := range cases {
		if got := IsIP(c.in); got != c.want {
			t.Errorf("IsIP(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestNewKeyedProvidersDisabledWhenKeysEmpty(t *testing.T) {
	provs := New(ProviderConfig{})
	// Shodan InternetDB is keyless, so it is always present and enabled.
	hasShodan := false
	for _, p := range provs {
		if p.Name() == "shodan" {
			if !p.Enabled() {
				t.Errorf("Shodan should be enabled even without a key")
			}
			hasShodan = true
			continue
		}
		if p.Enabled() {
			t.Errorf("%s should be disabled with no key", p.Name())
		}
	}
	if !hasShodan {
		t.Fatal("expected Shodan provider, none registered")
	}
}

func TestVerdictScoreClassification(t *testing.T) {
	v := Verdict{Source: "test", Score: 0.5, Tags: []string{"foo"}}
	if v.Malicious {
		t.Fatal("score 0.5 should not be malicious by default")
	}
	v.Malicious = true
	if !v.Malicious {
		t.Fatal("malicious flag should round-trip")
	}
}
