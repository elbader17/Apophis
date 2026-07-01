package sources

import (
	"strings"
	"testing"
)

func TestExtractCVE(t *testing.T) {
	cases := map[string]string{
		"Critical RCE in FooBar (CVE-2024-12345) exploited in the wild": "CVE-2024-12345",
		"Multiple issues including CVE-2023-1234 and CVE-2023-5678":     "CVE-2023-1234",
		"no cve here":                   "",
		"CVE-2024-99999 is the big one": "CVE-2024-99999",
	}
	for in, want := range cases {
		got := extractCVE(in)
		if got != want {
			t.Errorf("extractCVE(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStripHTML(t *testing.T) {
	in := "<p>Hello <b>world</b></p>"
	want := "Hello world"
	if got := stripHTML(in); got != want {
		t.Errorf("stripHTML(%q) = %q, want %q", in, got, want)
	}
}

func TestBestSignature(t *testing.T) {
	f := Finding{Products: []string{"log4j"}, Title: "RCE in foo"}
	svc, ver := bestSignature(f)
	if svc != "log4j" || ver != "*" {
		t.Errorf("expected log4j/*, got %s/%s", svc, ver)
	}
	f2 := Finding{Title: "Apache Struts RCE"}
	svc2, _ := bestSignature(f2)
	if !strings.HasPrefix(svc2, "apache") {
		t.Errorf("expected apache prefix, got %s", svc2)
	}
}
