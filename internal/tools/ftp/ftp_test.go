package ftp

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/apophis-eng/apophis/internal/models"
)

func TestReadReplySingleLine(t *testing.T) {
	input := "220 Welcome\r\n"
	br := bufio.NewReader(bytes.NewReader([]byte(input)))
	line, err := readReply(br)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if line[:3] != "220" {
		t.Fatalf("expected reply code 220, got %q", line)
	}
}

func TestReadReplyMultiLine(t *testing.T) {
	input := "230-A\r\n230 User logged in\r\n"
	br := bufio.NewReader(bytes.NewReader([]byte(input)))
	line, err := readReply(br)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if line[:3] != "230" {
		t.Fatalf("expected code 230, got %q", line)
	}
	if !bytes.Contains([]byte(line), []byte("User logged in")) {
		t.Fatalf("expected body, got %q", line)
	}
}

func TestPortOpen(t *testing.T) {
	ports := []models.PortInfo{{Port: 22}, {Port: 21}}
	if !portOpen(ports, 21) {
		t.Fatal("expected 21 to be open")
	}
	if portOpen(ports, 80) {
		t.Fatal("80 should not be in ports list")
	}
	if portOpen(nil, 21) {
		t.Fatal("nil list should not match")
	}
}
