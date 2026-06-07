package models

import "testing"

func TestSeverityScore(t *testing.T) {
	tests := []struct {
		sev  Severity
		want int
	}{
		{SeverityCritical, 10},
		{SeverityHigh, 7},
		{SeverityMedium, 4},
		{SeverityLow, 2},
		{SeverityInfo, 0},
		{Severity("weird"), 0},
	}
	for _, tt := range tests {
		if got := tt.sev.Score(); got != tt.want {
			t.Errorf("Severity(%q).Score() = %d, want %d", tt.sev, got, tt.want)
		}
	}
}
