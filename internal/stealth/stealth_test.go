package stealth

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestPacerAcquireRelease(t *testing.T) {
	p := NewPacer(1000, 0, 4)
	ctx := context.Background()
	if err := p.Acquire(ctx); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	p.Release()
	if err := p.Acquire(ctx); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	p.Release()
}

func TestPacerAdaptiveBackoff(t *testing.T) {
	p := NewPacer(1000, 0, 4)
	p.adaptive = true
	p.slowFactor = 1.0
	for i := 0; i < 30; i++ {
		p.ReportTimeout()
	}
	if p.slowFactor <= 1.0 {
		t.Fatalf("expected slowFactor to grow with timeouts, got %.2f", p.slowFactor)
	}
}

func TestPacerAcquireHonoursContext(t *testing.T) {
	p := NewPacer(1, 0, 1)
	p.slowFactor = 1.0
	// Fill the in-flight slot so the next acquire blocks on the timer.
	if err := p.Acquire(context.Background()); err != nil {
		t.Fatalf("warmup acquire: %v", err)
	}
	defer p.Release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Acquire(ctx); err == nil {
		t.Fatalf("expected acquire to honour cancelled context")
	}
}

func TestDecoyRouterIsDecoy(t *testing.T) {
	d := &DecoyRouter{Decoys: []string{"1.2.3.4", "noise.example.com"}}
	if !d.IsDecoy("1.2.3.4") {
		t.Fatal("expected 1.2.3.4 to be recognised as decoy")
	}
	if d.IsDecoy("9.9.9.9") {
		t.Fatal("9.9.9.9 should not be a decoy")
	}
}

func TestEvasionProfileApply(t *testing.T) {
	p := NewEvasionProfile("high")
	if p.Level != "high" {
		t.Fatalf("expected high, got %s", p.Level)
	}
	if !p.RandomPaths {
		t.Fatal("high profile should randomise paths")
	}
	if p.AcceptLang == "" {
		t.Fatal("high profile should set accept-language")
	}
}

func TestWAFDetectorRejectsEmptyURL(t *testing.T) {
	d := NewWAFDetector(time.Second)
	if info := d.Detect(context.Background(), ""); info != nil {
		t.Fatal("expected nil WAFInfo for empty URL")
	}
}

func TestPacerConcurrent(t *testing.T) {
	p := NewPacer(200, 1, 8)
	var counter atomic.Int64
	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func() {
			for j := 0; j < 5; j++ {
				_ = p.Acquire(context.Background())
				counter.Add(1)
				p.Release()
			}
		}()
	}
	go func() { done <- struct{}{} }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("pacer blocked; counter=%d", counter.Load())
	}
}
