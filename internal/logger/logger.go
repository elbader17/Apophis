package logger

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/fatih/color"
)

var (
	mu      sync.Mutex
	verbose = false
)

func SetVerbose(v bool) { verbose = v }

func timestamp() string {
	return time.Now().Format("15:04:05.000")
}

func out() *os.File {
	return os.Stderr
}

func Info(tag, msg string) {
	mu.Lock()
	defer mu.Unlock()
	c := color.New(color.FgCyan)
	c.Fprintf(out(), "[%s] ", timestamp())
	color.New(color.FgWhite, color.Bold).Fprintf(out(), "%-8s ", "["+tag+"]")
	fmt.Fprintln(out(), msg)
}

func Success(tag, msg string) {
	mu.Lock()
	defer mu.Unlock()
	c := color.New(color.FgCyan)
	c.Fprintf(out(), "[%s] ", timestamp())
	color.New(color.FgGreen, color.Bold).Fprintf(out(), "%-8s ", "["+tag+"]")
	fmt.Fprintln(out(), msg)
}

func Warn(tag, msg string) {
	mu.Lock()
	defer mu.Unlock()
	c := color.New(color.FgCyan)
	c.Fprintf(out(), "[%s] ", timestamp())
	color.New(color.FgYellow, color.Bold).Fprintf(out(), "%-8s ", "["+tag+"]")
	fmt.Fprintln(out(), msg)
}

func Error(tag, msg string) {
	mu.Lock()
	defer mu.Unlock()
	c := color.New(color.FgCyan)
	c.Fprintf(out(), "[%s] ", timestamp())
	color.New(color.FgRed, color.Bold).Fprintf(out(), "%-8s ", "["+tag+"]")
	fmt.Fprintln(out(), msg)
}

func Vuln(severity, target, title string) {
	mu.Lock()
	defer mu.Unlock()
	c := color.New(color.FgCyan)
	c.Fprintf(out(), "[%s] ", timestamp())
	var sc *color.Color
	switch severity {
	case "CRITICAL":
		sc = color.New(color.FgRed, color.Bold)
	case "HIGH":
		sc = color.New(color.FgRed)
	case "MEDIUM":
		sc = color.New(color.FgYellow)
	case "LOW":
		sc = color.New(color.FgBlue)
	default:
		sc = color.New(color.FgWhite)
	}
	sc.Fprintf(out(), "[%-8s] ", "["+severity+"]")
	fmt.Fprintf(out(), "%s -> %s\n", target, title)
}

func Debug(tag, msg string) {
	if !verbose {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	c := color.New(color.FgCyan)
	c.Fprintf(out(), "[%s] ", timestamp())
	color.New(color.FgMagenta, color.Bold).Fprintf(out(), "%-8s ", "[DBG-"+tag+"]")
	fmt.Fprintln(out(), msg)
}

func Banner() {
	c := color.New(color.FgRed, color.Bold)
	fmt.Fprintln(out())
	c.Fprintln(out(), ` █████  ██████  ██   ██  █████  ██████  ██    ██ ██ ███████`)
	c.Fprintln(out(), `██   ██ ██   ██ ██   ██ ██   ██ ██   ██ ██    ██ ██ ██`)
	c.Fprintln(out(), `███████ ██████  ███████ ██   ██ ██████  ████████ ██ ███████ `)
	c.Fprintln(out(), `██   ██ ██      ██   ██ ██   ██ ██      ██    ██ ██      ██`)
	c.Fprintln(out(), `██   ██ ██      ██   ██  █████  ██      ██    ██ ██ ███████`)
	color.New(color.FgWhite, color.FgHiBlack).Fprintln(out(), "    vulnerability chaos engine")
	fmt.Fprintln(out())
}
