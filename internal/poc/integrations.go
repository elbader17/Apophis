package poc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MSFRPC is a minimal client for the Metasploit msfrpcd (msgpack-rpc) daemon.
// We hand-roll the msgpack codec for the few types we need (maps, strings,
// ints, nils, arrays, booleans, bin8) so we don't add a runtime dep.
type MSFRPC struct {
	URL    string
	User   string
	Pass   string
	Token  string
	mu     sync.Mutex
	idCtr  uint64
	Client *http.Client
}

type MSFRPCOptions struct {
	URL  string
	User string
	Pass string
}

func NewMSFRPC(opts MSFRPCOptions) *MSFRPC {
	return &MSFRPC{
		URL:    opts.URL,
		User:   opts.User,
		Pass:   opts.Pass,
		Client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (m *MSFRPC) URLValid() error {
	if m.URL == "" {
		return errors.New("msfrpc URL is empty")
	}
	u, err := url.Parse(m.URL)
	if err != nil {
		return fmt.Errorf("parse msfrpc URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("msfrpc URL must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("msfrpc URL missing host")
	}
	return nil
}

func (m *MSFRPC) Login(ctx context.Context) error {
	if err := m.URLValid(); err != nil {
		return err
	}
	resp, err := m.call(ctx, "auth.login", []any{m.User, m.Pass})
	if err != nil {
		return err
	}
	tok, ok := resp.(string)
	if !ok {
		return fmt.Errorf("auth.login returned non-string: %T", resp)
	}
	m.mu.Lock()
	m.Token = tok
	m.mu.Unlock()
	return nil
}

func (m *MSFRPC) ModuleExecute(ctx context.Context, moduleType, moduleName string, opts map[string]any) (string, error) {
	if m.Token == "" {
		if err := m.Login(ctx); err != nil {
			return "", err
		}
	}
	params := []any{moduleType, moduleName, opts}
	resp, err := m.call(ctx, "module.execute", params)
	if err != nil {
		return "", err
	}
	jobID, ok := resp.(string)
	if !ok {
		return "", fmt.Errorf("module.execute returned non-string job id: %T", resp)
	}
	return jobID, nil
}

func (m *MSFRPC) call(ctx context.Context, method string, params []any) (any, error) {
	m.mu.Lock()
	id := atomic.AddUint64(&m.idCtr, 1)
	m.mu.Unlock()

	msg := []any{uint8(0), id, method, params}
	payload, err := msgpackEncode(msg)
	if err != nil {
		return nil, fmt.Errorf("encode msgpack: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.URL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "binary/message-pack")
	resp, err := m.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("msfrpc http %d: %s", resp.StatusCode, string(body))
	}
	decoded, _, err := msgpackDecode(body)
	if err != nil {
		return nil, fmt.Errorf("decode msgpack: %w", err)
	}
	arr, ok := decoded.([]any)
	if !ok || len(arr) < 4 {
		return nil, fmt.Errorf("unexpected msfrpc response shape: %T", decoded)
	}
	errV := arr[2]
	resV := arr[3]
	if errV != nil {
		if s, ok := errV.(string); ok {
			return nil, fmt.Errorf("msfrpc error: %s", s)
		}
		return nil, fmt.Errorf("msfrpc error: %v", errV)
	}
	return resV, nil
}

// -- Minimal msgpack codec ----------------------------------------------------
// Supports: nil, bool, int (signed/unsigned 8/16/32/64), uint, float64,
// string, []byte, []any, map[string]any, nested combinations.

func msgpackEncode(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := msgpackWrite(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func msgpackWrite(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteByte(0xc0)
	case bool:
		if x {
			buf.WriteByte(0xc3)
		} else {
			buf.WriteByte(0xc2)
		}
	case uint8:
		if x < 128 {
			buf.WriteByte(x)
		} else {
			buf.WriteByte(0xcc)
			buf.WriteByte(x)
		}
	case uint16:
		buf.WriteByte(0xcd)
		_ = binary.Write(buf, binary.BigEndian, x)
	case uint32:
		buf.WriteByte(0xce)
		_ = binary.Write(buf, binary.BigEndian, x)
	case uint64:
		buf.WriteByte(0xcf)
		_ = binary.Write(buf, binary.BigEndian, x)
	case int8:
		if x >= -32 {
			buf.WriteByte(byte(x) & 0xff)
		} else {
			buf.WriteByte(0xd0)
			buf.WriteByte(byte(x))
		}
	case int16:
		buf.WriteByte(0xd1)
		_ = binary.Write(buf, binary.BigEndian, x)
	case int32:
		buf.WriteByte(0xd2)
		_ = binary.Write(buf, binary.BigEndian, x)
	case int64:
		buf.WriteByte(0xd3)
		_ = binary.Write(buf, binary.BigEndian, x)
	case int:
		return msgpackWrite(buf, int64(x))
	case string:
		writeString(buf, x)
	case []byte:
		writeBin(buf, x)
	case float32:
		buf.WriteByte(0xca)
		_ = binary.Write(buf, binary.BigEndian, x)
	case float64:
		buf.WriteByte(0xcb)
		_ = binary.Write(buf, binary.BigEndian, x)
	case []any:
		writeArrayHeader(buf, len(x))
		for _, item := range x {
			if err := msgpackWrite(buf, item); err != nil {
				return err
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		writeMapHeader(buf, len(x))
		for _, k := range keys {
			if err := msgpackWrite(buf, k); err != nil {
				return err
			}
			if err := msgpackWrite(buf, x[k]); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("msgpack: unsupported type %T", v)
	}
	return nil
}

func writeString(buf *bytes.Buffer, s string) {
	b := []byte(s)
	n := len(b)
	switch {
	case n <= 31:
		buf.WriteByte(0xa0 | byte(n))
		buf.Write(b)
	case n <= 255:
		buf.WriteByte(0xd9)
		buf.WriteByte(byte(n))
		buf.Write(b)
	case n <= 65535:
		buf.WriteByte(0xda)
		_ = binary.Write(buf, binary.BigEndian, uint16(n))
		buf.Write(b)
	default:
		buf.WriteByte(0xdb)
		_ = binary.Write(buf, binary.BigEndian, uint32(n))
		buf.Write(b)
	}
}

func writeBin(buf *bytes.Buffer, b []byte) {
	n := len(b)
	switch {
	case n <= 255:
		buf.WriteByte(0xc4)
		buf.WriteByte(byte(n))
		buf.Write(b)
	case n <= 65535:
		buf.WriteByte(0xc5)
		_ = binary.Write(buf, binary.BigEndian, uint16(n))
		buf.Write(b)
	default:
		buf.WriteByte(0xc6)
		_ = binary.Write(buf, binary.BigEndian, uint32(n))
		buf.Write(b)
	}
}

func writeArrayHeader(buf *bytes.Buffer, n int) {
	switch {
	case n <= 15:
		buf.WriteByte(0x90 | byte(n))
	case n <= 65535:
		buf.WriteByte(0xdc)
		_ = binary.Write(buf, binary.BigEndian, uint16(n))
	default:
		buf.WriteByte(0xdd)
		_ = binary.Write(buf, binary.BigEndian, uint32(n))
	}
}

func writeMapHeader(buf *bytes.Buffer, n int) {
	switch {
	case n <= 15:
		buf.WriteByte(0x80 | byte(n))
	case n <= 65535:
		buf.WriteByte(0xde)
		_ = binary.Write(buf, binary.BigEndian, uint16(n))
	default:
		buf.WriteByte(0xdf)
		_ = binary.Write(buf, binary.BigEndian, uint32(n))
	}
}

func msgpackDecode(b []byte) (any, int, error) {
	v, n, err := msgpackRead(b, 0)
	return v, n, err
}

func msgpackRead(b []byte, off int) (any, int, error) {
	if off >= len(b) {
		return nil, off, io.ErrUnexpectedEOF
	}
	c := b[off]
	off++
	switch {
	case c <= 0x7f:
		return uint8(c), off, nil
	case c >= 0xe0:
		return int8(c), off, nil
	case c == 0xc0:
		return nil, off, nil
	case c == 0xc2:
		return false, off, nil
	case c == 0xc3:
		return true, off, nil
	case c == 0xc4:
		n := int(b[off])
		off++
		return b[off : off+n], off + n, nil
	case c == 0xc5:
		var n uint16
		_ = binary.Read(bytes.NewReader(b[off:off+2]), binary.BigEndian, &n)
		off += 2
		return b[off : off+int(n)], off + int(n), nil
	case c == 0xc6:
		var n uint32
		_ = binary.Read(bytes.NewReader(b[off:off+4]), binary.BigEndian, &n)
		off += 4
		return b[off : off+int(n)], off + int(n), nil
	case c == 0xca:
		var v float32
		_ = binary.Read(bytes.NewReader(b[off:off+4]), binary.BigEndian, &v)
		return v, off + 4, nil
	case c == 0xcb:
		var v float64
		_ = binary.Read(bytes.NewReader(b[off:off+8]), binary.BigEndian, &v)
		return v, off + 8, nil
	case c == 0xcc:
		return b[off], off + 1, nil
	case c == 0xcd:
		return uint16(binary.BigEndian.Uint16(b[off:])), off + 2, nil
	case c == 0xce:
		return binary.BigEndian.Uint32(b[off:]), off + 4, nil
	case c == 0xcf:
		return binary.BigEndian.Uint64(b[off:]), off + 8, nil
	case c == 0xd0:
		return int8(b[off]), off + 1, nil
	case c == 0xd1:
		return int16(binary.BigEndian.Uint16(b[off:])), off + 2, nil
	case c == 0xd2:
		return int32(binary.BigEndian.Uint32(b[off:])), off + 4, nil
	case c == 0xd3:
		return int64(binary.BigEndian.Uint64(b[off:])), off + 8, nil
	case c == 0xd9:
		n := int(b[off])
		off++
		return string(b[off : off+n]), off + n, nil
	case c == 0xda:
		var n uint16
		_ = binary.Read(bytes.NewReader(b[off:off+2]), binary.BigEndian, &n)
		off += 2
		return string(b[off : off+int(n)]), off + int(n), nil
	case c == 0xdb:
		var n uint32
		_ = binary.Read(bytes.NewReader(b[off:off+4]), binary.BigEndian, &n)
		off += 4
		return string(b[off : off+int(n)]), off + int(n), nil
	case c >= 0xa0 && c <= 0xbf:
		n := int(c & 0x1f)
		return string(b[off : off+n]), off + n, nil
	case c >= 0x90 && c <= 0x9f:
		return readArray(b, off, int(c&0x0f))
	case c == 0xdc:
		var n uint16
		_ = binary.Read(bytes.NewReader(b[off:off+2]), binary.BigEndian, &n)
		return readArray(b, off+2, int(n))
	case c == 0xdd:
		var n uint32
		_ = binary.Read(bytes.NewReader(b[off:off+4]), binary.BigEndian, &n)
		return readArray(b, off+4, int(n))
	case c >= 0x80 && c <= 0x8f:
		return readMap(b, off, int(c&0x0f))
	case c == 0xde:
		var n uint16
		_ = binary.Read(bytes.NewReader(b[off:off+2]), binary.BigEndian, &n)
		return readMap(b, off+2, int(n))
	case c == 0xdf:
		var n uint32
		_ = binary.Read(bytes.NewReader(b[off:off+4]), binary.BigEndian, &n)
		return readMap(b, off+4, int(n))
	}
	return nil, off, fmt.Errorf("msgpack: unknown type byte 0x%02x at offset %d", c, off-1)
}

func readArray(b []byte, off int, n int) (any, int, error) {
	out := make([]any, 0, n)
	for i := 0; i < n; i++ {
		v, no, err := msgpackRead(b, off)
		if err != nil {
			return nil, off, err
		}
		out = append(out, v)
		off = no
	}
	return out, off, nil
}

func readMap(b []byte, off int, n int) (any, int, error) {
	out := make(map[string]any, n)
	for i := 0; i < n; i++ {
		k, ko, err := msgpackRead(b, off)
		if err != nil {
			return nil, off, err
		}
		ks, ok := k.(string)
		if !ok {
			ks = fmt.Sprintf("%v", k)
		}
		v, vo, err := msgpackRead(b, ko)
		if err != nil {
			return nil, ko, err
		}
		out[ks] = v
		off = vo
	}
	return out, off, nil
}

// -- Nuclei dispatcher --------------------------------------------------------

type NucleiDispatcher struct {
	Binary  string
	TemplatesDir string
	ExtraArgs []string
	Timeout time.Duration
}

func DefaultNucleiDispatcher() NucleiDispatcher {
	return NucleiDispatcher{
		Binary:  "nuclei",
		Timeout: 5 * time.Minute,
	}
}

func (n NucleiDispatcher) IsInstalled() bool {
	bin := n.Binary
	if bin == "" {
		bin = "nuclei"
	}
	_, err := exec.LookPath(bin)
	return err == nil
}

func (n NucleiDispatcher) Dispatch(ctx context.Context, templatePath, target string, extraArgs []string) (*RunResult, error) {
	if !n.IsInstalled() {
		return nil, errors.New("nuclei binary not found in PATH; install nuclei or set the Binary field")
	}
	args := []string{"-t", templatePath, "-u", target, "-json-export", "-"}
	if n.TemplatesDir != "" {
		args = append(args, "-t", n.TemplatesDir)
	}
	args = append(args, n.ExtraArgs...)
	args = append(args, extraArgs...)

	started := time.Now()
	cmd := exec.CommandContext(ctx, n.Binary, args...)
	stdout := &limitedBuffer{limit: 2 << 20}
	stderr := &limitedBuffer{limit: 1 << 20}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	tctx, cancel := context.WithTimeout(ctx, n.Timeout)
	defer cancel()
	select {
	case <-tctx.Done():
		_ = cmd.Process.Kill()
		<-done
		return &RunResult{
			StartedAt:  started,
			FinishedAt: time.Now(),
			DurationMs: time.Since(started).Milliseconds(),
			ExitCode:   -1,
			Signal:     "KILLED_TIMEOUT",
			Stdout:     stdout.String(),
			Stderr:     stderr.String() + "\n[killed: nuclei timeout]",
		}, nil
	case err := <-done:
		finished := time.Now()
		res := &RunResult{
			StartedAt:  started,
			FinishedAt: finished,
			DurationMs: finished.Sub(started).Milliseconds(),
			Stdout:     stdout.String(),
			Stderr:     stderr.String(),
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
		} else if err != nil {
			res.Error = err.Error()
		} else {
			res.ExitCode = 0
		}
		return res, nil
	}
}

// -- Boofuzz dispatcher -------------------------------------------------------

type BoofuzzDispatcher struct {
	Python  string
	Binary  string
	WorkDir string
	Timeout time.Duration
}

func DefaultBoofuzzDispatcher() BoofuzzDispatcher {
	return BoofuzzDispatcher{
		Python:  "python3",
		Binary:  "boofuzz",
		Timeout: 10 * time.Minute,
	}
}

func (b BoofuzzDispatcher) IsInstalled() bool {
	py := b.Python
	if py == "" {
		py = "python3"
	}
	_, err := exec.LookPath(py)
	return err == nil
}

func (b BoofuzzDispatcher) Dispatch(ctx context.Context, scriptPath, target string) (*RunResult, error) {
	if !b.IsInstalled() {
		return nil, errors.New("python3 not found; boofuzz needs python3")
	}
	args := []string{scriptPath, "--target", target}
	started := time.Now()
	cmd := exec.CommandContext(ctx, b.Python, args...)
	cmd.Dir = b.WorkDir
	stdout := &limitedBuffer{limit: 2 << 20}
	stderr := &limitedBuffer{limit: 1 << 20}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	tctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	select {
	case <-tctx.Done():
		_ = cmd.Process.Kill()
		<-done
		return &RunResult{
			StartedAt:  started,
			FinishedAt: time.Now(),
			DurationMs: time.Since(started).Milliseconds(),
			ExitCode:   -1,
			Signal:     "KILLED_TIMEOUT",
			Stdout:     stdout.String(),
			Stderr:     stderr.String() + "\n[killed: boofuzz timeout]",
		}, nil
	case err := <-done:
		finished := time.Now()
		res := &RunResult{
			StartedAt:  started,
			FinishedAt: finished,
			DurationMs: finished.Sub(started).Milliseconds(),
			Stdout:     stdout.String(),
			Stderr:     stderr.String(),
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
		} else if err != nil {
			res.Error = err.Error()
		}
		return res, nil
	}
}

// resolveDispatcher picks the right integration based on PoC.Source
// (e.g. "metasploit", "nuclei", "fuzz"). Returns nil for sources that
// should be handled by the standard L1/L2 sandbox.
func resolveDispatcher(src string, msf *MSFRPC, nuclei NucleiDispatcher, fuzz BoofuzzDispatcher) (kind string, _ any) {
	switch strings.ToLower(src) {
	case "metasploit", "msf", "msfconsole":
		return "msfrpc", msf
	case "nuclei":
		return "nuclei", nuclei
	case "fuzz", "boofuzz":
		return "boofuzz", fuzz
	}
	return "", nil
}

// -- Utility ------------------------------------------------------------------

func isMSFRPCListening(ctx context.Context, addr string) bool {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

var _ = json.Marshal
var _ = isMSFRPCListening
