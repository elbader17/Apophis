package auth

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/apophis-eng/apophis/internal/logger"
	"github.com/apophis-eng/apophis/internal/models"
)

// ASREPRoastDetector probes candidate accounts for the DONT_REQUIRE_PREAUTH
// UAC bit. The detector is unauthenticated: it sends an AS-REQ with no
// padata and watches for either an AS-REP (preauth disabled → roastable)
// or a KDC_ERR_PREAUTH_REQUIRED error.
//
// Inputs:
//
//	dcIP    - the KDC's IPv4 address (the audit should have discovered
//	          this via an SRV _kerberos._tcp query or via DNS).
//	realm   - the uppercase Kerberos realm (typically the AD DNS domain in
//	          uppercase, e.g. "CORP.LOCAL").
//	users   - list of candidate account names (samAccountName).
type ASREPRoastDetector struct {
	Timeout       time.Duration
	MaxConcurrent int
}

// Result describes the per-account outcome.
type RoastResult struct {
	Username     string
	Roastable    bool
	Crackable    bool // RC4 etype — hash can be cracked with hashcat -m 7500
	EncPartEtype int
	ErrorCode    int
	Raw          []byte // AS-REP bytes (for offline cracking)
	Err          error
}

// NewASREPRoastDetector returns a detector with sensible defaults.
func NewASREPRoastDetector() *ASREPRoastDetector {
	return &ASREPRoastDetector{Timeout: 3 * time.Second, MaxConcurrent: 16}
}

// Probe sends AS-REQs for every username in the supplied list and returns
// the per-account outcome. The KDC is hit in parallel with bounded
// concurrency.
func (d *ASREPRoastDetector) Probe(ctx context.Context, dcIP, realm string, users []string) []RoastResult {
	out := make([]RoastResult, len(users))
	concurrency := d.MaxConcurrent
	if concurrency <= 0 {
		concurrency = 16
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, u := range users {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, u string) {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = d.probeOne(ctx, dcIP, realm, u)
		}(i, u)
	}
	wg.Wait()
	return out
}

// probeOne sends the AS-REQ and interprets the response.
func (d *ASREPRoastDetector) probeOne(ctx context.Context, dcIP, realm, user string) RoastResult {
	dialer := net.Dialer{Timeout: d.Timeout}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(dcIP, "88"))
	if err != nil {
		return RoastResult{Username: user, Err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(d.Timeout))
	// AS-REQ with no padata, only RC4-HMAC etype offered.
	pkt := ASReq(realm, []string{user}, []int{23})
	if _, err := conn.Write(pkt); err != nil {
		return RoastResult{Username: user, Err: err}
	}
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n < 4 {
		return RoastResult{Username: user, Err: fmt.Errorf("short response: %d bytes", n)}
	}
	resp := ParseASResponse(buf[:n])
	if resp == nil {
		return RoastResult{Username: user, Err: fmt.Errorf("unrecognised response tag 0x%02x", buf[0])}
	}
	r := RoastResult{
		Username:     user,
		Roastable:    !resp.IsError,
		Crackable:    resp.IsCrackable(),
		EncPartEtype: resp.EncPartEtype,
		ErrorCode:    resp.ErrorCode,
		Raw:          append([]byte{}, buf[:n]...),
	}
	return r
}

// ToFindings converts the per-account results into Finding entries suitable
// for inclusion in the audit report.
func ToFindings(dc string, results []RoastResult) []models.Finding {
	findings := []models.Finding{}
	var roastable, crackable []string
	for _, r := range results {
		if r.Roastable {
			roastable = append(roastable, r.Username)
		}
		if r.Crackable {
			crackable = append(crackable, r.Username)
		}
	}
	sort.Strings(roastable)
	sort.Strings(crackable)
	if len(roastable) > 0 {
		findings = append(findings, F(
			VectorASREPRoast,
			fmt.Sprintf("AS-REP-roastable accounts on %s (%d)", dc, len(roastable)),
			dc,
			models.SeverityHigh,
			fmt.Sprintf("accounts=%v", roastable),
			"One or more accounts have DONT_REQUIRE_PREAUTH set, allowing an unauthenticated attacker to request an AS-REP and crack the user's password offline (hashcat -m 7500).",
			"GetNPUsers.py -usersfile users.txt -dc-ip <DC> <REALM>/ -format hashcat",
			"Set the UF_DONT_REQUIRE_PREAUTH bit on all accounts. Audit accounts with 'Get-ADUser -Properties DoesNotRequirePreAuth | Where {$_.DoesNotRequirePreAuth -eq $true}'.",
		))
	}
	if len(crackable) > 0 {
		findings = append(findings, F(
			VectorASREPRoast,
			fmt.Sprintf("AS-REP-ROAST: RC4-HMAC accounts crackable offline on %s (%d)", dc, len(crackable)),
			dc,
			models.SeverityCritical,
			fmt.Sprintf("accounts=%v", crackable),
			"Crackable RC4-HMAC AS-REPs are equivalent to dumping the user's NT hash and running hashcat offline. With no network interaction, no account lockout, and no detection surface beyond a single UDP packet.",
			"hashcat -m 7500 asrep_hashes.txt rockyou.txt",
			"Force AES (etype 17/18) for AS-REPs: enforce the AES-only KDC registry key (Network security: Configure encryption types allowed for Kerberos = AES128_HMAC_SHA1, AES256_HMAC_SHA1).",
		))
	}
	if len(findings) == 0 {
		logger.Info("asrep-roast", fmt.Sprintf("no AS-REP-roastable accounts on %s", dc))
	}
	return findings
}
