package auth

import (
	"fmt"
	"sort"
	"strings"

	"github.com/apophis-eng/apophis/internal/models"
)

// SprayWord is one candidate password to try. The Targets field narrows
// which accounts the word should be sprayed against (empty = everyone).
type SprayWord struct {
	Word    string
	Reason  string
	Targets []string
}

// SprayConfig configures the wordlist generator.
type SprayConfig struct {
	Company  string   // "acme" — used as the seed for company-specific words
	Domain   string   // "acme.com" — splits on "." for base words
	Years    []int    // years to append (default = current year and ±1)
	Seasons  []string // seasons to append (default = Spring|Summer|Fall|Winter)
	MaxWords int      // cap the output (default 200)
	Include  []string // extra static words (already lowercased)
}

// GenerateSprayWords produces a small, targeted wordlist suitable for a
// stealthy password-spray campaign. The output is sorted and deduped.
//
// We follow the same heuristic that real attackers use: company-name
// mutations + seasons + years + common defaults, then dedupe and cap.
//
// Examples (Company="acme", Year=2025):
//
//	acme2025  acme2025!  Acme123  Acme@2025  AcmeSpring2025  …
func GenerateSprayWords(cfg SprayConfig) []SprayWord {
	if cfg.Company == "" && cfg.Domain == "" {
		cfg.Company = "company"
	}
	if cfg.Domain != "" && cfg.Company == "" {
		cfg.Domain = strings.ToLower(strings.TrimSpace(cfg.Domain))
		cfg.Company = strings.SplitN(cfg.Domain, ".", 2)[0]
	}
	company := strings.ToLower(strings.TrimSpace(cfg.Company))
	capCompany := strings.Title(company)
	years := cfg.Years
	if len(years) == 0 {
		y := 2025
		years = []int{y - 1, y, y + 1}
	}
	seasons := cfg.Seasons
	if len(seasons) == 0 {
		seasons = []string{"Spring", "Summer", "Fall", "Winter", "Autumn"}
	}
	max := cfg.MaxWords
	if max <= 0 {
		max = 200
	}
	seen := map[string]bool{}
	out := []SprayWord{}

	add := func(w, reason string) {
		if w == "" || seen[w] {
			return
		}
		seen[w] = true
		out = append(out, SprayWord{Word: w, Reason: reason})
	}

	// Always include the company lowercase + capitalized.
	add(company, "company-name")
	add(capCompany, "company-name-capitalised")

	// Common defaults.
	defaults := []string{
		"password", "Password", "Password1", "Password1!",
		"Welcome1", "Welcome1!", "Welcome123",
		"Summer2025", "Winter2025", "Fall2025",
		"Company1", "Company123", "Company1234",
		"Changeme", "Changeme1", "ChangeMe",
		"Password@1", "P@ssw0rd", "P@ssword1",
		"Qwerty123", "Qwerty123!",
	}
	for _, d := range defaults {
		add(d, "common-default")
	}
	for _, w := range cfg.Include {
		add(strings.ToLower(strings.TrimSpace(w)), "include")
	}

	// Company + year mutations.
	for _, y := range years {
		add(company+fmt.Sprint(y), "company+year")
		add(capCompany+fmt.Sprint(y), "company+year")
		add(company+fmt.Sprint(y)+"!", "company+year+suffix")
		add(capCompany+fmt.Sprint(y)+"!", "company+year+suffix")
		add(company+"@"+fmt.Sprint(y), "company+@+year")
		add(capCompany+"@"+fmt.Sprint(y), "company+@+year")
		add(company+fmt.Sprint(y%100), "company+yy")
		add(capCompany+fmt.Sprint(y%100), "company+yy")
	}

	// Company + season.
	for _, s := range seasons {
		add(company+s, "company+season")
		add(capCompany+s, "company+season")
		add(capCompany+s+fmt.Sprint(years[len(years)/2]), "company+season+year")
	}

	// Company + 1 / 123 / 1234.
	for _, tail := range []string{"1", "1!", "123", "1234", "123!", "@123", "12345", "12345!"} {
		add(company+tail, "company+number")
		add(capCompany+tail, "company+number")
	}
	add(capCompany+"@2025", "company+@+year")
	add(capCompany+"@2024", "company+@+year")

	// Sports teams, quarters (less common but seen in finance / retail).
	add("Go"+"Hawks", "sports-team")
	add("Go"+capCompany, "sports-team")

	// Domain variants.
	if cfg.Domain != "" {
		add(strings.ToLower(strings.TrimSpace(cfg.Domain)), "domain")
		add(capCompany+".com", "domain")
	}

	// Cap output.
	if len(out) > max {
		out = out[:max]
	}
	// Deterministic ordering.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Word < out[j].Word
	})
	return out
}

// ToFinding renders the wordlist as a single info-level finding. The
// Executor is the one that actually runs them (apophis_poc_run against a
// spraying PoC).
func ToFinding(target string, words []SprayWord) models.Finding {
	if len(words) == 0 {
		return models.Finding{}
	}
	previews := []string{}
	for i, w := range words {
		if i >= 20 {
			break
		}
		previews = append(previews, w.Word)
	}
	return F(
		VectorSpray,
		fmt.Sprintf("Targeted password-spray wordlist for %s (%d words)", target, len(words)),
		target,
		models.SeverityInfo,
		fmt.Sprintf("preview=%v total=%d", previews, len(words)),
		fmt.Sprintf("Curated wordlist seeded with the company name (%q), the active year and ±1, seasons, common defaults. Designed for low-volume spray (<= lockoutThreshold attempts).", target),
		"Pass the list to apophis_poc_run with a PoC that iterates over the wordlist and tries each against OWA / ADFS / LDAP / Kerberos preauth. Respect lockoutThreshold * 0.5 to avoid locking accounts.",
		"None — this is a defensive testing artifact.",
	)
}
