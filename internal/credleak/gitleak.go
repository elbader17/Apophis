package credleak

import (
	"fmt"
	"strings"

	"github.com/apophis-eng/apophis/internal/models"
)

// GitHit describes what was discovered on the .git endpoint.
type GitHit struct {
	Path   string
	Status int
	Size   int
	Body   string
}

// GitScan takes the response of a few targeted .git probes and reports
// findings. The fetcher is the same shape as BackupFileFetcher.
type GitScanFetcher func(ctx Context, path string) (GitHit, error)

// GitScan walks a curated list of .git probes and reports findings.
func GitScan(ctx Context, target string, fetch GitScanFetcher) []models.Finding {
	if fetch == nil {
		return nil
	}
	findings := []models.Finding{}
	probes := []struct {
		Path     string
		Severity models.Severity
		Title    string
		Detail   string
	}{
		{".git/HEAD", models.SeverityCritical, ".git/HEAD exposed", "Reading HEAD reveals the current branch. Combined with .git/config and .git/index, the full repository is downloadable."},
		{".git/config", models.SeverityCritical, ".git/config exposed", "May contain remote URLs (with embedded credentials), user.name, user.email."},
		{".git/index", models.SeverityCritical, ".git/index exposed", "Binary index of every tracked file in the repository."},
		{".git/COMMIT_EDITMSG", models.SeverityHigh, ".git/COMMIT_EDITMSG exposed", "The last commit message — may leak ticket numbers, internal hostnames, credentials."},
		{".git/description", models.SeverityLow, ".git/description exposed", "Unconfigured repository description."},
		{".git/logs/HEAD", models.SeverityHigh, ".git/logs/HEAD exposed", "Reflog — every commit the working copy has ever had."},
		{".gitignore", models.SeverityInfo, ".gitignore exposed", "Helps identify language / framework; useful for further enumeration."},
		{".git/refs/heads/main", models.SeverityCritical, ".git/refs/heads/main exposed", "Direct reference to the tip of main — the SHA can be used to fetch the commit."},
		{".git/refs/heads/master", models.SeverityCritical, ".git/refs/heads/master exposed", "Direct reference to the tip of master."},
		{".git/packed-refs", models.SeverityHigh, ".git/packed-refs exposed", "Packed reference file — list of every branch and tag."},
	}
	seen := map[string]bool{}
	for _, p := range probes {
		hit, err := fetch(ctx, p.Path)
		if err != nil {
			continue
		}
		if hit.Status < 200 || hit.Status >= 400 || hit.Size == 0 {
			continue
		}
		if seen[p.Path] {
			continue
		}
		seen[p.Path] = true
		// Run commit-message leak detector on COMMIT_EDITMSG / logs.
		extras := []models.Finding{}
		if strings.Contains(p.Path, "COMMIT_EDITMSG") || strings.Contains(p.Path, "logs/HEAD") {
			extras = CommitMessageLeak(target, hit.Body)
		}
		main := F(
			VectorGitExposed,
			fmt.Sprintf("%s on %s", p.Title, target),
			target,
			p.Severity,
			fmt.Sprintf("path=%s status=%d size=%d", p.Path, hit.Status, hit.Size),
			p.Detail,
			fmt.Sprintf("git-dumper https://%s/.git/", target),
			"Block access to the entire .git directory in the web server config (Apache: RedirectMatch 404 /\\.git; nginx: location ~ /\\.git { deny all; }).",
		)
		findings = append(findings, main)
		findings = append(findings, extras...)
	}
	return findings
}

// CommitMessageLeak walks commit messages for embedded credentials. The
// heuristics: any line that contains a credential keyword followed by a
// value is flagged. We also flag commit messages that look like they were
// copied from a config file (e.g. start with "AWS_" or include an
// "Authorization: Bearer" line).
func CommitMessageLeak(target, body string) []models.Finding {
	if body == "" {
		return nil
	}
	findings := []models.Finding{}
	for _, line := range strings.Split(body, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		lower := strings.ToLower(l)
		keyword := ""
		for _, k := range []string{"password", "passwd", "secret", "api_key", "apikey", "token", "credentials", "bearer"} {
			if strings.Contains(lower, k) {
				keyword = k
				break
			}
		}
		if keyword == "" {
			continue
		}
		if len(l) < 12 {
			continue
		}
		// Skip if it looks like a generic bug fix message.
		if strings.HasPrefix(lower, "fix") || strings.HasPrefix(lower, "bump") || strings.HasPrefix(lower, "release") {
			continue
		}
		findings = append(findings, F(
			VectorGitCommitLeak,
			fmt.Sprintf("Commit message contains possible credential on %s", target),
			target,
			models.SeverityHigh,
			fmt.Sprintf("line=%q", l),
			"The commit message embeds what looks like a credential. Developers frequently paste tokens into commit messages when troubleshooting.",
			"git log --all --pretty=format:'%H %s' | grep -iE 'password|secret|token' to enumerate further leaks.",
			"Enable pre-receive hooks that reject commits with credential-shaped content. Rotate any credential that ever appeared in commit history.",
		))
		if len(findings) >= 5 {
			break
		}
	}
	return findings
}
