// Package credleak implements credential-leak detectors across HTTP
// responses, JS bundles, backup files and .git directories:
//
//   - entropy.go       Shannon-entropy regex-based password leak detector
//   - hardcoded.go     Hardcoded credentials in JS bundles (AWS keys, JWT
//     secrets, API tokens, etc.)
//   - backup.go        Common backup file leak (id_rsa, .pgpass, .npmrc, …)
//   - gitleak.go       .git directory enumeration + commit-message leak
//
// Each detector consumes a (URL, response body) or a (path, response) and
// produces findings. Detectors never reach out to the network on their own.
package credleak

import (
	"github.com/apophis-eng/apophis/internal/models"
)

// AttackVector identifies the credential-leak category.
type AttackVector string

const (
	VectorEntropyLeak    AttackVector = "cred-leak-entropy"
	VectorHardcodedCreds AttackVector = "cred-leak-hardcoded"
	VectorBackupFile     AttackVector = "cred-leak-backup"
	VectorGitExposed     AttackVector = "cred-leak-git"
	VectorGitCommitLeak  AttackVector = "cred-leak-git-commit"
)

// F wraps models.Finding.
func F(vector AttackVector, title, target string, sev models.Severity, evidence, desc, exploit, remediation string) models.Finding {
	return models.Finding{
		Title:       title,
		Severity:    sev,
		Category:    "CredLeak",
		Target:      target,
		Evidence:    evidence,
		Description: desc,
		Exploit:     exploit,
		Remediation: remediation,
		Tags:        []string{"auth-attack", "cred-leak", string(vector)},
	}
}
