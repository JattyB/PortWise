from __future__ import annotations

REMEDIATION: dict[str, dict] = {
    # ── TLS / Certificate ────────────────────────────────────────────────────
    "Expired TLS Certificate": {
        "summary": "Replace the expired certificate immediately; clients enforcing certificate validity will reject the connection.",
        "steps": [
            "Identify the issuing CA and initiate a certificate renewal.",
            "Generate a new private key and CSR.",
            "Install the new certificate and chain file on the server.",
            "Verify the renewal is valid with a browser or SSL-check tool before cutting over.",
            "Configure automated renewal (e.g. certbot/ACME) to prevent recurrence.",
        ],
        "references": [],
        "effort": "low",
    },
    "TLS Certificate Expiring Soon": {
        "summary": "Renew the certificate before it expires to maintain trust and avoid service disruption.",
        "steps": [
            "Confirm the exact expiry date and the renewal window permitted by the CA.",
            "Generate a new CSR or use automated renewal if supported.",
            "Install and verify the renewed certificate before the old one expires.",
            "Schedule automated renewal for all future certificates.",
        ],
        "references": [],
        "effort": "low",
    },
    "Self-Signed TLS Certificate": {
        "summary": "Replace the self-signed certificate with one issued by a trusted CA to prevent trust errors and MITM risk.",
        "steps": [
            "Obtain a certificate from a publicly trusted CA (e.g. Let's Encrypt for public services).",
            "For internal services, issue from a corporate PKI whose root is distributed via MDM/GPO.",
            "Deploy the certificate and verify the full chain is presented correctly.",
            "Remove the self-signed certificate from the server configuration.",
        ],
        "references": [],
        "effort": "low",
    },
    "TLS Hostname Mismatch": {
        "summary": "Reissue the certificate with Subject Alternative Names covering all hostnames used to reach this service.",
        "steps": [
            "Identify all hostnames used to access this service.",
            "Reissue with all required SANs included.",
            "Verify with a browser or TLS tool that the hostname validates correctly after deployment.",
        ],
        "references": [],
        "effort": "low",
    },
    "TLS Certificate Metadata": {
        "summary": "Review the certificate subject, issuer, validity, and SANs for compliance with policy.",
        "steps": [
            "Confirm the issuing CA is trusted and the certificate is within its validity period.",
            "Verify the SANs cover all intended hostnames.",
        ],
        "references": [],
        "effort": "low",
    },
    "TLS Certificate Not Retrieved": {
        "summary": "Investigate why the TLS certificate could not be retrieved and confirm the TLS configuration is correct.",
        "steps": [
            "Attempt a manual TLS connection: openssl s_client -connect host:port",
            "Review server TLS configuration for mismatches or incomplete chain files.",
        ],
        "references": [],
        "effort": "low",
    },
    "TLS 1.0 Supported": {
        "summary": "Disable TLS 1.0, which is vulnerable to POODLE and BEAST downgrade attacks.",
        "steps": [
            "Configure the server to reject TLS 1.0 connections at the listener or virtual-host level.",
            "Ensure TLS 1.2 and TLS 1.3 remain enabled.",
            "Verify existing clients can connect over TLS 1.2 before removing TLS 1.0.",
            "Monitor access logs for TLS 1.0 clients during a transition window.",
        ],
        "references": [
            "https://www.rfc-editor.org/rfc/rfc8996",
        ],
        "effort": "low",
    },
    "TLS 1.1 Supported": {
        "summary": "Disable TLS 1.1, which is deprecated and shares cipher weaknesses with TLS 1.0.",
        "steps": [
            "Configure the server to reject TLS 1.1 connections.",
            "Confirm TLS 1.2 and TLS 1.3 remain available for clients.",
            "Update any internal integrations that negotiate TLS 1.1.",
        ],
        "references": [
            "https://www.rfc-editor.org/rfc/rfc8996",
        ],
        "effort": "low",
    },
    "HSTS Missing": {
        "summary": "Add Strict-Transport-Security to instruct browsers to use HTTPS only, preventing protocol downgrade.",
        "steps": [
            "Add to all HTTPS responses: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            "Start with a short max-age (300s) to test, then increase to at least 180 days.",
            "Only add includeSubDomains after confirming all subdomains support HTTPS.",
            "Consider submitting high-value public domains to the HSTS preload list.",
        ],
        "references": [
            "https://owasp.org/www-project-secure-headers/",
        ],
        "effort": "low",
    },
    "Weak HSTS Policy": {
        "summary": "Increase the HSTS max-age to at least 180 days to meet preload requirements.",
        "steps": [
            "Update Strict-Transport-Security max-age to at least 15552000 (180 days).",
            "Target 31536000 (one year) for production browser-facing services.",
        ],
        "references": [
            "https://owasp.org/www-project-secure-headers/",
        ],
        "effort": "low",
    },
    "Weak Certificate Signature Algorithm": {
        "summary": "Replace SHA-1-signed certificates with SHA-256 or stronger; SHA-1 is cryptographically broken.",
        "steps": [
            "Identify the issuing CA.",
            "Request a reissue using SHA-256 (sha256WithRSAEncryption) or an ECDSA equivalent.",
            "Deploy and verify the new certificate.",
        ],
        "references": [],
        "effort": "low",
    },
    # ── HTTP / Web ────────────────────────────────────────────────────────────
    "Missing HSTS Header": {
        "summary": "Add Strict-Transport-Security to HTTPS responses to prevent protocol downgrade.",
        "steps": [
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains to all HTTPS responses.",
            "Validate with curl -I https://host/ | grep -i strict",
        ],
        "references": [
            "https://owasp.org/www-project-secure-headers/",
        ],
        "effort": "low",
    },
    "Missing Content Security Policy": {
        "summary": "Add a Content-Security-Policy header to restrict content sources and reduce XSS impact.",
        "steps": [
            "Audit all legitimate content sources (scripts, styles, fonts, images, frames).",
            "Deploy in report-only mode first: Content-Security-Policy-Report-Only: default-src 'self'; ...",
            "Monitor violations and refine the policy until clean.",
            "Switch to enforcement mode.",
        ],
        "references": [
            "https://owasp.org/www-project-secure-headers/",
        ],
        "effort": "medium",
    },
    "Missing X-Frame-Options": {
        "summary": "Add X-Frame-Options to prevent clickjacking attacks on this page.",
        "steps": [
            "Add X-Frame-Options: DENY to HTTP responses where framing is not required.",
            "Alternatively, use Content-Security-Policy: frame-ancestors 'none' for modern browsers.",
        ],
        "references": [
            "https://owasp.org/www-project-secure-headers/",
        ],
        "effort": "low",
    },
    "Missing X-Content-Type-Options": {
        "summary": "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing attacks.",
        "steps": [
            "Add X-Content-Type-Options: nosniff to all HTTP responses.",
            "Ensure all responses carry an accurate Content-Type header.",
        ],
        "references": [
            "https://owasp.org/www-project-secure-headers/",
        ],
        "effort": "low",
    },
    "Cookie Missing Security Attributes": {
        "summary": "Add Secure, HttpOnly, and SameSite attributes to session and authentication cookies.",
        "steps": [
            "Set Secure on cookies that must only transmit over HTTPS.",
            "Set HttpOnly to prevent JavaScript access to session cookies.",
            "Set SameSite=Strict or SameSite=Lax to mitigate CSRF.",
            "Validate each cookie change is compatible with application behaviour.",
        ],
        "references": [
            "https://owasp.org/www-community/controls/SecureCookieAttribute",
        ],
        "effort": "low",
    },
    "HTTP TRACE Method Enabled": {
        "summary": "Disable the HTTP TRACE method to prevent cross-site tracing (XST) attacks.",
        "steps": [
            "Apache: TraceEnable Off in httpd.conf",
            "Nginx: if ($request_method = TRACE) { return 405; } in the server block.",
            "Verify: curl -X TRACE http://host/ returns 405.",
        ],
        "references": [],
        "effort": "low",
    },
    "Dangerous HTTP Methods Allowed": {
        "summary": "Restrict write-capable HTTP methods (PUT, DELETE) unless explicitly required and protected.",
        "steps": [
            "Confirm whether PUT/DELETE are required by any legitimate feature.",
            "Disable them at the web-server level if not required.",
            "If required, protect them with authentication and authorisation controls.",
            "Verify the Allow header no longer advertises the methods.",
        ],
        "references": [],
        "effort": "low",
    },
    "HTTP Server Version Disclosure": {
        "summary": "Remove or suppress the Server header to reduce product fingerprinting.",
        "steps": [
            "Apache: ServerTokens Prod; ServerSignature Off",
            "Nginx: server_tokens off;",
            "IIS: Use custom response headers to suppress the Server header.",
        ],
        "references": [],
        "effort": "low",
    },
    "HTTP Framework Version Disclosure": {
        "summary": "Remove the X-Powered-By header to reduce framework fingerprinting.",
        "steps": [
            "Node/Express: app.disable('x-powered-by') or use the helmet middleware.",
            "PHP: expose_php = Off in php.ini",
            "ASP.NET: Remove X-Powered-By via IIS HTTP response headers configuration.",
        ],
        "references": [],
        "effort": "low",
    },
    "Exposed Git Metadata": {
        "summary": "Block public access to the .git directory immediately; it may expose source code and secrets.",
        "steps": [
            "Block /.git/ at the web server or CDN immediately.",
            "Audit exposed commits for hard-coded credentials or secrets; rotate any found.",
            "Review the CI/CD pipeline to ensure build artefacts exclude .git directories.",
        ],
        "references": [],
        "effort": "medium",
    },
    "Exposed Environment File": {
        "summary": "Block access to .env files and rotate all secrets they contain immediately.",
        "steps": [
            "Block /.env at the web server level immediately.",
            "Identify all credentials in the file and rotate them without delay.",
            "Move secrets to a secrets manager or deployment-platform environment injection.",
            "Audit access logs to determine whether the file was downloaded before discovery.",
        ],
        "references": [],
        "effort": "high",
    },
    "Exposed phpinfo Page": {
        "summary": "Remove phpinfo() pages from production; they disclose server paths, configuration, and module details.",
        "steps": [
            "Delete or access-restrict the phpinfo.php file on the server.",
            "Audit for other debug or info-disclosure endpoints.",
        ],
        "references": [],
        "effort": "low",
    },
    "Exposed Spring Boot Actuator Endpoint": {
        "summary": "Restrict Actuator endpoints to authorised management networks and disable sensitive endpoints.",
        "steps": [
            "Limit exposed endpoints: management.endpoints.web.exposure.include=health,info",
            "Restrict the management port to internal IPs at the firewall.",
            "Disable /actuator/env and /actuator/heapdump unless explicitly required.",
        ],
        "references": [],
        "effort": "medium",
    },
    "Directory Listing Enabled": {
        "summary": "Disable directory listing to prevent enumeration of files not intended for public access.",
        "steps": [
            "Apache: Options -Indexes in the relevant Directory block.",
            "Nginx: Remove autoindex on;",
            "IIS: Disable directory browsing in site configuration.",
        ],
        "references": [],
        "effort": "low",
    },
    "Exposed API Documentation": {
        "summary": "Restrict API documentation endpoints to authenticated users or internal networks.",
        "steps": [
            "Require authentication before serving Swagger/OpenAPI docs in production.",
            "Confirm no internal-only endpoints appear in publicly visible documentation.",
        ],
        "references": [],
        "effort": "low",
    },
    "Exposed Server Status Page": {
        "summary": "Restrict the server-status page to authorised IP ranges.",
        "steps": [
            "Apache: Require ip 127.0.0.1 in the Location /server-status block.",
            "Alternatively, disable mod_status if not needed.",
        ],
        "references": [],
        "effort": "low",
    },
    "Exposed Admin Panel": {
        "summary": "Restrict admin panel access to authorised management networks.",
        "steps": [
            "Block the admin path from untrusted source IPs at the reverse proxy or firewall.",
            "Require strong authentication (MFA) for all admin access.",
        ],
        "references": [],
        "effort": "medium",
    },
    "Admin Panel Detected": {
        "summary": "Confirm admin panel exposure is intentional and that authentication is enforced.",
        "steps": [
            "Verify authentication is required before any management function is accessible.",
            "Restrict access to authorised networks where possible.",
        ],
        "references": [],
        "effort": "low",
    },
    "Default Installation Page": {
        "summary": "Remove or replace default installation pages to reduce server fingerprinting.",
        "steps": [
            "Remove or customise default index pages before exposing the service.",
            "Replace with a blank page or application content.",
        ],
        "references": [],
        "effort": "low",
    },
    # ── SMB ──────────────────────────────────────────────────────────────────
    "SMBv1 Enabled": {
        "summary": "Disable SMBv1 on all endpoints; the protocol is exploitable by EternalBlue (WannaCry, NotPetya) and has no modern use case.",
        "steps": [
            "Windows PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
            "Audit the domain GPO to disable SMBv1 client-side as well.",
            "Verify: Get-SmbServerConfiguration | Select EnableSMB1Protocol",
            "Confirm no legacy systems (Windows XP/2003) depend on SMBv1 before disabling.",
        ],
        "references": [
            "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
        ],
        "effort": "low",
    },
    "SMB Signing Not Required": {
        "summary": "Enforce SMB signing to prevent relay attacks that lead to credential theft and lateral movement.",
        "steps": [
            "GPO: Computer Config → Windows Settings → Security Settings → Local Policies → Security Options → 'Microsoft network server: Digitally sign communications (always)' = Enabled",
            "Apply the same policy to domain workstations via domain GPO.",
            "Verify: Get-SmbServerConfiguration | Select RequireSecuritySignature",
            "Test that file sharing works correctly after enforcing signing.",
        ],
        "references": [
            "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security",
        ],
        "effort": "medium",
    },
    "SMB OS/Domain Disclosure": {
        "summary": "SMB metadata (OS version, domain, workgroup) is disclosed; restrict SMB to trusted networks.",
        "steps": [
            "Block ports 445/139 from untrusted networks at the perimeter firewall.",
            "Review whether the disclosed information is sensitive in the deployment context.",
        ],
        "references": [],
        "effort": "medium",
    },
    "SMB Service Exposed": {
        "summary": "Restrict SMB access to authorised management networks.",
        "steps": [
            "Block ports 445/139 from untrusted source IPs at the firewall.",
            "Confirm only authorised management hosts require direct SMB access.",
        ],
        "references": [],
        "effort": "medium",
    },
    # ── SSH ──────────────────────────────────────────────────────────────────
    "SSH Service Exposed": {
        "summary": "Confirm SSH is intentionally exposed and restrict it to authorised source IPs.",
        "steps": [
            "Restrict port 22 to management IP ranges using firewall ACLs.",
            "Disable password authentication; require key-based or certificate-based auth.",
            "Enable MFA for SSH on high-value systems.",
        ],
        "references": [],
        "effort": "medium",
    },
    "SSH Version Disclosure": {
        "summary": "Suppress the SSH version banner to reduce targeted attack surface.",
        "steps": [
            "Add Banner none to /etc/ssh/sshd_config.",
            "Restart sshd and verify the banner is no longer returned.",
        ],
        "references": [],
        "effort": "low",
    },
    "Legacy SSH Service": {
        "summary": "Upgrade to a current OpenSSH version to receive security patches and modern cipher support.",
        "steps": [
            "Identify the installed OpenSSH version on the host.",
            "Apply OS-level package updates.",
            "Review sshd_config for deprecated options that may need updating.",
        ],
        "references": [],
        "effort": "medium",
    },
    "Weak SSH Key Exchange Algorithm": {
        "summary": "Disable weak Diffie-Hellman key exchange algorithms from the SSH server configuration.",
        "steps": [
            "Add to /etc/ssh/sshd_config: KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512",
            "Remove diffie-hellman-group1-sha1 and diffie-hellman-group14-sha1.",
            "Restart sshd and verify: ssh -vv user@host 2>&1 | grep kex",
        ],
        "references": [],
        "effort": "low",
    },
    "Weak SSH Cipher": {
        "summary": "Remove CBC-mode and weak ciphers from the SSH server configuration.",
        "steps": [
            "Set in sshd_config: Ciphers aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr",
            "Restart sshd and verify cipher negotiation with an SSH client.",
        ],
        "references": [],
        "effort": "low",
    },
    "Weak SSH MAC": {
        "summary": "Remove weak HMAC algorithms (MD5, SHA-1-96) from the SSH server MAC list.",
        "steps": [
            "Set in sshd_config: MACs hmac-sha2-256,hmac-sha2-512,umac-128@openssh.com",
            "Remove hmac-md5, hmac-sha1, hmac-sha1-96, hmac-md5-96.",
            "Restart sshd.",
        ],
        "references": [],
        "effort": "low",
    },
    # ── RDP ──────────────────────────────────────────────────────────────────
    "RDP NLA Disabled": {
        "summary": "Enable Network Level Authentication to require credentials before the RDP session is established.",
        "steps": [
            "GPO: Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Security → 'Require use of specific security layer' = NLA",
            "Via System Properties: Remote tab → 'Allow connections only from computers running Remote Desktop with Network Level Authentication'.",
            "Test that authorised users can still connect after enabling NLA.",
        ],
        "references": [
            "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access",
        ],
        "effort": "low",
    },
    "RDP Service Exposed": {
        "summary": "Restrict RDP to authorised management IPs; it should not be reachable from untrusted networks.",
        "steps": [
            "Block port 3389 at the perimeter firewall for all sources except authorised management IPs.",
            "Place RDP behind a VPN or PAM solution for remote access.",
            "Enable Account Lockout Policy to limit brute-force attacks.",
        ],
        "references": [],
        "effort": "medium",
    },
    # ── WinRM ─────────────────────────────────────────────────────────────────
    "WinRM Exposed": {
        "summary": "Restrict WinRM to authorised management IPs; it provides remote PowerShell execution.",
        "steps": [
            "Block ports 5985/5986 at the perimeter firewall.",
            "Configure WinRM HTTPS (5986) and restrict using WinRM filters.",
            "Require Kerberos or certificate authentication; disable Basic auth.",
        ],
        "references": [],
        "effort": "medium",
    },
    # ── FTP ──────────────────────────────────────────────────────────────────
    "Anonymous FTP Login Enabled": {
        "summary": "Disable anonymous FTP access immediately; it permits unauthenticated file access.",
        "steps": [
            "vsftpd: anonymous_enable=NO in vsftpd.conf",
            "ProFTPD: Remove the <Anonymous> block from proftpd.conf",
            "Restart the FTP service and confirm anonymous login is rejected.",
            "Review what files were accessible anonymously and assess the data exposure.",
        ],
        "references": [],
        "effort": "low",
    },
    "FTP Cleartext Service Exposed": {
        "summary": "FTP transmits credentials and data in cleartext; migrate to SFTP or FTPS.",
        "steps": [
            "Deploy SFTP (SSH File Transfer Protocol) as a drop-in replacement.",
            "If FTP must remain, enable FTPS (FTP over TLS) and require TLS for control and data channels.",
            "Restrict FTP access to authorised source IPs.",
        ],
        "references": [],
        "effort": "medium",
    },
    # ── SNMP ─────────────────────────────────────────────────────────────────
    "Default SNMP Community Accepted": {
        "summary": "Change all default SNMP community strings immediately; 'public'/'private' are universally known.",
        "steps": [
            "Change the read community string to a long random string.",
            "Change write communities and restrict by source ACL.",
            "Upgrade to SNMPv3 with authentication and encryption where supported.",
            "Restrict SNMP access to the network management server IP only.",
        ],
        "references": [],
        "effort": "low",
    },
    "SNMP v1/v2c Exposed": {
        "summary": "SNMPv1/v2c use cleartext community strings; upgrade to SNMPv3 or restrict access tightly.",
        "steps": [
            "Upgrade to SNMPv3 with authPriv security level (authentication + encryption).",
            "If v1/v2c must remain, restrict port 161 to the management server IP via ACL.",
            "Use a non-default community string.",
        ],
        "references": [],
        "effort": "medium",
    },
    "SNMP Service Exposed": {
        "summary": "SNMP should only be reachable from the authorised network management system.",
        "steps": [
            "Block UDP port 161 to all sources except the network management server.",
            "Disable SNMP on hosts that do not require remote monitoring.",
        ],
        "references": [],
        "effort": "low",
    },
    "SNMP Information Disclosure": {
        "summary": "SNMP disclosed device metadata; restrict access and harden community strings.",
        "steps": [
            "Apply SNMP access controls as described for the community string findings.",
            "Review disclosed metadata for sensitivity.",
        ],
        "references": [],
        "effort": "low",
    },
    # ── DNS ──────────────────────────────────────────────────────────────────
    "DNS Recursion Enabled": {
        "summary": "Disable open recursion on authoritative servers; restrict recursion to internal clients on resolvers.",
        "steps": [
            "Authoritative BIND: recursion no;",
            "Internal resolvers: recursion yes; allow-recursion { internal-nets; };",
            "Block UDP/TCP port 53 from external sources if this is an internal resolver.",
            "Implement response rate limiting (RRL) to mitigate amplification attacks.",
        ],
        "references": [],
        "effort": "medium",
    },
    "DNS Zone Transfer Allowed": {
        "summary": "Restrict AXFR zone transfers to authorised secondary nameservers only.",
        "steps": [
            "BIND: allow-transfer { secondary-ip; }; in the zone block.",
            "Verify: dig AXFR zone @server from an unauthorised IP is rejected.",
            "Review exposed zone data for sensitive hostnames.",
        ],
        "references": [
            "https://www.rfc-editor.org/rfc/rfc5936",
        ],
        "effort": "low",
    },
    "DNS Version Disclosure": {
        "summary": "Suppress the DNS version string to reduce targeted attack surface.",
        "steps": [
            "BIND: version \"not currently available\"; in the options block.",
            "Restart named and verify: dig @server chaos txt version.bind",
        ],
        "references": [],
        "effort": "low",
    },
    "DNS Service Exposed": {
        "summary": "Confirm DNS exposure is intentional; internal resolvers should not be reachable externally.",
        "steps": [
            "For internal resolvers, block external access to port 53.",
            "For authoritative servers, confirm the exposure is required by the DNS delegation.",
        ],
        "references": [],
        "effort": "medium",
    },
    # ── NTP ──────────────────────────────────────────────────────────────────
    "NTP Information Disclosure": {
        "summary": "Restrict NTP control queries and limit access to authorised NTP clients.",
        "steps": [
            "Disable monlist: noquery in ntp.conf",
            "Restrict access: restrict default kod nomodify notrap nopeer noquery",
            "Verify: ntpdc -c monlist <server> returns a permission error.",
        ],
        "references": [],
        "effort": "low",
    },
    "NTP Service Exposed": {
        "summary": "Restrict NTP access to intended clients to prevent amplification abuse.",
        "steps": [
            "Block UDP port 123 from the internet at the perimeter firewall.",
            "Configure NTP ACLs to restrict clients to the internal network range.",
        ],
        "references": [],
        "effort": "low",
    },
    # ── Database ─────────────────────────────────────────────────────────────
    "Unauthenticated Redis Access": {
        "summary": "Require authentication for Redis and restrict network access immediately.",
        "steps": [
            "Set a strong password: requirepass <random-string> in redis.conf",
            "Bind to 127.0.0.1 or a management VLAN: bind 127.0.0.1",
            "Block port 6379 at the host firewall.",
            "Audit the keyspace for signs of data exfiltration or crypto-miner persistence.",
        ],
        "references": [],
        "effort": "medium",
    },
    "Memcached Exposed": {
        "summary": "Bind Memcached to localhost and block external access to prevent data disclosure and DDoS amplification.",
        "steps": [
            "Configure Memcached to listen on 127.0.0.1 only.",
            "Block UDP and TCP port 11211 at the host firewall.",
            "Enable SASL authentication if network access is genuinely required.",
        ],
        "references": [],
        "effort": "low",
    },
    "Database Service Exposed": {
        "summary": "Restrict database ports to application server IPs; databases should not be directly accessible from untrusted networks.",
        "steps": [
            "Block database ports (3306, 5432, 1433, 27017, etc.) at the perimeter firewall.",
            "Restrict at the host firewall to the application server IP only.",
            "Ensure the database user has only minimum required privileges.",
        ],
        "references": [],
        "effort": "medium",
    },
    "Database Version Disclosure": {
        "summary": "Suppress version disclosure in banners and error messages.",
        "steps": [
            "Review whether version disclosure can be suppressed at the application or proxy layer.",
            "Maintain a rigorous patching programme so version information remains low-value.",
        ],
        "references": [],
        "effort": "low",
    },
    "Unauthenticated Elasticsearch Access": {
        "summary": "Enable Elasticsearch security features and restrict network access to prevent data exfiltration.",
        "steps": [
            "Enable X-Pack security: xpack.security.enabled: true in elasticsearch.yml",
            "Configure TLS for the transport and HTTP layers.",
            "Restrict port 9200/9300 to the application server at the firewall.",
            "Create role-based access control for all application users.",
        ],
        "references": [],
        "effort": "medium",
    },
    # ── DevOps / Admin panels ─────────────────────────────────────────────────
    "DevOps/Admin Panel Exposed": {
        "summary": "Restrict administrative interfaces to authorised management networks.",
        "steps": [
            "Block admin panel paths at the firewall or reverse proxy for all but authorised IPs.",
            "Require strong authentication (MFA) for all admin access.",
            "Place admin access behind a VPN or PAM solution for remote management.",
        ],
        "references": [],
        "effort": "medium",
    },
    "Anonymous Access Possible": {
        "summary": "Disable anonymous or unauthenticated access to the management interface.",
        "steps": [
            "Enable authentication on the management interface.",
            "Review the application's access control configuration.",
            "Audit logs for any unauthenticated access activity.",
        ],
        "references": [],
        "effort": "medium",
    },
    "Sensitive Management Interface Exposed": {
        "summary": "Place sensitive management interfaces behind authentication and restrict network access.",
        "steps": [
            "Confirm the service requires authentication for all management operations.",
            "Restrict access to authorised networks at the firewall.",
            "Evaluate whether internet accessibility is required.",
        ],
        "references": [],
        "effort": "medium",
    },
    "Version Disclosure": {
        "summary": "Suppress version disclosure in service banners and HTTP headers.",
        "steps": [
            "Identify which component discloses the version.",
            "Apply vendor or server-specific configuration to suppress the banner.",
            "Maintain patching cadence so version disclosure remains low-signal.",
        ],
        "references": [],
        "effort": "low",
    },
    # ── Kubernetes / Container ────────────────────────────────────────────────
    "Kubernetes API Exposed": {
        "summary": "Restrict the Kubernetes API server to authorised management networks and enforce RBAC.",
        "steps": [
            "Configure the API server to bind only on internal management interfaces.",
            "Enforce RBAC and audit API server logs.",
            "Disable anonymous authentication: --anonymous-auth=false",
        ],
        "references": [],
        "effort": "high",
    },
    "Docker API Exposed": {
        "summary": "Restrict the Docker API; an exposed Docker daemon provides root-equivalent access to the host.",
        "steps": [
            "Configure Docker to accept connections via Unix socket only (not TCP).",
            "If remote API access is required, use TLS mutual authentication.",
            "Block ports 2375/2376 at the firewall.",
        ],
        "references": [],
        "effort": "medium",
    },
    "Docker Registry Exposed": {
        "summary": "Require authentication for the container registry and restrict network access.",
        "steps": [
            "Enable registry authentication.",
            "Restrict the registry to internal network access.",
            "Audit images for sensitive data in layers.",
        ],
        "references": [],
        "effort": "medium",
    },
    "etcd Exposed": {
        "summary": "Restrict etcd access to the Kubernetes control plane; it stores all cluster state including secrets.",
        "steps": [
            "Bind etcd to loopback or a management interface only.",
            "Enable client certificate authentication.",
            "Block ports 2379/2380 at the firewall.",
        ],
        "references": [],
        "effort": "high",
    },
    "Kubelet Endpoint Exposed": {
        "summary": "Restrict Kubelet API access and disable anonymous authentication.",
        "steps": [
            "Set --anonymous-auth=false in Kubelet configuration.",
            "Configure Kubelet to use Webhook authentication.",
            "Block port 10250 from non-control-plane sources at the firewall.",
        ],
        "references": [],
        "effort": "medium",
    },
    # ── Mail ──────────────────────────────────────────────────────────────────
    "SMTP STARTTLS Missing": {
        "summary": "Enable STARTTLS on the SMTP server to protect credentials and mail content in transit.",
        "steps": [
            "Install a valid TLS certificate on the SMTP server.",
            "Postfix: smtpd_tls_security_level = may (or encrypt for mandatory TLS)",
            "Test: openssl s_client -starttls smtp -connect host:25",
        ],
        "references": [],
        "effort": "medium",
    },
    "VRFY Enabled": {
        "summary": "Disable SMTP VRFY to prevent user enumeration.",
        "steps": [
            "Postfix: disable_vrfy_command = yes in main.cf",
            "Exim: smtp_verify = false",
            "Restart the mail service and verify: telnet host 25 → VRFY test@example.com is rejected.",
        ],
        "references": [],
        "effort": "low",
    },
    "EXPN Enabled": {
        "summary": "Disable SMTP EXPN to prevent mailing list enumeration.",
        "steps": [
            "Postfix: smtpd_discard_ehlo_keywords = expn in main.cf",
            "Verify by sending EXPN after the change.",
        ],
        "references": [],
        "effort": "low",
    },
    "SMTP Service Exposed": {
        "summary": "Confirm SMTP exposure is intentional and implement STARTTLS and relay restrictions.",
        "steps": [
            "Ensure STARTTLS is enabled.",
            "Configure relay restrictions to prevent open relay.",
            "Monitor for spam and abuse patterns.",
        ],
        "references": [],
        "effort": "medium",
    },
    "Mail Server Version Disclosure": {
        "summary": "Suppress the mail server version from SMTP banners to reduce fingerprinting.",
        "steps": [
            "Postfix: smtpd_banner = $myhostname ESMTP (remove version info).",
            "Review EHLO/HELO responses for other version strings.",
        ],
        "references": [],
        "effort": "low",
    },
    "POP3 Cleartext Service Exposed": {
        "summary": "Migrate to POP3S (port 995) to protect credentials in transit.",
        "steps": [
            "Enable POP3S with TLS and a valid certificate.",
            "Disable plaintext POP3 (port 110) once all clients support POP3S.",
        ],
        "references": [],
        "effort": "medium",
    },
    "IMAP Cleartext Service Exposed": {
        "summary": "Migrate to IMAPS (port 993) to protect credentials in transit.",
        "steps": [
            "Enable IMAPS with TLS and a valid certificate.",
            "Disable plaintext IMAP (port 143) once all clients support IMAPS.",
        ],
        "references": [],
        "effort": "medium",
    },
    # ── VPN / Appliance ───────────────────────────────────────────────────────
    "VPN Interface Exposed": {
        "summary": "Confirm VPN exposure is intentional, apply latest firmware patches, and restrict management access.",
        "steps": [
            "Apply any available vendor security patches without delay.",
            "Restrict management access to authorised IPs.",
            "Review vendor advisories for known vulnerabilities in the identified version.",
        ],
        "references": [],
        "effort": "medium",
    },
    "Security Appliance Interface Exposed": {
        "summary": "Restrict appliance management interfaces to authorised networks and apply current firmware.",
        "steps": [
            "Block management ports from untrusted networks at the firewall.",
            "Apply the latest vendor firmware update.",
            "Review vendor security bulletins for the detected product version.",
        ],
        "references": [],
        "effort": "medium",
    },
    "Appliance Version Disclosure": {
        "summary": "Suppress version information from appliance banners where possible.",
        "steps": [
            "Review vendor documentation for options to suppress version disclosure.",
            "Maintain current firmware to limit the value of disclosed version information.",
        ],
        "references": [],
        "effort": "low",
    },
    # ── CVE ───────────────────────────────────────────────────────────────────
    "Known Exploited Vulnerability Indicator": {
        "summary": "Apply the vendor patch or mitigation for this CVE immediately; it is actively exploited in the wild.",
        "steps": [
            "Identify the exact installed version on the affected host.",
            "Apply the vendor-supplied patch as an emergency change.",
            "If patching is not immediately possible, apply the vendor's interim mitigation.",
            "Monitor security logs for indicators of exploitation.",
            "Re-scan after remediation to confirm the vulnerable version is gone.",
        ],
        "references": [
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ],
        "effort": "high",
    },
    "Known Vulnerable Component Detected": {
        "summary": "Validate the installed version and apply available patches to address the identified CVE.",
        "steps": [
            "Confirm the installed version matches the CVE's vulnerable range (check for distribution backports).",
            "Apply the vendor patch or OS-level update.",
            "Verify the fix: check --version or package manager.",
            "Re-scan to confirm resolution.",
        ],
        "references": [],
        "effort": "medium",
    },
    "CVE Match Requires Manual Validation": {
        "summary": "Manually verify whether the installed component is within the CVE's affected version range before treating as confirmed.",
        "steps": [
            "Identify the exact installed version on the affected host.",
            "Check whether the distribution applies backport patches (common in Debian, Ubuntu, RHEL).",
            "Compare against the CVE's affected version range in the NVD entry.",
            "Remediate if confirmed vulnerable.",
        ],
        "references": [],
        "effort": "medium",
    },
}

_GENERIC: dict = {}


def get_remediation(title: str) -> dict:
    """Return the remediation entry for a finding title, or a generic fallback."""
    if title in REMEDIATION:
        return REMEDIATION[title]
    tl = title.lower()
    for key, value in REMEDIATION.items():
        if key.lower() in tl:
            return value
    return _GENERIC
