from __future__ import annotations

# CRITICAL: PortWise NEVER attempts any credentials.
# This module is a KNOWLEDGE BASE ONLY. No sockets, no login functions.
ATTEMPTS_AUTH = False

# ---------------------------------------------------------------------------
# Default credential knowledge base
# ---------------------------------------------------------------------------
# Each entry: product_key -> {pairs, notes, references, risk}
# pairs: list of (username, password) or [] when no default user/pass applies
# ---------------------------------------------------------------------------

DEFAULT_CREDS: dict[str, dict] = {
    "tomcat-manager": {
        "pairs": [("tomcat", "tomcat"), ("admin", "admin"), ("admin", "password"), ("tomcat", "s3cret")],
        "notes": "Apache Tomcat Manager ships with no accounts enabled by default on modern releases, but many deployments re-enable the sample users from conf/tomcat-users.xml.",
        "references": ["https://tomcat.apache.org/tomcat-10.1-doc/manager-howto.html"],
        "risk": "Remote code execution via WAR deployment if default credentials are valid.",
        "severity": "medium",
    },
    "jenkins": {
        "pairs": [("admin", "")],
        "notes": "Jenkins generates a random initial admin password written to /var/jenkins_home/secrets/initialAdminPassword. Some older or containerised deployments default to admin/admin.",
        "references": ["https://www.jenkins.io/doc/book/installing/"],
        "risk": "Full CI/CD pipeline access; arbitrary code execution on build nodes.",
        "severity": "medium",
    },
    "grafana": {
        "pairs": [("admin", "admin")],
        "notes": "Grafana ships with admin/admin and forces a password change on first login. Automated deployments often skip this.",
        "references": ["https://grafana.com/docs/grafana/latest/administration/user-management/"],
        "risk": "Data source credential exposure; RCE via plugin rendering in some versions.",
        "severity": "medium",
    },
    "phpmyadmin": {
        "pairs": [("root", ""), ("root", "root"), ("pma", "")],
        "notes": "phpMyAdmin uses MySQL credentials. Root with no password is common on development systems.",
        "references": ["https://www.phpmyadmin.net/docs/"],
        "risk": "Full database access including file read/write via SELECT INTO OUTFILE.",
        "severity": "high",
    },
    "mysql": {
        "pairs": [("root", ""), ("root", "root")],
        "notes": "MySQL root account often ships with no password in development packages. Verify before production.",
        "references": ["https://dev.mysql.com/doc/refman/8.0/en/default-privileges.html"],
        "risk": "Full database server access; potential OS command execution via UDFs.",
        "severity": "medium",
    },
    "postgres": {
        "pairs": [("postgres", "postgres"), ("postgres", "")],
        "notes": "PostgreSQL superuser 'postgres' sometimes has a blank password or common default.",
        "references": ["https://www.postgresql.org/docs/current/auth-pg-hba-conf.html"],
        "risk": "Full database access; OS command execution via COPY TO/FROM PROGRAM.",
        "severity": "medium",
    },
    "mongodb": {
        "pairs": [],
        "notes": "Older MongoDB versions (<3.6) default to NO authentication. Check whether auth is enforced.",
        "references": ["https://www.mongodb.com/docs/manual/administration/security-checklist/"],
        "risk": "Unauthenticated full database access in unprotected deployments.",
        "severity": "high",
    },
    "redis": {
        "pairs": [],
        "notes": "Redis ships with NO password by default. If requirepass is not set and the port is reachable, access is unauthenticated.",
        "references": ["https://redis.io/docs/manual/security/"],
        "risk": "Data exfiltration; configuration write leading to SSH key injection or cron RCE.",
        "severity": "high",
    },
    "rabbitmq": {
        "pairs": [("guest", "guest")],
        "notes": "RabbitMQ ships with guest/guest, accessible from localhost only by default. Network-exposed deployments with this default are fully compromised.",
        "references": ["https://www.rabbitmq.com/access-control.html"],
        "risk": "Message queue access; potential lateral movement if internal services consume from the queue.",
        "severity": "medium",
    },
    "elasticsearch": {
        "pairs": [],
        "notes": "Elasticsearch prior to 8.x ships with no authentication by default. Verify X-Pack security is enabled.",
        "references": ["https://www.elastic.co/guide/en/elasticsearch/reference/current/security-settings.html"],
        "risk": "Unauthenticated full data access; possible remote code execution via Groovy/Painless scripting.",
        "severity": "high",
    },
    "portainer": {
        "pairs": [("admin", "")],
        "notes": "Portainer prompts for an admin password on first access. Expired first-login window (> 5 min) may lock the UI and force a reset. Some automated deployments pre-set admin/admin.",
        "references": ["https://docs.portainer.io/admin/settings"],
        "risk": "Full Docker/Kubernetes management; container escape to host.",
        "severity": "high",
    },
    "kibana": {
        "pairs": [("elastic", "changeme")],
        "notes": "Kibana uses Elasticsearch credentials. Pre-8.x clusters with security disabled allow access without any credentials.",
        "references": ["https://www.elastic.co/guide/en/kibana/current/security-settings-kb.html"],
        "risk": "Data access; Kibana Canvas/Lens SSRF in some versions.",
        "severity": "medium",
    },
    "sonarqube": {
        "pairs": [("admin", "admin")],
        "notes": "SonarQube ships with admin/admin. The Community Edition forces a change on first login in newer releases.",
        "references": ["https://docs.sonarqube.org/latest/instance-administration/security/"],
        "risk": "Source code access; credential disclosure from linked SCM/CI integrations.",
        "severity": "medium",
    },
    "nexus": {
        "pairs": [("admin", "admin123")],
        "notes": "Sonatype Nexus Repository Manager default credentials. v3+ may generate a random password in /nexus-data/admin.password.",
        "references": ["https://help.sonatype.com/repomanager3/product-information/security"],
        "risk": "Artifact repository access; supply-chain compromise via malicious package publication.",
        "severity": "high",
    },
    "artifactory": {
        "pairs": [("admin", "password")],
        "notes": "JFrog Artifactory default admin/password. Some versions generate a setup token.",
        "references": ["https://jfrog.com/help/r/jfrog-installation-setup-documentation/managing-users"],
        "risk": "Artifact poisoning; access to internal registry credentials stored in the system.",
        "severity": "high",
    },
    "snmp": {
        "pairs": [("", "public"), ("", "private")],
        "notes": "SNMP v1/v2c community strings 'public' (read) and 'private' (write) are defaults on many devices. PortWise actively checks these safely via a single OID probe.",
        "references": ["https://www.cisecurity.org/insights/white-papers/security-primer-snmp"],
        "risk": "Device configuration read; write community enables device reconfiguration.",
        "severity": "medium",
    },
    "idrac": {
        "pairs": [("root", "calvin")],
        "notes": "Dell iDRAC default credentials are root/calvin. Firmware updates and newer generations may change this.",
        "references": ["https://www.dell.com/support/kbdoc/en-us/000134243/dell-idrac-default-credential"],
        "risk": "Out-of-band full server control; virtual media mounting; OS reinstall.",
        "severity": "high",
    },
    "ilo": {
        "pairs": [("Administrator", "<serial-tag>")],
        "notes": "HPE iLO default password is printed on a tag attached to the physical server. Verify via management network.",
        "references": ["https://support.hpe.com/hpesc/public/docDisplay?docId=a00018324en_us"],
        "risk": "Out-of-band full server management.",
        "severity": "medium",
    },
    "printer": {
        "pairs": [("admin", "admin"), ("admin", "password"), ("admin", "1234")],
        "notes": "Network printers (HP, Canon, Ricoh, Lexmark) commonly ship with admin/admin or admin/password. SNMP community 'public' also provides read access.",
        "references": ["https://www.cisa.gov/uscert/ics/alerts/ics-alert-09-208-01a"],
        "risk": "Document interception; network pivot via printer VLAN; firmware modification.",
        "severity": "low",
    },
}

# ---------------------------------------------------------------------------
# Product → KB key mapping for fingerprint-based lookup
# ---------------------------------------------------------------------------
_PRODUCT_MAP: list[tuple[str, str]] = [
    ("tomcat", "tomcat-manager"),
    ("jenkins", "jenkins"),
    ("grafana", "grafana"),
    ("phpmyadmin", "phpmyadmin"),
    ("mysql", "mysql"),
    ("mariadb", "mysql"),
    ("postgres", "postgres"),
    ("postgresql", "postgres"),
    ("mongodb", "mongodb"),
    ("redis", "redis"),
    ("rabbitmq", "rabbitmq"),
    ("elasticsearch", "elasticsearch"),
    ("portainer", "portainer"),
    ("kibana", "kibana"),
    ("sonarqube", "sonarqube"),
    ("nexus", "nexus"),
    ("artifactory", "artifactory"),
    ("snmp", "snmp"),
    ("idrac", "idrac"),
    ("ilo", "ilo"),
    ("printer", "printer"),
    ("laserjet", "printer"),
    ("officejet", "printer"),
]


def lookup_default_creds(product_text: str) -> tuple[str, dict] | None:
    """
    Returns (kb_key, entry) for the first product keyword match, or None.
    product_text should be a lowercased concatenation of service fingerprint fields.
    """
    for keyword, kb_key in _PRODUCT_MAP:
        if keyword in product_text:
            return kb_key, DEFAULT_CREDS[kb_key]
    return None
