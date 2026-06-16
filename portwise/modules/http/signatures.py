from __future__ import annotations

from dataclasses import dataclass
from portwise.core.models import FindingCategory, Severity


@dataclass(frozen=True)
class AdminPanelSignature:
    name: str
    paths: tuple[str, ...]
    required_status: frozenset[int]
    body_contains: tuple[str, ...]  # ALL must match (case-insensitive)
    body_any: tuple[str, ...]       # ANY must match (case-insensitive); empty = not checked
    severity: Severity
    category: FindingCategory
    unauthenticated_management: bool = False  # escalate if reachable without 401/403


@dataclass(frozen=True)
class DefaultInstallSignature:
    name: str
    paths: tuple[str, ...]
    body_any: tuple[str, ...]  # ANY match triggers detection
    severity: Severity = Severity.LOW
    category: FindingCategory = FindingCategory.HYGIENE


ADMIN_PANEL_SIGNATURES: tuple[AdminPanelSignature, ...] = (
    AdminPanelSignature(
        name="phpMyAdmin",
        paths=("/phpmyadmin/", "/phpmyadmin/index.php", "/pma/", "/phpMyAdmin/"),
        required_status=frozenset({200, 401, 403}),
        body_contains=(),
        body_any=("phpmyadmin", "pmahomme", "pma_password", "welcome to phpmyadmin"),
        severity=Severity.HIGH,
        category=FindingCategory.VULNERABILITY,
        unauthenticated_management=True,
    ),
    AdminPanelSignature(
        name="Apache Tomcat Manager",
        paths=("/manager/html", "/manager/status", "/host-manager/html"),
        required_status=frozenset({200, 401, 403}),
        body_contains=(),
        body_any=("apache tomcat", "tomcat web application manager", "tomcat/", "manager app"),
        severity=Severity.HIGH,
        category=FindingCategory.VULNERABILITY,
        unauthenticated_management=True,
    ),
    AdminPanelSignature(
        name="Jenkins",
        paths=("/jenkins/", "/jenkins", "/jenkins/login"),
        required_status=frozenset({200, 401, 403}),
        body_contains=(),
        body_any=("jenkins", "hudson", "sign in to jenkins", "dashboard [jenkins]"),
        severity=Severity.HIGH,
        category=FindingCategory.VULNERABILITY,
        unauthenticated_management=True,
    ),
    AdminPanelSignature(
        name="Grafana",
        paths=("/grafana/login", "/grafana/", "/grafana"),
        required_status=frozenset({200, 302, 401}),
        body_contains=(),
        body_any=("grafana", "grafana labs", "welcome to grafana"),
        severity=Severity.MEDIUM,
        category=FindingCategory.VULNERABILITY,
        unauthenticated_management=False,
    ),
    AdminPanelSignature(
        name="Kibana",
        paths=("/kibana/", "/kibana", "/app/kibana"),
        required_status=frozenset({200, 401, 302}),
        body_contains=(),
        body_any=("kibana", "elastic", "kbn-version"),
        severity=Severity.MEDIUM,
        category=FindingCategory.VULNERABILITY,
        unauthenticated_management=False,
    ),
    AdminPanelSignature(
        name="Adminer",
        paths=("/adminer.php", "/adminer/", "/adminer"),
        required_status=frozenset({200}),
        body_contains=(),
        body_any=("adminer", "login – adminer", "adminer.org"),
        severity=Severity.HIGH,
        category=FindingCategory.VULNERABILITY,
        unauthenticated_management=True,
    ),
    AdminPanelSignature(
        name="WordPress Admin",
        paths=("/wp-login.php", "/wp-admin/"),
        required_status=frozenset({200, 302, 301}),
        body_contains=(),
        body_any=("wp-login.php", "wordpress", "log in &lsaquo; wordpress", "powered by wordpress"),
        severity=Severity.LOW,
        category=FindingCategory.INFORMATION,
        unauthenticated_management=False,
    ),
    AdminPanelSignature(
        name="Webmin",
        paths=("/webmin/", ":10000/", "/webmin"),
        required_status=frozenset({200, 401}),
        body_contains=(),
        body_any=("webmin", "webmin login", "usermin"),
        severity=Severity.HIGH,
        category=FindingCategory.VULNERABILITY,
        unauthenticated_management=False,
    ),
    AdminPanelSignature(
        name="Portainer",
        paths=("/portainer/", "/portainer", "/:9000/"),
        required_status=frozenset({200, 302}),
        body_contains=(),
        body_any=("portainer", "portainer.io", "docker management"),
        severity=Severity.HIGH,
        category=FindingCategory.VULNERABILITY,
        unauthenticated_management=True,
    ),
    AdminPanelSignature(
        name="Kubernetes Dashboard",
        paths=("/kubernetes-dashboard/", "/api/v1/namespaces/kubernetes-dashboard/"),
        required_status=frozenset({200, 401}),
        body_contains=(),
        body_any=("kubernetes dashboard", "kubernetes-dashboard", "k8s dashboard"),
        severity=Severity.HIGH,
        category=FindingCategory.VULNERABILITY,
        unauthenticated_management=True,
    ),
    AdminPanelSignature(
        name="pgAdmin",
        paths=("/pgadmin/", "/pgadmin4/", "/pgadmin"),
        required_status=frozenset({200, 302}),
        body_contains=(),
        body_any=("pgadmin", "postgresql tools", "pgadmin 4"),
        severity=Severity.HIGH,
        category=FindingCategory.VULNERABILITY,
        unauthenticated_management=True,
    ),
    AdminPanelSignature(
        name="RabbitMQ Management",
        paths=("/rabbitmq/", "/:15672/"),
        required_status=frozenset({200, 401}),
        body_contains=(),
        body_any=("rabbitmq management", "rabbitmq", "amqp"),
        severity=Severity.HIGH,
        category=FindingCategory.VULNERABILITY,
        unauthenticated_management=True,
    ),
    AdminPanelSignature(
        name="Spring Boot Actuator",
        paths=("/actuator", "/actuator/health", "/actuator/env", "/actuator/info"),
        required_status=frozenset({200}),
        body_contains=(),
        body_any=('"status"', '"health"', '"activeProfiles"', '"beans"'),
        severity=Severity.MEDIUM,
        category=FindingCategory.VULNERABILITY,
        unauthenticated_management=False,
    ),
    AdminPanelSignature(
        name="Solr Admin",
        paths=("/solr/", "/solr/admin/"),
        required_status=frozenset({200, 302}),
        body_contains=(),
        body_any=("apache solr", "solr admin", "solrconfig"),
        severity=Severity.MEDIUM,
        category=FindingCategory.VULNERABILITY,
        unauthenticated_management=True,
    ),
)

DEFAULT_INSTALL_SIGNATURES: tuple[DefaultInstallSignature, ...] = (
    DefaultInstallSignature(
        name="Apache2 Ubuntu Default Page",
        paths=("/",),
        body_any=("apache2 ubuntu default page", "it works!", "apache2 debian default page"),
    ),
    DefaultInstallSignature(
        name="nginx Default Page",
        paths=("/",),
        body_any=("welcome to nginx!", "thank you for using nginx"),
    ),
    DefaultInstallSignature(
        name="IIS Default Page",
        paths=("/",),
        body_any=("iis windows server", "internet information services", "iisstart.htm", "welcome to iis"),
    ),
    DefaultInstallSignature(
        name="Apache Tomcat Default Root",
        paths=("/",),
        body_any=("apache tomcat", "tomcat/", "if you're seeing this, you've successfully installed tomcat"),
    ),
    DefaultInstallSignature(
        name="XAMPP/WAMP Dashboard",
        paths=("/", "/xampp/", "/dashboard/"),
        body_any=("xampp for", "wampserver", "xampp is currently running", "bitnami xampp"),
    ),
    DefaultInstallSignature(
        name="CentOS/RHEL Apache Test Page",
        paths=("/",),
        body_any=("test page for the apache http server", "fedora powertools", "centos"),
    ),
    DefaultInstallSignature(
        name="Jenkins Setup Wizard",
        paths=("/jenkins/", "/", "/jenkins"),
        body_any=("getting started", "unlock jenkins", "please wait while jenkins is getting ready"),
    ),
    DefaultInstallSignature(
        name="Grafana Initial Setup",
        paths=("/grafana/login", "/"),
        body_any=("grafana", "welcome to grafana"),
        severity=Severity.LOW,
        category=FindingCategory.HYGIENE,
    ),
    DefaultInstallSignature(
        name="Plesk Default Page",
        paths=("/",),
        body_any=("plesk", "this is the default page of the domain"),
    ),
    DefaultInstallSignature(
        name="cPanel Default",
        paths=("/", "/cpanel"),
        body_any=("cpanel", "webmail login", "whm"),
    ),
)


def match_admin_panel(path: str, status: int, body: str) -> AdminPanelSignature | None:
    """Return the first matching admin-panel signature for (path, status, body), or None."""
    lower = body.lower()
    for sig in ADMIN_PANEL_SIGNATURES:
        if status not in sig.required_status:
            continue
        if path not in sig.paths and not any(path.startswith(p.rstrip("/")) for p in sig.paths):
            continue
        if sig.body_contains and not all(s in lower for s in sig.body_contains):
            continue
        if sig.body_any and not any(s in lower for s in sig.body_any):
            # For 401/403 responses the body may be minimal — still match on path
            if status in {401, 403}:
                return sig  # path match alone is enough for auth-protected paths
            continue
        return sig
    return None


def match_default_install(path: str, status: int, body: str) -> DefaultInstallSignature | None:
    """Return the first matching default-install signature, or None."""
    if status != 200:
        return None
    lower = body.lower()
    for sig in DEFAULT_INSTALL_SIGNATURES:
        if path not in sig.paths and "/" not in sig.paths:
            continue
        if any(s in lower for s in sig.body_any):
            return sig
    return None


def has_password_form(body: str) -> bool:
    """Returns True when the body contains an HTML password input field."""
    lower = body.lower()
    return 'type="password"' in lower or "type='password'" in lower or "type=password" in lower
