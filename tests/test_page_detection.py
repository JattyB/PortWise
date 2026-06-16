from __future__ import annotations


from portwise.core.models import FindingCategory, Severity
from portwise.modules.http.http_engine import HttpEngine
from portwise.modules.http.signatures import (
    has_password_form,
    match_admin_panel,
    match_default_install,
)


# ---------------------------------------------------------------------------
# Signature helper unit tests
# ---------------------------------------------------------------------------

def test_match_admin_panel_phpmyadmin():
    body = "Welcome to phpMyAdmin pma_password login"
    sig = match_admin_panel("/phpmyadmin/", 200, body)
    assert sig is not None
    assert sig.name == "phpMyAdmin"
    assert sig.unauthenticated_management is True


def test_match_admin_panel_tomcat():
    body = "Tomcat Web Application Manager"
    sig = match_admin_panel("/manager/html", 200, body)
    assert sig is not None
    assert sig.unauthenticated_management is True


def test_match_admin_panel_grafana_auth_protected():
    body = "Welcome to Grafana"
    sig = match_admin_panel("/grafana/login", 200, body)
    assert sig is not None
    assert sig.unauthenticated_management is False


def test_match_default_install_apache():
    body = "Apache2 Ubuntu Default Page: It works!"
    sig = match_default_install("/", 200, body)
    assert sig is not None
    assert "Apache" in sig.name


def test_match_default_install_nginx():
    body = "<h1>Welcome to nginx!</h1>"
    sig = match_default_install("/", 200, body)
    assert sig is not None
    assert "nginx" in sig.name


def test_match_default_install_iis():
    body = "IIS Windows Server"
    sig = match_default_install("/", 200, body)
    assert sig is not None
    assert "IIS" in sig.name


def test_match_default_install_not_200():
    body = "Welcome to nginx!"
    assert match_default_install("/", 403, body) is None


def test_has_password_form_double_quote():
    assert has_password_form('<input type="password" name="pass">')


def test_has_password_form_single_quote():
    assert has_password_form("<input type='password'>")


def test_has_password_form_absent():
    assert not has_password_form("<input type='text'>")


# ---------------------------------------------------------------------------
# _path_title unit tests  (now returns 3-tuple: title, severity, category)
# ---------------------------------------------------------------------------

def test_403_on_admin_is_not_a_finding():
    title, _, _ = HttpEngine._path_title("/phpmyadmin/", 403, "403 Forbidden")
    assert title is None


def test_401_on_admin_is_not_a_finding():
    title, _, _ = HttpEngine._path_title("/manager/html", 401, "401 Unauthorized")
    assert title is None


def test_200_spa_catchall_no_signature_is_dropped():
    body = "<html><body><div id='app'></div></body></html>"
    title, _, _ = HttpEngine._path_title("/login", 200, body)
    assert title is None


def test_phpmyadmin_signature_match_reports_panel():
    body = "<html><title>phpMyAdmin</title>Welcome to phpMyAdmin pma_password</html>"
    title, severity, category = HttpEngine._path_title("/phpmyadmin/", 200, body)
    assert title is not None
    assert "phpMyAdmin" in title
    assert severity == Severity.HIGH
    assert category == FindingCategory.VULNERABILITY


def test_open_tomcat_manager_is_high_vulnerability():
    body = "<html>Tomcat Web Application Manager</html>"
    title, severity, category = HttpEngine._path_title("/manager/html", 200, body)
    assert title is not None
    assert severity == Severity.HIGH
    assert category == FindingCategory.VULNERABILITY


def test_auth_protected_management_is_information_low():
    """Admin panel that requires auth (unauthenticated_management=False) → LOW INFORMATION."""
    body = "<html><title>Grafana</title>Welcome to Grafana</html>"
    title, severity, category = HttpEngine._path_title("/grafana/login", 200, body)
    assert title is not None
    assert severity == Severity.LOW
    assert category == FindingCategory.INFORMATION


def test_default_apache_page_detected_as_hygiene():
    body = "<html>Apache2 Ubuntu Default Page: It works!</html>"
    title, severity, category = HttpEngine._path_title("/", 200, body)
    assert title is not None
    assert category == FindingCategory.HYGIENE
    assert severity == Severity.LOW


def test_default_nginx_page_detected():
    body = "<html><h1>Welcome to nginx!</h1></html>"
    title, severity, category = HttpEngine._path_title("/", 200, body)
    assert title is not None
    assert category == FindingCategory.HYGIENE


def test_iis_default_page_detected():
    body = "<html>IIS Windows Server</html>"
    title, severity, category = HttpEngine._path_title("/", 200, body)
    assert title is not None
    assert category == FindingCategory.HYGIENE


def test_generic_password_form_is_login_information():
    body = '<html><form><input type="password" name="pass"/></form></html>'
    title, severity, category = HttpEngine._path_title("/login", 200, body)
    assert title is not None
    assert severity == Severity.INFO
    assert category == FindingCategory.INFORMATION


# ---------------------------------------------------------------------------
# High-value special paths preserved
# ---------------------------------------------------------------------------

def test_git_head_exposed():
    title, severity, _ = HttpEngine._path_title("/.git/HEAD", 200, "ref: refs/heads/main")
    assert title == "Exposed Git Metadata"
    assert severity == Severity.HIGH


def test_env_file_exposed():
    body = "DB_PASSWORD=secret\nSECRET_KEY=abc123"
    title, severity, _ = HttpEngine._path_title("/.env", 200, body)
    assert title == "Exposed Environment File"
    assert severity == Severity.HIGH


def test_phpinfo_exposed():
    title, severity, _ = HttpEngine._path_title("/phpinfo.php", 200, "phpinfo() output")
    assert title == "Exposed phpinfo Page"
    assert severity == Severity.HIGH


def test_actuator_env_is_high():
    title, severity, _ = HttpEngine._path_title("/actuator/env", 200, '{"activeProfiles":[]}')
    assert severity == Severity.HIGH


def test_actuator_health_is_medium():
    title, severity, _ = HttpEngine._path_title("/actuator/health", 200, '{"status":"UP"}')
    assert severity == Severity.MEDIUM


def test_swagger_is_information():
    title, severity, category = HttpEngine._path_title("/swagger-ui/", 200, "swagger")
    assert title is not None
    assert category == FindingCategory.INFORMATION


def test_directory_listing():
    body = "Index of / <a href"
    title, severity, _ = HttpEngine._path_title("/", 200, body)
    assert title == "Directory Listing Enabled"
    assert severity == Severity.MEDIUM


def test_server_status():
    title, severity, _ = HttpEngine._path_title("/server-status", 200, "apache server status")
    assert title == "Exposed Server Status Page"
    assert severity == Severity.MEDIUM
