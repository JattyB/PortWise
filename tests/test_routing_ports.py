from portwise.core.models import Asset, Service
from portwise.core.routing import route_assets
from portwise.modules.registry import KubernetesContainerModule
from portwise.core.models import Confidence, FindingCategory, Severity


def _asset(host, services):
    return Asset(ip=host, services=services)


def test_cloudflare_alt_ports_route_to_web():
    # nmap default names that are NOT web fingerprints
    svcs = [
        Service(host="1.1.1.1", port=2052, protocol="tcp", state="open", service_name="clearvisn"),
        Service(host="1.1.1.1", port=2083, protocol="tcp", state="open", service_name="radsec"),
        Service(host="1.1.1.1", port=8880, protocol="tcp", state="open", service_name="cddbp-alt"),
        Service(host="1.1.1.1", port=5000, protocol="tcp", state="open", service_name="upnp"),
    ]
    routes = route_assets([_asset("1.1.1.1", svcs)])
    http_ports = {t.port for t in routes["http_targets"]}
    tls_ports = {t.port for t in routes["tls_targets"]}
    assert {2052, 8880, 5000}.issubset(http_ports)
    assert 2083 in http_ports          # https alt port still gets web checks
    assert 2083 in tls_ports           # ...and TLS checks


def test_db_and_docker_ports_route():
    svcs = [
        Service(host="2.2.2.2", port=6379, protocol="tcp", state="open", service_name="unknown"),
        Service(host="2.2.2.2", port=9200, protocol="tcp", state="open", service_name="wap-wsp"),
        Service(host="2.2.2.2", port=2375, protocol="tcp", state="open", service_name="docker"),
    ]
    routes = route_assets([_asset("2.2.2.2", svcs)])
    assert 6379 in {t.port for t in routes["database_targets"]}
    assert 9200 in {t.port for t in routes["database_targets"]}
    assert 2375 in {t.port for t in routes["kubernetes_targets"]}


def test_unauthenticated_docker_api_is_critical(monkeypatch):
    import portwise.modules.registry as reg
    # Make the safe HTTP fingerprint return a Docker /version-like 200 response
    monkeypatch.setattr(reg, "_safe_http_fingerprint",
                        lambda target, config, paths, client=None: (200, "", '{"ApiVersion":"1.43","Version":"24.0"}', "http://2.2.2.2:2375/version"))
    result = KubernetesContainerModule().run(
        {"host": "2.2.2.2", "port": 2375, "protocol": "tcp", "service": "docker"}, {})
    crit = [f for f in result.findings if f.title == "Unauthenticated Docker API Access"]
    assert crit and crit[0].severity == Severity.CRITICAL
    assert crit[0].category == FindingCategory.VULNERABILITY
