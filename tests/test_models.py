from portwise.core.models import Asset, Evidence, Finding, Service, Severity
from portwise.scanners.nmap_parser import parse_nmap_xml


def test_model_creation() -> None:
    service = Service(host="192.0.2.10", port=443, protocol="tcp", state="open", service_name="https")
    asset = Asset(ip="192.0.2.10")
    asset.add_service(service)
    finding = Finding(
        title="TLS 1.0 Supported",
        severity=Severity.MEDIUM,
        asset=asset.ip,
        port=443,
        evidence=[Evidence("tls", "Handshake succeeded.", 5)],
    )
    assert asset.services[0].endpoint == "192.0.2.10:443/tcp"
    assert finding.evidence_strength == 1
    assert finding.evidence[0].strength == 5


def test_nmap_parser_inline_sample(tmp_path) -> None:
    sample = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames><hostname name="web.example.test" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.24.0" tunnel="ssl" conf="10">
          <cpe>cpe:/a:nginx:nginx:1.24.0</cpe>
        </service>
        <script id="ssl-cert" output="subject=example"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    path = tmp_path / "sample.xml"
    path.write_text(sample, encoding="utf-8")
    assets = parse_nmap_xml(path)
    assert len(assets) == 1
    assert assets[0].hostnames == ["web.example.test"]
    service = assets[0].services[0]
    assert service.port == 443
    assert service.product == "nginx"
    assert service.cpes == ["cpe:/a:nginx:nginx:1.24.0"]
    assert service.scripts["ssl-cert"]["output"] == "subject=example"
