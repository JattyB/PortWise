from portwise.core.routing import module_target_counts, route_assets
from portwise.scanners.nmap_parser import parse_nmap_xml


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames><hostname name="app.example.test" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache Tomcat" version="9.0.1" method="probed" conf="10">
          <cpe>cpe:/a:apache:tomcat:9.0.1</cpe>
        </service>
        <script id="http-title" output="Tomcat Manager"/>
      </port>
      <port protocol="tcp" portid="8443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.24.0" tunnel="ssl" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="2222">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.2" extrainfo="protocol 2.0" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="2121">
        <state state="open" reason="syn-ack"/>
        <service name="ftp" product="vsftpd" version="3.0.5" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds" product="Samba smbd" version="4.18" method="probed" conf="10"/>
      </port>
      <port protocol="udp" portid="161">
        <state state="open" reason="udp-response"/>
        <service name="snmp" product="Net-SNMP" version="5.9" method="probed" conf="10"/>
      </port>
      <port protocol="udp" portid="500">
        <state state="open|filtered" reason="no-response"/>
        <service name="isakmp" method="table" conf="3"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.0.2.20" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def test_parser_extracts_services_and_udp_states(tmp_path) -> None:
    path = tmp_path / "sample.xml"
    path.write_text(SAMPLE_XML, encoding="utf-8")

    assets = parse_nmap_xml(path)

    assert len(assets) == 2
    assert assets[0].status == "up"
    assert assets[0].ipv4 == "192.0.2.10"
    assert assets[0].hostnames == ["app.example.test"]
    services = {(svc.protocol, svc.port): svc for svc in assets[0].services}
    assert services[("tcp", 8080)].product == "Apache Tomcat"
    assert services[("tcp", 8080)].cpes == ["cpe:/a:apache:tomcat:9.0.1"]
    assert services[("tcp", 8080)].scripts["http-title"]["output"] == "Tomcat Manager"
    assert services[("tcp", 8443)].tunnel == "ssl"
    assert services[("tcp", 2222)].service_name == "ssh"
    assert services[("tcp", 2121)].service_name == "ftp"
    assert services[("udp", 161)].state == "open"
    assert services[("udp", 500)].state == "open|filtered"
    assert services[("udp", 500)].confidence == 3
    assert assets[1].status == "down"


def test_module_routing_uses_fingerprints_not_just_ports(tmp_path) -> None:
    path = tmp_path / "sample.xml"
    path.write_text(SAMPLE_XML, encoding="utf-8")
    assets = parse_nmap_xml(path)

    routes = route_assets(assets)
    counts = module_target_counts(routes)

    assert counts["http_targets"] == 2
    assert counts["tls_targets"] == 1
    assert counts["ssh_targets"] == 1
    assert routes["ssh_targets"][0].port == 2222
    assert counts["ftp_targets"] == 1
    assert routes["ftp_targets"][0].port == 2121
    assert counts["smb_targets"] == 1
    assert counts["snmp_targets"] == 1
    assert counts["devops_targets"] >= 1
    assert any(target.port == 500 for target in routes["unknown_services"])
