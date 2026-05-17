from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from portwise.core.models import Asset, Service


def parse_nmap_xml(path: Path | str) -> list[Asset]:
    xml_path = Path(path)
    if not xml_path.exists() or xml_path.stat().st_size == 0:
        return []
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError:
        return []
    root = tree.getroot()
    assets: list[Asset] = []

    for host in root.findall("host"):
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            address = host.find("address[@addrtype='ipv6']")
        if address is None:
            address = host.find("address")
        if address is None:
            continue
        addresses = {item.attrib.get("addrtype", ""): item.attrib.get("addr", "") for item in host.findall("address")}
        ip = address.attrib.get("addr", "")
        hostnames = [
            hostname.attrib.get("name", "")
            for hostname in host.findall("./hostnames/hostname")
            if hostname.attrib.get("name")
        ]
        status_el = host.find("status")
        asset = Asset(
            ip=ip,
            status=status_el.attrib.get("state", "unknown") if status_el is not None else "unknown",
            ipv4=addresses.get("ipv4"),
            ipv6=addresses.get("ipv6"),
            hostnames=hostnames,
        )

        for port_el in host.findall("./ports/port"):
            state_el = port_el.find("state")
            service_el = port_el.find("service")
            scripts = {
                script.attrib.get("id", "script"): script.attrib.get("output", "")
                for script in port_el.findall("script")
            }
            cpes = [cpe.text.strip() for cpe in port_el.findall("./service/cpe") if cpe.text]
            service = Service(
                host=ip,
                hostname=hostnames[0] if hostnames else None,
                port=int(port_el.attrib.get("portid", "0")),
                protocol=port_el.attrib.get("protocol", ""),
                state=state_el.attrib.get("state", "") if state_el is not None else "",
                reason=state_el.attrib.get("reason", "") if state_el is not None else "",
                service_name=service_el.attrib.get("name", "") if service_el is not None else "",
                product=service_el.attrib.get("product", "") if service_el is not None else "",
                version=service_el.attrib.get("version", "") if service_el is not None else "",
                extrainfo=service_el.attrib.get("extrainfo", "") if service_el is not None else "",
                tunnel=service_el.attrib.get("tunnel") if service_el is not None else None,
                method=service_el.attrib.get("method") if service_el is not None else None,
                confidence=int(service_el.attrib["conf"]) if service_el is not None and service_el.attrib.get("conf", "").isdigit() else None,
                cpes=cpes,
                scripts=scripts,
                source_file=str(xml_path),
            )
            asset.add_service(service)
        assets.append(asset)

    return assets
