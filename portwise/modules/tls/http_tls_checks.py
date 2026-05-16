from __future__ import annotations

from portwise.core.models import Service


def service_suggests_tls(service: Service) -> bool:
    text = " ".join([service.service_name, service.product, service.extrainfo, service.tunnel or ""]).lower()
    return service.port in {443, 8443, 9443} or "ssl" in text or "https" in text or "tls" in text
