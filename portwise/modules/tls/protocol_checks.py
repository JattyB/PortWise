from __future__ import annotations

import ssl


TLS_PROTOCOLS: dict[str, ssl.TLSVersion] = {
    "TLS 1.0": ssl.TLSVersion.TLSv1,
    "TLS 1.1": ssl.TLSVersion.TLSv1_1,
    "TLS 1.2": ssl.TLSVersion.TLSv1_2,
    "TLS 1.3": ssl.TLSVersion.TLSv1_3,
}
