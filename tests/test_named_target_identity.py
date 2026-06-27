import socket

from portwise.core.models import Asset, Service
from portwise.core.runner import _restore_named_target_assets


def test_shared_ip_targets_remain_distinct_for_sni(monkeypatch):
    source = Asset(
        ip="192.0.2.10",
        status="up",
        services=[Service("192.0.2.10", 443, "tcp", "open", "https")],
    )

    def resolve(name, *_args, **_kwargs):
        assert name in {"expired.example", "self-signed.example"}
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    assets = _restore_named_target_assets(
        [source],
        ["expired.example", "self-signed.example"],
    )
    aliases = {asset.ip: asset for asset in assets}
    assert aliases["expired.example"].services[0].hostname == "expired.example"
    assert aliases["self-signed.example"].services[0].host == "self-signed.example"
