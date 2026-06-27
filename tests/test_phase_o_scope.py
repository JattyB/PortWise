import pytest

from portwise.core.config import ConfigError
from portwise.core.scope import ScopePolicy
from portwise.modules.http.surface import DiscoveredSurface


def test_scope_allows_host_domain_and_cidr_but_exclude_wins():
    policy = ScopePolicy(["example.com", "10.0.0.0/24"], ["admin.example.com"])
    assert policy.permits("https://www.example.com/a")
    assert policy.permits("10.0.0.8")
    assert not policy.permits("admin.example.com")
    assert not policy.permits("example.net")


def test_out_of_scope_target_hard_fails_and_override_is_explicit():
    with pytest.raises(ConfigError, match="Refusing out-of-scope"):
        ScopePolicy(["example.com"]).require(["example.net"])
    ScopePolicy(["example.com"], override=True).require(["example.net"])


def test_discovered_out_of_scope_url_is_dropped():
    surface = DiscoveredSurface("example.com", scope_policy=ScopePolicy(["example.com"]))
    assert surface.add_url("https://example.com/ok", "crawl")
    assert surface.add_url("https://outside.test/no", "archive") == ""
    assert list(surface.endpoints) == ["https://example.com/ok"]
