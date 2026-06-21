from __future__ import annotations

from portwise.core.models import ModuleTarget
from portwise.core.module_runner import execute_safe_modules
from portwise.modules.results import ModuleResult


def test_module_runner_injects_and_closes_shared_http_client(monkeypatch):
    seen_clients = []

    class _Client:
        def __init__(self) -> None:
            self.closed = False

        def close_sync(self) -> None:
            self.closed = True

    created = []

    def fake_client_from_config(config):
        client = _Client()
        created.append(client)
        return client

    class _Module:
        name = "http"
        description = "dummy"

        def execute(self, target, config):
            seen_clients.append(config["_shared_http_client_factory"]())
            return ModuleResult(self.name, target)

    monkeypatch.setattr("portwise.core.module_runner.available_modules", lambda: [_Module()])
    monkeypatch.setattr("portwise.core.module_runner.module_targets_key", lambda name: "http_targets")
    monkeypatch.setattr("portwise.core.module_runner.client_from_config", fake_client_from_config)

    execute_safe_modules(
        {
            "http_targets": [
                ModuleTarget(host="203.0.113.10", port=80, protocol="tcp", service="http"),
                ModuleTarget(host="203.0.113.10", port=8080, protocol="tcp", service="http"),
            ]
        },
        config={"module_concurrency": 1},
        enabled_modules={"http": True},
        dry_run=False,
    )

    assert len(created) == 1
    assert seen_clients == [created[0], created[0]]
    assert created[0].closed is True
