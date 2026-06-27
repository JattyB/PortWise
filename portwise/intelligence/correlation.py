"""High-precision cross-finding correlation and attack-path construction."""
from __future__ import annotations

from collections import defaultdict

from portwise.core.models import Confidence, Evidence, Finding, Severity


def correlate_findings(findings: list[Finding]) -> list[Finding]:
    correlated = credential_reuse_findings(findings)
    correlated.extend(secret_endpoint_paths(findings))
    return correlated


def credential_reuse_findings(findings: list[Finding]) -> list[Finding]:
    accepted: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        if finding.type != "authenticated":
            continue
        for evidence in finding.evidence:
            credential_id = str(evidence.data.get("credential_id", ""))
            if credential_id:
                accepted[credential_id].append(finding)
    output: list[Finding] = []
    for credential_id, linked in accepted.items():
        hosts = sorted({str(item.asset) for item in linked})
        if len(hosts) < 2:
            continue
        refs = sorted({item.id for item in linked})
        output.append(Finding(
            title="Credential Reuse Across Hosts",
            severity=Severity.HIGH,
            asset=", ".join(hosts),
            description=f"One operator-supplied credential authenticated successfully on {len(hosts)} hosts.",
            recommendation="Issue unique credentials per trust boundary and rotate the reused credential.",
            confidence=Confidence.CONFIRMED,
            evidence_strength=5,
            type="credential-reuse",
            module="correlation",
            false_positive_risk="low",
            evidence=[Evidence(
                "correlation:credential-reuse",
                "Successful authentication findings share the same non-reversible credential identifier.",
                5,
                {"credential_id": credential_id, "hosts": hosts, "finding_ids": refs},
            )],
            tags=["authenticated", "credential-reuse", "attack-path"],
        ))
    return output


def secret_endpoint_paths(findings: list[Finding]) -> list[Finding]:
    secrets = [f for f in findings if "secret" in f.tags or f.type in {"js-secret", "secret"}]
    endpoints = [f for f in findings if f.type in {"authenticated", "http-exposure"}]
    output: list[Finding] = []
    for secret in secrets:
        for endpoint in endpoints:
            if secret.asset != endpoint.asset:
                continue
            # Require explicit endpoint linkage in evidence; same-host alone is not enough.
            secret_urls = {
                str(value)
                for ev in secret.evidence
                for key, value in ev.data.items()
                if key in {"url", "endpoint"} and value
            }
            endpoint_urls = {
                str(value)
                for ev in endpoint.evidence
                for key, value in ev.data.items()
                if key in {"url", "endpoint", "path"} and value
            }
            if not secret_urls.intersection(endpoint_urls):
                continue
            output.append(Finding(
                title="Attack Path - Client Secret Reaches Valid Endpoint",
                severity=Severity.HIGH,
                asset=secret.asset,
                port=endpoint.port,
                description="A client-delivered secret is explicitly linked to a reachable authenticated or exposed endpoint.",
                recommendation="Revoke the secret, remove it from client content, and enforce server-side authorization.",
                confidence=Confidence.LIKELY,
                evidence_strength=4,
                type="attack-path",
                module="correlation",
                evidence=[Evidence(
                    "correlation:attack-path",
                    "Related findings share an explicit endpoint.",
                    4,
                    {"finding_ids": [secret.id, endpoint.id], "endpoints": sorted(secret_urls & endpoint_urls)},
                )],
                tags=["attack-path", "correlated"],
            ))
    return output
