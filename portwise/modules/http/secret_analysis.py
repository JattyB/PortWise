from __future__ import annotations

import math
import re
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any, Iterable

from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity


@dataclass(frozen=True, slots=True)
class SecretRule:
    id: str
    description: str
    regex: str
    secret_group: int = 0
    entropy: float = 0.0
    keywords: tuple[str, ...] = ()
    path: str | None = None


@dataclass(frozen=True, slots=True)
class SecretMatch:
    rule_id: str
    description: str
    value: str
    redacted: str
    source: str
    kind: str
    entropy: float
    confidence: str
    context: str


@dataclass(slots=True)
class SecretScanResult:
    matches: list[SecretMatch] = field(default_factory=list)
    scanned: int = 0

    @property
    def true_positives(self) -> int:
        return len(self.matches)


def load_secret_rules() -> list[SecretRule]:
    return _load_rules()


def scan_secret_texts(
    samples: Iterable[dict[str, Any]],
    *,
    source_kind: str = "text",
    rules: list[SecretRule] | None = None,
) -> SecretScanResult:
    active_rules = rules or load_secret_rules()
    result = SecretScanResult()
    for sample in samples:
        text = str(sample.get("text", ""))
        source = str(sample.get("source", ""))
        kind = str(sample.get("kind", source_kind))
        result.scanned += 1
        result.matches.extend(_scan_text(text, source=source, kind=kind, rules=active_rules))
    return result


def secret_findings(
    samples: Iterable[dict[str, Any]],
    *,
    asset: str,
    port: int | None,
    protocol: str | None,
    service: str | None,
    module: str = "http",
    rules: list[SecretRule] | None = None,
) -> list[Finding]:
    scan = scan_secret_texts(samples, source_kind="text", rules=rules)
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for match in scan.matches:
        key = (match.rule_id, match.value)
        if key in seen:
            continue
        seen.add(key)
        evidence = Evidence(
            f"module:{module}:secret",
            f"Matched secret rule {match.rule_id} in {match.source}.",
            4,
            {
                "rule_id": match.rule_id,
                "source": match.source,
                "kind": match.kind,
                "entropy": round(match.entropy, 2),
                "confidence": match.confidence,
                "context": match.context[:200],
                "value_redacted": match.redacted,
            },
        )
        findings.append(Finding(
            title=f"Potential Secret Exposed ({match.rule_id})",
            severity=Severity.HIGH,
            asset=asset,
            port=port,
            protocol=protocol,
            service=service,
            description=f"A possible secret matched rule {match.rule_id} in {match.source}: {match.redacted}.",
            recommendation="Validate the value, rotate any live credential, and move secrets out of client-delivered assets.",
            confidence=Confidence.NEEDS_MANUAL_VALIDATION,
            evidence_strength=4,
            type="Secret Exposure",
            module=module,
            false_positive_risk="medium",
            manual_validation=True,
            evidence=[evidence],
            category=FindingCategory.VULNERABILITY,
            tags=["secret", "manual-required", "js-analysis"],
        ))
    return findings


def _scan_text(text: str, *, source: str, kind: str, rules: list[SecretRule]) -> list[SecretMatch]:
    lowered = text.lower()
    matches: list[SecretMatch] = []
    for rule in rules:
        if rule.path and not re.search(rule.path, source, re.IGNORECASE):
            continue
        if rule.keywords and not any(keyword.lower() in lowered for keyword in rule.keywords):
            continue
        try:
            regex = _compiled(rule.regex)
        except re.error:
            continue
        for match in regex.finditer(text):
            value = _extract_secret(match, rule.secret_group)
            if not value or not _looks_like_secret(value, rule, text, match.start(), match.end()):
                continue
            entropy = shannon_entropy(value)
            if rule.entropy and entropy < rule.entropy:
                continue
            context = _context_window(text, match.start(), match.end())
            if not _context_allows(context, value, rule):
                continue
            matches.append(SecretMatch(
                rule_id=rule.id,
                description=rule.description,
                value=value,
                redacted=_redact(value),
                source=source,
                kind=kind,
                entropy=entropy,
                confidence=_confidence_from_entropy(entropy, rule.entropy),
                context=context,
            ))
    return matches


def _extract_secret(match: re.Match[str], secret_group: int) -> str:
    if secret_group > 0:
        try:
            value = match.group(secret_group)
            if value:
                return value
        except IndexError:
            return ""
    if match.lastindex:
        for idx in range(1, match.lastindex + 1):
            value = match.group(idx)
            if value:
                return value
    return match.group(0)


def _looks_like_secret(value: str, rule: SecretRule, text: str, start: int, end: int) -> bool:
    lowered = value.lower()
    if any(token in lowered for token in ("example", "placeholder", "dummy", "sample", "changeme", "replace_me", "your_", "test")):
        return False
    if lowered.isdigit() or len(set(lowered)) <= 4:
        return False
    window = text[max(0, start - 64): min(len(text), end + 64)].lower()
    if rule.id != "private-key-block" and not any(
        term in window
        for term in (
            "key",
            "secret",
            "token",
            "auth",
            "bearer",
            "credential",
            "password",
            "client",
            "api",
        )
    ) and not any(keyword.lower() in window for keyword in rule.keywords):
        return False
    return True


def _context_allows(context: str, value: str, rule: SecretRule) -> bool:
    lowered = context.lower()
    if any(token in lowered for token in ("example", "placeholder", "dummy", "sample", "changeme", "test key", "fake", "not a real", "demo")):
        return False
    if "minified" in lowered and len(value) < 40:
        return False
    if rule.id == "private-key-block":
        return True
    if rule.keywords and any(keyword.lower() in lowered for keyword in rule.keywords):
        return True
    return any(term in lowered for term in ("key", "secret", "token", "auth", "bearer", "credential", "password", "client", "api"))


def _context_window(text: str, start: int, end: int, window: int = 80) -> str:
    return text[max(0, start - window): min(len(text), end + window)]


def _confidence_from_entropy(entropy: float, threshold: float) -> str:
    if threshold and entropy >= threshold + 0.75:
        return "high"
    if threshold and entropy >= threshold:
        return "medium"
    return "low"


def _redact(value: str) -> str:
    if len(value) <= 8:
        return value[:2] + "***"
    return value[:4] + "***" + value[-4:]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


@lru_cache(maxsize=1)
def _load_rules() -> list[SecretRule]:
    data = resources.files("portwise").joinpath("data", "secrets", "rules.toml").read_bytes()
    parsed = tomllib.loads(data.decode("utf-8"))
    rules: list[SecretRule] = []
    for item in parsed.get("rules", []):
        rules.append(SecretRule(
            id=str(item.get("id", "")),
            description=str(item.get("description", "")),
            regex=str(item.get("regex", "")),
            secret_group=int(item.get("secretGroup", 0) or 0),
            entropy=float(item.get("entropy", 0) or 0),
            keywords=tuple(str(keyword) for keyword in item.get("keywords", []) or []),
            path=str(item.get("path")) if item.get("path") else None,
        ))
    return rules


@lru_cache(maxsize=4096)
def _compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)
