from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from html.parser import HTMLParser
from importlib import resources
from typing import Any, Iterable

from portwise.core.models import Evidence, Finding, FindingCategory, Service, Severity


@dataclass(frozen=True, slots=True)
class TechnologyMatch:
    name: str
    confidence: int
    version: str | None = None
    categories: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()


@dataclass(slots=True)
class _MatchAccumulator:
    confidence: int = 0
    version: str | None = None
    evidence: set[str] = field(default_factory=set)


class _HTMLSignals(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, list[str]] = {}
        self.script_src: list[str] = []
        self.inline_scripts: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {name.lower(): value or "" for name, value in attrs}
        if tag.lower() == "meta":
            name = (attrs_dict.get("name") or attrs_dict.get("property") or attrs_dict.get("http-equiv") or "").lower()
            content = attrs_dict.get("content", "")
            if name:
                self.meta.setdefault(name, []).append(content)
        if tag.lower() == "script":
            src = attrs_dict.get("src")
            if src:
                self.script_src.append(src)
            self._in_script = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script and data.strip():
            self.inline_scripts.append(data)


class WappalyzerFingerprinter:
    def __init__(self, apps: dict[str, dict[str, Any]], categories: dict[str, dict[str, Any]]) -> None:
        self.apps = apps
        self.categories = categories

    @classmethod
    def bundled(cls) -> WappalyzerFingerprinter:
        return _load_bundled_fingerprinter()

    def identify(
        self,
        *,
        url: str,
        headers: dict[str, str] | list[tuple[str, str]],
        cookies: dict[str, str] | None = None,
        body: bytes | str = b"",
        min_confidence: int = 50,
    ) -> list[TechnologyMatch]:
        headers_map = _normalize_headers(headers)
        cookie_map = {key.lower(): value for key, value in (cookies or {}).items()}
        text = body.decode("utf-8", errors="ignore") if isinstance(body, bytes) else body
        html = _parse_html(text)
        matches: dict[str, _MatchAccumulator] = {}

        for name, app in self.apps.items():
            acc = _MatchAccumulator()
            self._match_header_patterns(name, app, headers_map, acc)
            self._match_cookie_patterns(name, app, cookie_map, headers_map, acc)
            self._match_meta_patterns(name, app, html.meta, acc)
            self._match_list_patterns(name, app.get("html"), text, "html", acc)
            self._match_list_patterns(name, app.get("text"), text, "text", acc)
            self._match_list_patterns(name, app.get("scripts"), "\n".join(html.inline_scripts), "script", acc)
            self._match_list_patterns(name, app.get("scriptSrc"), "\n".join(html.script_src), "script-src", acc)
            self._match_list_patterns(name, app.get("url"), url, "url", acc)
            if acc.confidence >= min_confidence:
                matches[name] = acc

        self._apply_implies(matches)
        return self._to_results(matches, min_confidence)

    def _match_header_patterns(
        self,
        name: str,
        app: dict[str, Any],
        headers: dict[str, str],
        acc: _MatchAccumulator,
    ) -> None:
        for header, pattern in _dict_items(app.get("headers")):
            value = headers.get(header.lower(), "")
            _record_pattern_match(name, f"header:{header}", pattern, value, acc)

    def _match_cookie_patterns(
        self,
        name: str,
        app: dict[str, Any],
        cookies: dict[str, str],
        headers: dict[str, str],
        acc: _MatchAccumulator,
    ) -> None:
        for cookie, pattern in _dict_items(app.get("cookies")):
            value = cookies.get(cookie.lower())
            if value is None and cookie.lower() in headers.get("set-cookie", "").lower():
                value = headers.get("set-cookie", "")
            _record_pattern_match(name, f"cookie:{cookie}", pattern, value or "", acc)

    def _match_meta_patterns(
        self,
        name: str,
        app: dict[str, Any],
        meta: dict[str, list[str]],
        acc: _MatchAccumulator,
    ) -> None:
        for meta_name, patterns in _dict_items(app.get("meta")):
            values = meta.get(meta_name.lower(), [])
            for value in values:
                for pattern in _as_list(patterns):
                    _record_pattern_match(name, f"meta:{meta_name}", pattern, value, acc)

    def _match_list_patterns(
        self,
        name: str,
        patterns: Any,
        value: str,
        source: str,
        acc: _MatchAccumulator,
    ) -> None:
        if not value:
            return
        for pattern in _as_list(patterns):
            _record_pattern_match(name, source, pattern, value, acc)

    def _apply_implies(self, matches: dict[str, _MatchAccumulator]) -> None:
        pending = list(matches)
        seen = set(pending)
        while pending:
            name = pending.pop()
            app = self.apps.get(name, {})
            for implied in _as_list(app.get("implies")):
                implied_name = str(implied).split(r"\;", 1)[0].split(";", 1)[0]
                if implied_name in seen or implied_name not in self.apps:
                    continue
                matches[implied_name] = _MatchAccumulator(
                    confidence=50,
                    evidence={f"implied-by:{name}"},
                )
                seen.add(implied_name)
                pending.append(implied_name)

    def _to_results(self, matches: dict[str, _MatchAccumulator], min_confidence: int) -> list[TechnologyMatch]:
        results: list[TechnologyMatch] = []
        for name, acc in matches.items():
            if acc.confidence < min_confidence:
                continue
            app = self.apps.get(name, {})
            categories = tuple(
                self.categories.get(str(cat), {}).get("name", str(cat))
                for cat in app.get("cats", [])
            )
            results.append(TechnologyMatch(
                name=name,
                confidence=min(acc.confidence, 100),
                version=acc.version,
                categories=categories,
                evidence=tuple(sorted(acc.evidence)),
            ))
        return sorted(results, key=lambda item: (-item.confidence, item.name.lower()))


def detect_technologies(
    *,
    url: str,
    headers: dict[str, str] | list[tuple[str, str]],
    cookies: dict[str, str] | None = None,
    body: bytes | str = b"",
    min_confidence: int = 50,
) -> list[TechnologyMatch]:
    return WappalyzerFingerprinter.bundled().identify(
        url=url,
        headers=headers,
        cookies=cookies,
        body=body,
        min_confidence=min_confidence,
    )


def technology_finding(service: Service, technologies: Iterable[TechnologyMatch]) -> Finding | None:
    techs = list(technologies)
    if not techs:
        return None
    data = [
        {
            "name": tech.name,
            "version": tech.version,
            "confidence": tech.confidence,
            "categories": list(tech.categories),
            "evidence": list(tech.evidence)[:8],
        }
        for tech in techs
    ]
    evidence = Evidence(
        "http-technology-fingerprint",
        "Wappalyzer-compatible native technology fingerprinting matched response evidence.",
        4,
        {"technologies": data},
    )
    names = ", ".join(
        f"{tech.name} {tech.version}".strip() if tech.version else tech.name
        for tech in techs[:10]
    )
    return Finding(
        title="HTTP Technology Fingerprint",
        severity=Severity.INFO,
        asset=service.host,
        port=service.port,
        protocol=service.protocol,
        service=service.service_name,
        description=f"Detected web technologies: {names}.",
        recommendation="Use the technology inventory to prioritize version-specific validation and hardening.",
        evidence_strength=4,
        type="http-technology",
        module="http",
        evidence=[evidence],
        tags=["safe-active", "technology-fingerprint", "wappalyzer"],
        category=FindingCategory.INFORMATION,
    )


@lru_cache(maxsize=1)
def _load_bundled_fingerprinter() -> WappalyzerFingerprinter:
    data_root = resources.files("portwise").joinpath("data", "wappalyzer")
    apps_data = json.loads(data_root.joinpath("fingerprints_data.json").read_text(encoding="utf-8"))
    categories = json.loads(data_root.joinpath("categories_data.json").read_text(encoding="utf-8"))
    apps = apps_data.get("apps", apps_data)
    if not isinstance(apps, dict):
        raise ValueError("Bundled Wappalyzer fingerprint data is invalid.")
    return WappalyzerFingerprinter(apps=apps, categories=categories)


def _parse_html(text: str) -> _HTMLSignals:
    parser = _HTMLSignals()
    try:
        parser.feed(text[:1_000_000])
    except Exception:
        pass
    return parser


def _normalize_headers(headers: dict[str, str] | list[tuple[str, str]]) -> dict[str, str]:
    if isinstance(headers, dict):
        items = headers.items()
    else:
        items = headers
    out: dict[str, str] = {}
    for key, value in items:
        lower = key.lower()
        out[lower] = f"{out[lower]}, {value}" if lower in out else value
    return out


def _dict_items(value: Any) -> Iterable[tuple[str, Any]]:
    return value.items() if isinstance(value, dict) else ()


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _record_pattern_match(name: str, source: str, pattern_value: Any, value: str, acc: _MatchAccumulator) -> None:
    pattern = str(pattern_value or "")
    if not value and pattern:
        return
    parsed = _parse_pattern(pattern)
    if pattern == "":
        if value:
            _record(acc, 100, None, f"{source}:present")
        return
    regex = parsed["regex"]
    try:
        compiled = _compile_regex(regex)
    except re.error:
        return
    match = compiled.search(value)
    if not match:
        return
    version_template = parsed.get("version")
    version = None
    if version_template:
        try:
            version = match.expand(str(version_template)).strip()
        except re.error:
            version = None
    confidence = int(parsed.get("confidence", 100))
    _record(acc, confidence, version, f"{source}:{name}")


def _record(acc: _MatchAccumulator, confidence: int, version: str | None, evidence: str) -> None:
    acc.confidence = max(acc.confidence, confidence)
    if version and version != r"\1":
        acc.version = version
    acc.evidence.add(evidence)


def _parse_pattern(pattern: str) -> dict[str, Any]:
    normalized = pattern.replace(r"\;", ";")
    parts = normalized.split(";")
    parsed: dict[str, Any] = {"regex": parts[0]}
    for part in parts[1:]:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        if key == "confidence":
            try:
                parsed[key] = int(value)
            except ValueError:
                pass
        elif key == "version":
            parsed[key] = value
    return parsed


@lru_cache(maxsize=20_000)
def _compile_regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)
