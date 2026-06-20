from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import yaml

from portwise.core.models import Finding
from portwise.intelligence.web_engines import parse_nuclei_records
from portwise.utils.http_client import PoliteHttpClient, PoliteResponse

_SUPPORTED_MATCHERS = {"status", "word", "regex", "binary", "size"}
_SUPPORTED_EXTRACTORS = {"regex", "kval", "json"}
_SKIPPED_MARKERS = ("workflow", "workflows", "interactsh", "flow")
_UNSUPPORTED_HTTP_KEYS = {"dsl", "interactsh", "payloads", "attack", "race", "threads"}
_STATIC_TEMPLATE_PATTERNS = ("{{BaseURL}}", "{{RootURL}}", "{{Hostname}}", "{{Host}}", "{{Port}}", "{{Scheme}}")
_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}


@dataclass(slots=True)
class NucleiMatcher:
    type: str
    part: str = "body"
    negative: bool = False
    condition: str = "or"
    words: list[str] = field(default_factory=list)
    regex: list[str] = field(default_factory=list)
    binary: list[str] = field(default_factory=list)
    status: list[int] = field(default_factory=list)
    size: list[int] = field(default_factory=list)


@dataclass(slots=True)
class NucleiExtractor:
    type: str
    name: str = ""
    part: str = "body"
    regex: list[str] = field(default_factory=list)
    kval: list[str] = field(default_factory=list)
    json_paths: list[str] = field(default_factory=list)
    group: int = 0


@dataclass(slots=True)
class NucleiRequest:
    method: str
    paths: list[str] = field(default_factory=list)
    raw: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    matchers: list[NucleiMatcher] = field(default_factory=list)
    matchers_condition: str = "or"
    extractors: list[NucleiExtractor] = field(default_factory=list)
    unsupported_features: list[str] = field(default_factory=list)


@dataclass(slots=True)
class NucleiTemplate:
    template_id: str
    name: str
    severity: str
    description: str
    classification: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    http: list[NucleiRequest] = field(default_factory=list)
    path: str = ""
    unsupported_features: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TemplateResponse:
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    url: str

    @property
    def header_text(self) -> str:
        return "\n".join(f"{key}: {value}" for key, value in self.headers)

    @property
    def body_text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def raw_text(self) -> str:
        return f"{self.header_text}\n\n{self.body_text}"

    @property
    def all_text(self) -> str:
        return self.raw_text

    @property
    def headers_lower(self) -> dict[str, str]:
        return {key.lower(): value for key, value in self.headers}


@dataclass(slots=True)
class TemplateMatch:
    template: NucleiTemplate
    request: NucleiRequest
    url: str
    response: TemplateResponse
    extracted: list[str] = field(default_factory=list)


@dataclass(slots=True)
class NativeNucleiRunResult:
    findings: list[Finding] = field(default_factory=list)
    loaded_templates: int = 0
    attempted_requests: int = 0
    matched_requests: int = 0
    skipped_features: list[str] = field(default_factory=list)
    skipped_templates: list[str] = field(default_factory=list)
    elapsed_s: float = 0.0

    @property
    def templates_per_s(self) -> float:
        return self.loaded_templates / self.elapsed_s if self.elapsed_s > 0 else 0.0


class NativeNucleiEngine:
    def __init__(
        self,
        client: PoliteHttpClient | None = None,
        *,
        concurrency: int = 10,
        timeout: float = 8.0,
    ) -> None:
        self.client = client or PoliteHttpClient()
        self.concurrency = concurrency
        self.timeout = timeout

    async def run(
        self,
        *,
        target: dict[str, Any],
        config: dict[str, Any],
    ) -> NativeNucleiRunResult:
        started = time.perf_counter()
        cfg = config.get("web_template_engine", {}) if isinstance(config.get("web_template_engine"), dict) else {}
        templates, skipped_templates, skipped_features = load_nuclei_templates(cfg)
        result = NativeNucleiRunResult(
            loaded_templates=len(templates),
            skipped_templates=skipped_templates,
            skipped_features=sorted(set(skipped_features)),
        )
        if not templates:
            result.elapsed_s = time.perf_counter() - started
            _record_skips(config, result)
            return result

        semaphore = asyncio.Semaphore(int(cfg.get("concurrency", self.concurrency)))
        tasks = [self._run_template(semaphore, template, target) for template in templates]
        outputs = await asyncio.gather(*tasks, return_exceptions=True)
        records: list[dict[str, Any]] = []
        for output in outputs:
            if isinstance(output, Exception):
                continue
            template_records, attempted, matched, template_skips = output
            records.extend(template_records)
            result.attempted_requests += attempted
            result.matched_requests += matched
            result.skipped_features.extend(template_skips)
        result.findings = _dedup_findings(parse_nuclei_records(records, module="native-nuclei"))
        result.skipped_features = sorted(set(result.skipped_features + skipped_features))
        result.elapsed_s = time.perf_counter() - started
        _record_skips(config, result)
        return result

    async def _run_template(
        self,
        semaphore: asyncio.Semaphore,
        template: NucleiTemplate,
        target: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], int, int, list[str]]:
        base_url = _target_base_url(target)
        rendered = _render_context(base_url)
        records: list[dict[str, Any]] = []
        attempted = 0
        matched = 0
        local_skips = list(template.unsupported_features)

        for request in template.http:
            local_skips.extend(request.unsupported_features)
            for method, url, headers, body in _iter_request_variants(request, rendered):
                attempted += 1
                async with semaphore:
                    response = await self.client.request_url_async(
                        url,
                        method=method,
                        headers=headers or None,
                        body=body.encode("utf-8") if body else None,
                        timeout=self.timeout,
                        allow_redirects=True,
                    )
                template_response = TemplateResponse(
                    status=response.status,
                    headers=response.getheaders(),
                    body=response.read(),
                    url=response.request_meta.get("url", url),
                )
                if _match_request(request, template_response):
                    matched += 1
                    extracted = _extract_values(request, template_response)
                    records.append(_template_record(template, request, target, template_response, extracted))
        return records, attempted, matched, sorted(set(local_skips))


def load_nuclei_templates(config: dict[str, Any]) -> tuple[list[NucleiTemplate], list[str], list[str]]:
    include_packaged = bool(config.get("include_packaged", True))
    locations: list[Path] = []
    if include_packaged:
        locations.append(resources.files("portwise").joinpath("data", "nuclei"))  # type: ignore[arg-type]
    custom = config.get("template_dirs") or config.get("template_dir") or config.get("custom_templates")
    if isinstance(custom, str) and custom.strip():
        locations.append(Path(custom))
    elif isinstance(custom, list):
        locations.extend(Path(str(item)) for item in custom if str(item).strip())

    templates: list[NucleiTemplate] = []
    skipped_templates: list[str] = []
    skipped_features: list[str] = []
    for location in locations:
        path = Path(str(location))
        if not path.exists():
            continue
        for candidate in sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml")):
            parsed = _load_template(candidate)
            if parsed is None:
                skipped_templates.append(f"{candidate}: parse-error")
                continue
            template, template_skips = parsed
            skipped_features.extend(template_skips)
            if not template.http:
                skipped_templates.append(f"{candidate}: no-supported-http-requests")
                continue
            template.path = str(candidate)
            templates.append(template)
    return templates, skipped_templates, sorted(set(skipped_features))


def _load_template(path: Path) -> tuple[NucleiTemplate, list[str]] | None:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(document, dict):
        return None
    if any(marker in document for marker in _SKIPPED_MARKERS):
        return (
            NucleiTemplate(
                template_id=str(document.get("id", path.stem)),
                name=str(((document.get("info") or {}) if isinstance(document.get("info"), dict) else {}).get("name", path.stem)),
                severity=str(((document.get("info") or {}) if isinstance(document.get("info"), dict) else {}).get("severity", "info")),
                description=str(((document.get("info") or {}) if isinstance(document.get("info"), dict) else {}).get("description", "")),
            ),
            [f"{path.name}:unsupported-top-level"],
        )
    info = document.get("info", {}) if isinstance(document.get("info"), dict) else {}
    http_items = document.get("http") or document.get("requests") or []
    if not isinstance(http_items, list):
        http_items = [http_items]
    requests: list[NucleiRequest] = []
    skipped: list[str] = []
    for item in http_items:
        request = _parse_request_item(item, path.name)
        if request is None:
            skipped.append(f"{path.name}:unsupported-request")
            continue
        skipped.extend(request.unsupported_features)
        if request.matchers:
            requests.append(request)
        else:
            skipped.append(f"{path.name}:no-supported-matchers")
    template = NucleiTemplate(
        template_id=str(document.get("id", path.stem)),
        name=str(info.get("name", path.stem)),
        severity=str(info.get("severity", "info")),
        description=str(info.get("description", "")),
        classification=info.get("classification", {}) if isinstance(info.get("classification"), dict) else {},
        references=[str(item) for item in (info.get("reference") or [])] if isinstance(info.get("reference"), list) else ([str(info.get("reference"))] if info.get("reference") else []),
        tags=[tag.strip() for tag in str(info.get("tags", "")).split(",") if tag.strip()],
        http=requests,
        unsupported_features=skipped,
    )
    return template, skipped


def _parse_request_item(item: Any, template_name: str) -> NucleiRequest | None:
    if not isinstance(item, dict):
        return None
    unsupported = [f"{template_name}:{key}" for key in _UNSUPPORTED_HTTP_KEYS if key in item]
    raw_matchers = item.get("matchers") or []
    raw_extractors = item.get("extractors") or []
    matchers = _parse_matchers(raw_matchers)
    extractors = _parse_extractors(raw_extractors)
    if isinstance(raw_matchers, list):
        for matcher in raw_matchers:
            if isinstance(matcher, dict):
                matcher_type = str(matcher.get("type", "")).lower()
                if matcher_type and matcher_type not in _SUPPORTED_MATCHERS:
                    unsupported.append(f"{template_name}:matcher:{matcher_type}")
    if isinstance(raw_extractors, list):
        for extractor in raw_extractors:
            if isinstance(extractor, dict):
                extractor_type = str(extractor.get("type", "")).lower()
                if extractor_type and extractor_type not in _SUPPORTED_EXTRACTORS:
                    unsupported.append(f"{template_name}:extractor:{extractor_type}")
    method = str(item.get("method", "GET")).upper()
    paths = [str(value) for value in (item.get("path") or [])] if isinstance(item.get("path"), list) else ([str(item.get("path"))] if item.get("path") else [])
    raw = [str(value) for value in (item.get("raw") or [])] if isinstance(item.get("raw"), list) else ([str(item.get("raw"))] if item.get("raw") else [])
    headers = {str(key): str(value) for key, value in (item.get("headers") or {}).items()} if isinstance(item.get("headers"), dict) else {}
    body = str(item.get("body", "") or "")
    if not paths and not raw:
        return None
    return NucleiRequest(
        method=method,
        paths=paths,
        raw=raw,
        headers=headers,
        body=body,
        matchers=matchers,
        matchers_condition=str(item.get("matchers-condition", "or")).lower(),
        extractors=extractors,
        unsupported_features=unsupported,
    )


def _parse_matchers(items: Any) -> list[NucleiMatcher]:
    matchers: list[NucleiMatcher] = []
    if not isinstance(items, list):
        return matchers
    for item in items:
        if not isinstance(item, dict):
            continue
        matcher_type = str(item.get("type", "")).lower()
        if matcher_type not in _SUPPORTED_MATCHERS:
            continue
        matchers.append(NucleiMatcher(
            type=matcher_type,
            part=str(item.get("part", "body")).lower(),
            negative=bool(item.get("negative", False)),
            condition=str(item.get("condition", "or")).lower(),
            words=[str(value) for value in item.get("words", [])] if isinstance(item.get("words"), list) else [],
            regex=[str(value) for value in item.get("regex", [])] if isinstance(item.get("regex"), list) else [],
            binary=[str(value) for value in item.get("binary", [])] if isinstance(item.get("binary"), list) else [],
            status=[int(value) for value in item.get("status", [])] if isinstance(item.get("status"), list) else [],
            size=[int(value) for value in item.get("size", [])] if isinstance(item.get("size"), list) else [],
        ))
    return matchers


def _parse_extractors(items: Any) -> list[NucleiExtractor]:
    extractors: list[NucleiExtractor] = []
    if not isinstance(items, list):
        return extractors
    for item in items:
        if not isinstance(item, dict):
            continue
        extractor_type = str(item.get("type", "")).lower()
        if extractor_type not in _SUPPORTED_EXTRACTORS:
            continue
        extractors.append(NucleiExtractor(
            type=extractor_type,
            name=str(item.get("name", "")),
            part=str(item.get("part", "body")).lower(),
            regex=[str(value) for value in item.get("regex", [])] if isinstance(item.get("regex"), list) else [],
            kval=[str(value) for value in item.get("kval", [])] if isinstance(item.get("kval"), list) else [],
            json_paths=[str(value) for value in item.get("json", [])] if isinstance(item.get("json"), list) else ([str(item.get("json"))] if item.get("json") else []),
            group=int(item.get("group", 0) or 0),
        ))
    return extractors


def _iter_request_variants(request: NucleiRequest, context: dict[str, str]) -> list[tuple[str, str, dict[str, str], str]]:
    variants: list[tuple[str, str, dict[str, str], str]] = []
    for path in request.paths:
        url = _render_string(path, context)
        headers = {key: _render_string(value, context) for key, value in request.headers.items()}
        body = _render_string(request.body, context)
        variants.append((request.method, url, headers, body))
    for raw in request.raw:
        parsed = _parse_raw_request(_render_string(raw, context), context)
        if parsed:
            variants.append(parsed)
    return variants


def _parse_raw_request(raw: str, context: dict[str, str]) -> tuple[str, str, dict[str, str], str] | None:
    normalized = raw.replace("\r\n", "\n")
    header_text, _, body = normalized.partition("\n\n")
    lines = [line.rstrip("\r") for line in header_text.splitlines() if line.strip()]
    if not lines:
        return None
    method, path, *_rest = lines[0].split()
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    host = headers.get("Host", context["Hostname"])
    if path.startswith(("http://", "https://")):
        url = path
    else:
        scheme = context["Scheme"]
        url = f"{scheme}://{host}{path}"
    return method.upper(), url, headers, body


def _match_request(request: NucleiRequest, response: TemplateResponse) -> bool:
    if not request.matchers:
        return False
    results = [_evaluate_matcher(matcher, response) for matcher in request.matchers]
    if request.matchers_condition == "and":
        return all(results)
    return any(results)


def _evaluate_matcher(matcher: NucleiMatcher, response: TemplateResponse) -> bool:
    matched = False
    haystack = _response_part(response, matcher.part)
    if matcher.type == "status":
        matched = response.status in matcher.status
    elif matcher.type == "size":
        matched = len(response.body) in matcher.size
    elif matcher.type == "word":
        checks = [word in haystack for word in matcher.words]
        matched = all(checks) if matcher.condition == "and" else any(checks)
    elif matcher.type == "regex":
        checks = [re.search(pattern, haystack, re.IGNORECASE | re.DOTALL) is not None for pattern in matcher.regex]
        matched = all(checks) if matcher.condition == "and" else any(checks)
    elif matcher.type == "binary":
        checks = [bytes.fromhex(item) in response.body for item in matcher.binary]
        matched = all(checks) if matcher.condition == "and" else any(checks)
    return not matched if matcher.negative else matched


def _extract_values(request: NucleiRequest, response: TemplateResponse) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for extractor in request.extractors:
        for value in _run_extractor(extractor, response):
            if value and value not in seen:
                seen.add(value)
                values.append(value)
    return values


def _run_extractor(extractor: NucleiExtractor, response: TemplateResponse) -> list[str]:
    if extractor.type == "regex":
        text = _response_part(response, extractor.part)
        output: list[str] = []
        for pattern in extractor.regex:
            for match in re.finditer(pattern, text, re.IGNORECASE | re.DOTALL):
                if extractor.group > 0 and match.lastindex and extractor.group <= match.lastindex:
                    output.append(match.group(extractor.group))
                elif match.lastindex:
                    output.extend(group for group in match.groups() if group)
                else:
                    output.append(match.group(0))
        return output
    if extractor.type == "kval":
        headers = response.headers_lower
        return [headers.get(key.lower().replace("_", "-"), "") for key in extractor.kval if headers.get(key.lower().replace("_", "-"))]
    if extractor.type == "json":
        try:
            parsed = json.loads(response.body_text)
        except Exception:
            return []
        values: list[str] = []
        for path in extractor.json_paths:
            resolved = _json_path_lookup(parsed, path)
            if resolved is None:
                continue
            if isinstance(resolved, list):
                values.extend(str(item) for item in resolved)
            else:
                values.append(str(resolved))
        return values
    return []


def _json_path_lookup(document: Any, path: str) -> Any:
    cleaned = path.strip()
    if not cleaned or "|" in cleaned or "(" in cleaned:
        return None
    cleaned = cleaned.lstrip(".")
    current = document
    for token in re.split(r"\.(?![^\[]*\])", cleaned):
        if not token:
            continue
        match = re.fullmatch(r"([A-Za-z0-9_-]+)(?:\[(\d+)\])?", token)
        if not match:
            return None
        key = match.group(1)
        index = match.group(2)
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
        if index is not None:
            if not isinstance(current, list):
                return None
            idx = int(index)
            if idx >= len(current):
                return None
            current = current[idx]
    return current


def _response_part(response: TemplateResponse, part: str) -> str:
    if part == "header":
        return response.header_text
    if part == "all" or part == "raw":
        return response.all_text
    return response.body_text


def _render_context(base_url: str) -> dict[str, str]:
    parsed = urlsplit(base_url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return {
        "BaseURL": base_url.rstrip("/"),
        "RootURL": base_url.rstrip("/"),
        "Hostname": hostname,
        "Host": hostname,
        "Port": str(port),
        "Scheme": parsed.scheme,
    }


def _render_string(value: str, context: dict[str, str]) -> str:
    rendered = value
    for token in _STATIC_TEMPLATE_PATTERNS:
        rendered = rendered.replace(token, context[token.strip("{}")])
    if rendered.startswith("/"):
        return urljoin(context["BaseURL"] + "/", rendered.lstrip("/"))
    return rendered


def _template_record(
    template: NucleiTemplate,
    request: NucleiRequest,
    target: dict[str, Any],
    response: TemplateResponse,
    extracted: list[str],
) -> dict[str, Any]:
    classification = dict(template.classification)
    cve_id = classification.get("cve-id")
    if isinstance(cve_id, str):
        classification["cve-id"] = [cve_id]
    return {
        "template-id": template.template_id,
        "template-path": template.path,
        "info": {
            "name": template.name,
            "severity": _SEVERITY_MAP.get(template.severity.lower(), "info"),
            "description": template.description,
            "reference": template.references,
            "classification": classification,
            "tags": template.tags,
        },
        "type": "http",
        "host": f"{target.get('host', '')}:{target.get('port', '')}",
        "port": str(target.get("port", "")),
        "matched-at": response.url,
        "extracted-results": extracted,
        "curl-command": f"curl -X {request.method} {response.url}",
    }


def _target_base_url(target: dict[str, Any]) -> str:
    port = int(target.get("port") or 80)
    service = str(target.get("service", "")).lower()
    protocol = str(target.get("protocol", "tcp")).lower()
    tls = port in {443, 8443, 9443, 4443, 10443} or "https" in service or protocol == "ssl"
    scheme = "https" if tls else "http"
    host = str(target.get("host", ""))
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _dedup_findings(findings: list[Finding]) -> list[Finding]:
    deduped: list[Finding] = []
    seen: set[tuple[str, str, int | None, str]] = set()
    for finding in findings:
        matched_at = ""
        if finding.evidence and isinstance(finding.evidence[0].data, dict):
            matched_at = str(finding.evidence[0].data.get("matched_at", ""))
        key = (finding.title, finding.asset, finding.port, matched_at)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _record_skips(config: dict[str, Any], result: NativeNucleiRunResult) -> None:
    bucket = config.setdefault("_native_nuclei", {})
    if isinstance(bucket, dict):
        bucket["skipped_features"] = list(result.skipped_features)
        bucket["skipped_templates"] = list(result.skipped_templates)
        bucket["templates_per_s"] = round(result.templates_per_s, 2)
        bucket["loaded_templates"] = result.loaded_templates
        bucket["attempted_requests"] = result.attempted_requests
        bucket["matched_requests"] = result.matched_requests


async def run_native_nuclei_async(
    client: PoliteHttpClient,
    target: dict[str, Any],
    config: dict[str, Any],
) -> NativeNucleiRunResult:
    engine = NativeNucleiEngine(
        client,
        concurrency=int(((config.get("web_template_engine") or {}) if isinstance(config.get("web_template_engine"), dict) else {}).get("concurrency", 10)),
        timeout=float(((config.get("web_template_engine") or {}) if isinstance(config.get("web_template_engine"), dict) else {}).get("timeout", 8.0)),
    )
    return await engine.run(target=target, config=config)
