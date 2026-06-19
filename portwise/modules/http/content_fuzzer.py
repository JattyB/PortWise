from __future__ import annotations

import asyncio
import hashlib
import random
import re
import string
import time
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from importlib import resources
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin, urlsplit

from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.modules.http.content_discovery import _content_verdict
from portwise.modules.http.surface import DiscoveredSurface, normalize_url, strip_query
from portwise.utils.http_client import PoliteHttpClient

DEFAULT_REPORT_STATUSES = {200, 204, 301, 302, 307, 308, 401, 403}
DEFAULT_RECURSE_STATUSES = {200, 301, 302, 307, 308, 401, 403}


@dataclass(frozen=True, slots=True)
class ResponseSignature:
    status: int
    size: int
    words: int
    lines: int
    digest: str
    sample: str


@dataclass(frozen=True, slots=True)
class Soft404Baseline:
    url: str
    signature: ResponseSignature


@dataclass(frozen=True, slots=True)
class FuzzHit:
    url: str
    path: str
    status: int
    size: int
    words: int
    lines: int
    reason: str
    depth: int = 0


@dataclass(slots=True)
class ContentFuzzResult:
    base_url: str
    hits: list[FuzzHit] = field(default_factory=list)
    baselines: list[Soft404Baseline] = field(default_factory=list)
    tested: int = 0
    filtered_soft404: int = 0
    filtered_known: int = 0
    filtered_rules: int = 0
    elapsed_s: float = 0.0

    @property
    def req_s(self) -> float:
        return self.tested / self.elapsed_s if self.elapsed_s > 0 else 0.0


@dataclass(slots=True)
class FuzzFilters:
    status_allow: set[int] = field(default_factory=lambda: set(DEFAULT_REPORT_STATUSES))
    status_deny: set[int] = field(default_factory=set)
    size_allow: set[int] = field(default_factory=set)
    size_deny: set[int] = field(default_factory=set)
    words_allow: set[int] = field(default_factory=set)
    words_deny: set[int] = field(default_factory=set)
    lines_allow: set[int] = field(default_factory=set)
    lines_deny: set[int] = field(default_factory=set)
    regex_include: re.Pattern[str] | None = None
    regex_exclude: re.Pattern[str] | None = None

    @classmethod
    def from_config(cls, data: dict[str, Any]) -> FuzzFilters:
        return cls(
            status_allow=_int_set(data.get("status_allow", data.get("match_status", DEFAULT_REPORT_STATUSES))),
            status_deny=_int_set(data.get("status_deny", data.get("filter_status", []))),
            size_allow=_int_set(data.get("size_allow", data.get("match_size", []))),
            size_deny=_int_set(data.get("size_deny", data.get("filter_size", []))),
            words_allow=_int_set(data.get("words_allow", data.get("match_words", []))),
            words_deny=_int_set(data.get("words_deny", data.get("filter_words", []))),
            lines_allow=_int_set(data.get("lines_allow", data.get("match_lines", []))),
            lines_deny=_int_set(data.get("lines_deny", data.get("filter_lines", []))),
            regex_include=_compile_optional(data.get("regex_include", data.get("match_regex"))),
            regex_exclude=_compile_optional(data.get("regex_exclude", data.get("filter_regex"))),
        )

    def allows(self, sig: ResponseSignature, body: str) -> bool:
        if self.status_allow and sig.status not in self.status_allow:
            return False
        if sig.status in self.status_deny:
            return False
        if self.size_allow and sig.size not in self.size_allow:
            return False
        if sig.size in self.size_deny:
            return False
        if self.words_allow and sig.words not in self.words_allow:
            return False
        if sig.words in self.words_deny:
            return False
        if self.lines_allow and sig.lines not in self.lines_allow:
            return False
        if sig.lines in self.lines_deny:
            return False
        if self.regex_include and not self.regex_include.search(body):
            return False
        if self.regex_exclude and self.regex_exclude.search(body):
            return False
        return True


class AsyncContentFuzzer:
    def __init__(
        self,
        client: PoliteHttpClient,
        timeout: float = 8.0,
        concurrency: int = 8,
        max_tests: int = 200,
        baseline_count: int = 3,
        body_limit: int = 120_000,
        filters: FuzzFilters | None = None,
        recurse: bool = False,
        max_depth: int = 1,
    ) -> None:
        self.client = client
        self.timeout = timeout
        self.concurrency = max(1, concurrency)
        self.max_tests = max_tests
        self.baseline_count = max(1, baseline_count)
        self.body_limit = body_limit
        self.filters = filters or FuzzFilters()
        self.recurse = recurse
        self.max_depth = max_depth

    async def fuzz(
        self,
        base_url: str,
        words: Iterable[str],
        surface: DiscoveredSurface | None = None,
    ) -> ContentFuzzResult:
        started = time.perf_counter()
        result = ContentFuzzResult(base_url=base_url.rstrip("/") + "/")
        result.baselines = await self._calibrate(result.base_url)
        words_list = list(words)
        known = set(surface.endpoints) if surface else set()
        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        seen_paths: set[str] = set()
        for word in words_list:
            path = _normalize_word(word)
            if path and path not in seen_paths:
                seen_paths.add(path)
                await queue.put((path, 0))

        semaphore = asyncio.Semaphore(self.concurrency)
        tested_lock = asyncio.Lock()

        async def worker() -> None:
            while True:
                try:
                    path, depth = await asyncio.wait_for(queue.get(), timeout=0.1)
                except asyncio.TimeoutError:
                    return
                try:
                    url = normalize_url(urljoin(result.base_url, path))
                    if url in known:
                        result.filtered_known += 1
                        continue
                    async with tested_lock:
                        if result.tested >= self.max_tests:
                            continue
                        result.tested += 1
                    try:
                        async with semaphore:
                            status, body = await self._fetch(url)
                    except Exception:
                        continue
                    sig = signature_for(status, body)
                    if not self.filters.allows(sig, body):
                        result.filtered_rules += 1
                        continue
                    if _matches_any_baseline(sig, body, result.baselines):
                        result.filtered_soft404 += 1
                        continue
                    verdict = _content_verdict("/" + path.lstrip("/"), _category_for_path(path), body)
                    if verdict == "drop":
                        result.filtered_rules += 1
                        continue
                    reason = _hit_reason(sig, result.baselines, verdict)
                    hit = FuzzHit(url=url, path="/" + path.lstrip("/"), status=sig.status, size=sig.size, words=sig.words, lines=sig.lines, reason=reason, depth=depth)
                    result.hits.append(hit)
                    if surface:
                        surface.add_url(url, "content-fuzzer", status=sig.status, depth=depth)
                    if self.recurse and depth < self.max_depth and _looks_directory(path, sig.status):
                        for word in words_list:
                            child = f"{path.rstrip('/')}/{_normalize_word(word)}"
                            if child not in seen_paths:
                                seen_paths.add(child)
                                await queue.put((child, depth + 1))
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
        await queue.join()
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        result.elapsed_s = time.perf_counter() - started
        return result

    async def _calibrate(self, base_url: str) -> list[Soft404Baseline]:
        baselines: list[Soft404Baseline] = []
        for _ in range(self.baseline_count):
            path = _random_baseline_path()
            url = normalize_url(urljoin(base_url, path))
            try:
                status, body = await self._fetch(url)
            except Exception:
                continue
            baselines.append(Soft404Baseline(url, signature_for(status, body)))
        return baselines

    async def _fetch(self, url: str) -> tuple[int, str]:
        response = await self.client.request_url_async(url, timeout=self.timeout, allow_redirects=False)
        body = response.read(self.body_limit).decode("utf-8", errors="replace")
        return response.status, body


def load_wordlist(config: dict[str, Any] | None = None) -> list[str]:
    data = config or {}
    path = data.get("wordlist_path") or data.get("wordlist")
    if path:
        return _read_wordlist(Path(str(path)))
    default = resources.files("portwise").joinpath("data", "wordlists", "content_fuzz_default.txt")
    return [
        line.strip()
        for line in default.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


async def run_content_fuzzer_async(
    *,
    base_url: str,
    client: PoliteHttpClient,
    target: dict[str, Any],
    config: dict[str, Any],
    surface: DiscoveredSurface,
    module: str = "http",
) -> list[Finding]:
    cfg = config.get("web_content_fuzzer", {}) if isinstance(config.get("web_content_fuzzer"), dict) else {}
    if not bool(cfg.get("enabled", True)):
        return []
    fuzzer = AsyncContentFuzzer(
        client=client,
        timeout=float(cfg.get("timeout", 8.0)),
        concurrency=int(cfg.get("concurrency", 8)),
        max_tests=int(cfg.get("max_tests", 200)),
        baseline_count=int(cfg.get("baseline_count", 3)),
        filters=FuzzFilters.from_config(cfg.get("filters", cfg)),
        recurse=bool(cfg.get("recurse", False)),
        max_depth=int(cfg.get("max_depth", 1)),
    )
    result = await fuzzer.fuzz(base_url, load_wordlist(cfg), surface)
    finding = content_fuzzer_finding(result, target, module=module)
    return [finding] if finding else []


def content_fuzzer_finding(result: ContentFuzzResult, target: dict[str, Any], module: str = "http") -> Finding | None:
    if not result.hits:
        return None
    evidence = Evidence(
        f"module:{module}:content-fuzzer",
        "Wordlist-driven content fuzzing found responses that diverged from calibrated soft-404 baselines.",
        4,
        {
            "base_url": result.base_url,
            "hits": [_hit_evidence(hit) for hit in result.hits[:100]],
            "soft404_baselines": [_baseline_evidence(item) for item in result.baselines],
            "tested": result.tested,
            "filtered_soft404": result.filtered_soft404,
            "filtered_known": result.filtered_known,
            "filtered_rules": result.filtered_rules,
            "req_s": round(result.req_s, 2),
        },
    )
    return Finding(
        title="Content Fuzzer Discovered Additional Paths",
        severity=Severity.INFO,
        asset=str(target.get("host", "")),
        port=target.get("port"),
        protocol=str(target.get("protocol", "tcp")),
        service=str(target.get("service", "http")),
        description=f"Found {len(result.hits)} content path(s) after soft-404 calibration and response filtering.",
        recommendation="Review discovered paths for authentication, sensitive data exposure, and follow-on template checks.",
        confidence=Confidence.CONFIRMED,
        evidence_strength=4,
        type="Information",
        module=module,
        false_positive_risk="low",
        evidence=[evidence],
        category=FindingCategory.INFORMATION,
        tags=["content-fuzzer", "url-discovery"],
    )


def signature_for(status: int, body: str) -> ResponseSignature:
    normalized = _normalize_body(body)
    return ResponseSignature(
        status=status,
        size=len(body.encode("utf-8", errors="replace")),
        words=len(re.findall(r"\S+", body)),
        lines=body.count("\n") + (1 if body else 0),
        digest=hashlib.sha256(normalized[:8192].encode("utf-8", errors="ignore")).hexdigest(),
        sample=normalized[:4096],
    )


def _matches_any_baseline(sig: ResponseSignature, body: str, baselines: list[Soft404Baseline]) -> bool:
    return any(_matches_baseline(sig, body, baseline.signature) for baseline in baselines)


def _matches_baseline(sig: ResponseSignature, body: str, baseline: ResponseSignature) -> bool:
    if sig.status != baseline.status:
        return False
    if sig.digest == baseline.digest:
        return True
    size_close = _close(sig.size, baseline.size, 0.08, 96)
    words_close = _close(sig.words, baseline.words, 0.10, 8)
    lines_close = _close(sig.lines, baseline.lines, 0.10, 4)
    if not (size_close and words_close and lines_close):
        return False
    normalized = _normalize_body(body)[:4096]
    similarity = SequenceMatcher(None, normalized, baseline.sample).ratio()
    return similarity >= 0.90


def _hit_reason(sig: ResponseSignature, baselines: list[Soft404Baseline], verdict: str) -> str:
    statuses = {baseline.signature.status for baseline in baselines}
    if sig.status not in statuses:
        return "status-divergence"
    if verdict == "confirmed":
        return "content-signature"
    return "body-shape-divergence"


def _baseline_evidence(baseline: Soft404Baseline) -> dict[str, Any]:
    sig = baseline.signature
    return {"url": baseline.url, "status": sig.status, "size": sig.size, "words": sig.words, "lines": sig.lines, "digest": sig.digest[:16]}


def _hit_evidence(hit: FuzzHit) -> dict[str, Any]:
    return {
        "url": hit.url,
        "path": hit.path,
        "status": hit.status,
        "size": hit.size,
        "words": hit.words,
        "lines": hit.lines,
        "reason": hit.reason,
        "depth": hit.depth,
    }


def _normalize_word(word: str) -> str:
    stripped = word.strip()
    if not stripped or stripped.startswith("#"):
        return ""
    return stripped.lstrip("/")


def _read_wordlist(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _random_baseline_path() -> str:
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
    return f"/portwise-fuzz-miss-{token}"


def _normalize_body(body: str) -> str:
    text = re.sub(r"portwise-fuzz-miss-[a-z0-9]+", "PORTWISE_RANDOM", body, flags=re.IGNORECASE)
    text = re.sub(r"pwx[a-f0-9]{8,16}", "PORTWISE_RANDOM", text, flags=re.IGNORECASE)
    text = re.sub(r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?", "TIMESTAMP", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()


def _category_for_path(path: str) -> str:
    lower = path.lower()
    if any(marker in lower for marker in (".git", ".svn", ".hg")):
        return "vcs"
    if any(lower.endswith(suffix) for suffix in (".zip", ".tar.gz", ".sql", ".bak", ".backup")):
        return "backup"
    if lower.endswith((".env", "web.config", "app.config")) or "config" in lower:
        return "config"
    if any(marker in lower for marker in ("admin", "login", "manager")):
        return "admin"
    return "info"


def _looks_directory(path: str, status: int) -> bool:
    return status in DEFAULT_RECURSE_STATUSES and path.endswith("/")


def _int_set(value: Any) -> set[int]:
    if value is None:
        return set()
    if isinstance(value, int):
        return {value}
    if isinstance(value, str):
        value = [part.strip() for part in value.split(",") if part.strip()]
    return {int(item) for item in value}


def _compile_optional(value: Any) -> re.Pattern[str] | None:
    if not value:
        return None
    return re.compile(str(value), re.IGNORECASE | re.DOTALL)


def _close(left: int, right: int, ratio: float, absolute: int) -> bool:
    return abs(left - right) <= max(absolute, int(max(left, right) * ratio))
