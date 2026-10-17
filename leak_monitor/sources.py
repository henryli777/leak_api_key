from __future__ import annotations

import base64
import math
import os
import re
import time
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import Any, Iterable
from urllib.parse import quote_plus, urlparse

import requests

from .config import AppConfig
from .models import SearchHit, SourceStats
from .timeutils import DEFAULT_TIMEZONE, now_iso


DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

MAX_ATTEMPTS = 3
MAX_RETRY_DELAY_SECONDS = 30.0
MAX_RETRY_WAIT_SECONDS = 60.0
SOURCE_BUDGET_SECONDS = 600.0


def _retry_delay(headers: Any, attempt: int, *, rate_limited: bool) -> float:
    delays = [float(2 ** (attempt + 1))]
    retry_after = headers.get("Retry-After", "")
    try:
        seconds = float(retry_after)
    except (TypeError, ValueError):
        try:
            date = parsedate_to_datetime(retry_after)
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            seconds = date.timestamp() - time.time()
        except (TypeError, ValueError, OverflowError):
            seconds = 0.0
    if math.isfinite(seconds):
        delays.append(max(0.0, seconds))
    if rate_limited:
        try:
            reset_delay = float(headers.get("X-RateLimit-Reset", "")) - time.time()
            if math.isfinite(reset_delay):
                delays.append(max(0.0, reset_delay))
        except (TypeError, ValueError, OverflowError):
            pass
    return max(delays)


def _serpapi_quota_error(response: Any) -> bool:
    try:
        error = str(response.json().get("error") or "").lower()
    except (ValueError, AttributeError, TypeError):
        return False
    return any(phrase in error for phrase in ("run out of searches", "searches exhausted", "monthly limit")) or (
        "quota" in error and any(word in error for word in ("exceed", "exhaust", "limit"))
    )


class _SourceRequests:
    def __init__(self, session: requests.Session, stats: SourceStats, request_limit: int) -> None:
        self.session = session
        self.stats = stats
        self.request_limit = request_limit
        self.started = time.monotonic()
        self.stopped = False

    def stop(self, reason: str, status: int | None = None) -> None:
        self.stopped = True
        self.message(reason, status)

    def message(self, reason: str, status: int | None = None) -> None:
        suffix = f" HTTP {status}" if status is not None else ""
        self.stats.message = f"{self.stats.source}: {reason}{suffix}"

    def available(self) -> bool:
        if self.stopped:
            return False
        if time.monotonic() - self.started >= SOURCE_BUDGET_SECONDS:
            self.stop("source_time_budget")
        elif self.stats.requests >= self.request_limit:
            self.stop("source_request_budget")
        return not self.stopped

    def pace(self, seconds: float) -> None:
        if not self.available():
            return
        seconds = max(0.0, seconds)
        if seconds >= SOURCE_BUDGET_SECONDS - (time.monotonic() - self.started):
            self.stop("source_time_budget")
            return
        time.sleep(seconds)

    def get(self, url: str, *, timeout: float, serpapi: bool = False, **kwargs: Any) -> Any:
        for attempt in range(MAX_ATTEMPTS):
            if not self.available():
                return None
            self.stats.requests += 1
            if attempt:
                self.stats.retries += 1
            headers: Any = {}
            status = None
            retryable = False
            try:
                remaining = SOURCE_BUDGET_SECONDS - (time.monotonic() - self.started)
                response = self.session.get(url, timeout=min(timeout, remaining), **kwargs)
                status = response.status_code
                headers = response.headers
                quota = str(headers.get("X-RateLimit-Remaining", "")).strip() == "0"
                quota = quota or (serpapi and _serpapi_quota_error(response))
                if 200 <= status < 300:
                    if quota:
                        self.stop("quota_exhausted", status)
                    return response
                self.stats.errors += 1
                if status == 401:
                    self.stats.failed_requests += 1
                    self.stop("unauthorized", status)
                    return None
                if quota:
                    self.stats.failed_requests += 1
                    self.stop("quota_exhausted", status)
                    return None
                limited = status == 429 or (status == 403 and bool(headers.get("Retry-After")))
                retryable = limited or 500 <= status < 600
                reason = "rate_limited" if limited else "server_error" if retryable else "http_error"
                if status == 403 and not limited:
                    self.stats.failed_requests += 1
                    self.stop("permission_denied", status)
                    return None
            except (requests.Timeout, requests.ConnectionError) as exc:
                self.stats.errors += 1
                retryable = True
                reason = "timeout" if isinstance(exc, requests.Timeout) else "connection_error"
            except requests.RequestException:
                self.stats.errors += 1
                reason = "request_error"
            self.message(reason, status)
            if not retryable:
                self.stats.failed_requests += 1
                return None
            if attempt + 1 == MAX_ATTEMPTS:
                self.stats.failed_requests += 1
                self.stop("retry_exhausted_" + reason, status)
                return None
            delay = _retry_delay(headers, attempt, rate_limited=reason == "rate_limited")
            remaining = SOURCE_BUDGET_SECONDS - (time.monotonic() - self.started)
            if (delay > MAX_RETRY_DELAY_SECONDS or self.stats.retry_wait_seconds + delay > MAX_RETRY_WAIT_SECONDS or delay >= remaining):
                self.stats.failed_requests += 1
                self.stop("cooldown_deferred_" + reason, status)
                return None
            time.sleep(delay)
            self.stats.retry_wait_seconds += delay
        return None

    def json(self, url: str, *, timeout: float, serpapi: bool = False, **kwargs: Any) -> dict[str, Any] | None:
        response = self.get(url, timeout=timeout, serpapi=serpapi, **kwargs)
        if response is None:
            return None
        try:
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError
        except (ValueError, TypeError):
            self.stats.errors += 1
            self.stats.failed_requests += 1
            self.message("invalid_response")
            return None
        if serpapi and data.get("error"):
            self.stats.errors += 1
            self.stats.failed_requests += 1
            self.stop("quota_exhausted" if _serpapi_quota_error(response) else "provider_error", response.status_code)
            return None
        return data

    def search_complete(self, data: dict[str, Any]) -> bool:
        self.stats.successful_searches += 1
        if data.get("incomplete_results"):
            self.stats.errors += 1
            self.stats.failed_requests += 1
            self.message("incomplete_results")
            return False
        return True


def github_raw_content_url(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    if host in {"raw.githubusercontent.com", "gist.githubusercontent.com"}:
        return url
    if host != "github.com":
        return ""
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 5:
        return ""
    owner, repo, marker = parts[0], parts[1], parts[2]
    if marker not in {"blob", "raw"}:
        return ""
    ref = parts[3]
    file_path = "/".join(parts[4:])
    if not file_path:
        return ""
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{file_path}"


def should_fetch_google_result_body(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    if "/api/providers" in path:
        return True
    if path.endswith((".json", ".env", ".yaml", ".yml", ".toml")):
        return True
    return False


class GitHubSource:
    def __init__(self, token: str | None, per_query: int, delay_seconds: float, timezone_name: str = DEFAULT_TIMEZONE) -> None:
        self.token = token
        self.per_query = per_query
        self.delay_seconds = delay_seconds
        self.timezone_name = timezone_name
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "User-Agent": DEFAULT_UA,
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    def search(self, queries: Iterable[str]) -> tuple[list[SearchHit], SourceStats]:
        queries = list(queries)
        stats = SourceStats(source="github", planned_queries=len(queries))
        if not queries:
            return [], stats
        if not self.token:
            stats.skipped = True
            stats.deferred_queries = len(queries)
            stats.message = "GITHUB_TOKEN not configured; skip GitHub API search"
            return [], stats

        hits: list[SearchHit] = []
        requests = _SourceRequests(self.session, stats, len(queries) * (2 + max(0, self.per_query)) * MAX_ATTEMPTS)
        for query in queries:
            if not requests.available():
                break
            query_text = query_text_value(query)
            stats.queries += 1
            code_hits, code_ok = self._search_code(query_text, stats, requests)
            hits.extend(code_hits)
            requests.pace(self.delay_seconds)
            issue_hits, issues_ok = self._search_issues(query_text, stats, requests)
            hits.extend(issue_hits)
            if code_ok and issues_ok:
                stats.completed_queries += 1
            else:
                stats.failed_queries += 1
            requests.pace(self.delay_seconds)
        stats.hits = len(hits)
        stats.deferred_queries = len(queries) - stats.queries
        return hits, stats

    def _search_code(self, query: str, stats: SourceStats, requests: _SourceRequests) -> tuple[list[SearchHit], bool]:
        params = {"q": query, "sort": "indexed", "order": "desc", "per_page": self.per_query}
        data = requests.json("https://api.github.com/search/code", params=params, timeout=20)
        if data is None:
            return [], False
        items = data.get("items") or []
        complete = requests.search_complete(data)

        hits: list[SearchHit] = []
        for item in items[: self.per_query]:
            content = self._fetch_code_content(item.get("url") or "", requests)
            repo = (item.get("repository") or {}).get("full_name", "")
            path = item.get("path") or item.get("name") or ""
            title = f"{repo}/{path}".strip("/")
            hits.append(
                SearchHit(
                    source="github_code",
                    query=query,
                    url=item.get("html_url") or "",
                    title=title,
                    snippet=f"GitHub code result: {title}",
                    content=content,
                    fetched_at=utc_now(self.timezone_name),
                    metadata={"repo": repo, "path": path},
                )
            )
            requests.pace(max(0.2, self.delay_seconds / 2))
        return hits, complete

    def _fetch_code_content(self, api_url: str, requests: _SourceRequests) -> str:
        if not api_url:
            return ""
        try:
            data = requests.json(api_url, timeout=20)
            if data is None:
                return ""
            if data.get("encoding") == "base64" and data.get("content"):
                raw = base64.b64decode(data["content"], validate=False)
                return raw[:120_000].decode("utf-8", errors="ignore")
        except Exception:
            return ""
        return ""

    def _search_issues(self, query: str, stats: SourceStats, requests: _SourceRequests) -> tuple[list[SearchHit], bool]:
        params = {"q": query, "sort": "updated", "order": "desc", "per_page": self.per_query}
        data = requests.json("https://api.github.com/search/issues", params=params, timeout=20)
        if data is None:
            return [], False
        items = data.get("items") or []
        complete = requests.search_complete(data)

        hits: list[SearchHit] = []
        for item in items[: self.per_query]:
            hits.append(
                SearchHit(
                    source="github_issues",
                    query=query,
                    url=item.get("html_url") or "",
                    title=item.get("title") or "",
                    snippet=item.get("body") or "",
                    content="",
                    fetched_at=utc_now(self.timezone_name),
                    metadata={"state": item.get("state"), "updated_at": item.get("updated_at")},
                )
            )
        return hits, complete


class GoogleSerpApiSource:
    def __init__(
        self,
        api_keys: list[str],
        per_query: int,
        delay_seconds: float,
        fetch_pages: bool = False,
        timezone_name: str = DEFAULT_TIMEZONE,
    ) -> None:
        self.api_keys = api_keys
        self.per_query = per_query
        self.delay_seconds = delay_seconds
        self.fetch_pages = fetch_pages
        self.timezone_name = timezone_name
        self.key_index = 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_UA, "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"})

    def search(self, queries: Iterable[str]) -> tuple[list[SearchHit], SourceStats]:
        queries = list(queries)
        stats = SourceStats(source="google_serpapi", planned_queries=len(queries))
        if not queries:
            return [], stats
        if not self.api_keys:
            stats.skipped = True
            stats.deferred_queries = len(queries)
            stats.message = "SERPAPI_KEY or SERPAPI_KEYS not configured; skip Google search"
            return [], stats

        hits: list[SearchHit] = []
        requests = _SourceRequests(self.session, stats, len(queries) * (1 + max(0, self.per_query)) * MAX_ATTEMPTS)
        for query in queries:
            if not requests.available():
                break
            query_text = query_text_value(query)
            stats.queries += 1
            key = self._next_key()
            params = {
                "engine": "google",
                "q": query_text,
                "num": self.per_query,
                "hl": "zh-cn",
                "gl": "us",
                "api_key": key,
            }
            data = requests.json("https://serpapi.com/search.json", params=params, timeout=30, serpapi=True)
            if data is None:
                stats.failed_queries += 1
                requests.pace(self.delay_seconds)
                continue
            stats.successful_searches += 1
            stats.completed_queries += 1

            for item in (data.get("organic_results") or [])[: self.per_query]:
                link = item.get("link") or ""
                raw_link = github_raw_content_url(link)
                content = ""
                if raw_link:
                    content = self._fetch_page(raw_link, requests)
                elif self.fetch_pages or should_fetch_google_result_body(link):
                    content = self._fetch_page(link, requests)
                hits.append(
                    SearchHit(
                        source="google_serpapi",
                        query=query_text,
                        url=link,
                        title=item.get("title") or "",
                        snippet=item.get("snippet") or "",
                        content=content,
                        fetched_at=utc_now(self.timezone_name),
                        metadata={"position": item.get("position"), "displayed_link": item.get("displayed_link")},
                    )
                )
            requests.pace(self.delay_seconds)
        stats.hits = len(hits)
        stats.deferred_queries = len(queries) - stats.queries
        return hits, stats

    def _next_key(self) -> str:
        key = self.api_keys[self.key_index % len(self.api_keys)]
        self.key_index += 1
        return key

    def _fetch_page(self, url: str, requests: _SourceRequests) -> str:
        if not url or not url.startswith(("http://", "https://")):
            return ""
        try:
            resp = requests.get(url, timeout=15)
            if resp is None:
                return ""
            if "text/" not in resp.headers.get("Content-Type", "") and "json" not in resp.headers.get("Content-Type", ""):
                return ""
            return resp.text[:120_000]
        except Exception:
            return ""


def load_serpapi_keys() -> list[str]:
    keys: list[str] = []
    if os.getenv("SERPAPI_KEYS"):
        keys.extend(_split_secret_keys(os.getenv("SERPAPI_KEYS", "")))
    if os.getenv("SERPAPI_KEY"):
        keys.extend(_split_secret_keys(os.getenv("SERPAPI_KEY", "")))
    for idx in range(1, 11):
        if os.getenv(f"SERPAPI_KEY_{idx}"):
            keys.extend(_split_secret_keys(os.getenv(f"SERPAPI_KEY_{idx}", "")))
    return list(dict.fromkeys(k for k in keys if k))


def _split_secret_keys(value: str) -> list[str]:
    return [part.strip() for part in re.split(r"[\s,;]+", value or "") if part.strip()]


def run_sources(cfg: AppConfig, queries: list[str], requested_sources: set[str]) -> tuple[list[SearchHit], list[SourceStats]]:
    hits: list[SearchHit] = []
    stats: list[SourceStats] = []

    if "github" in requested_sources and cfg.github.enabled:
        source = GitHubSource(os.getenv("GITHUB_TOKEN"), cfg.github.per_query, cfg.github.delay_seconds, cfg.timezone)
        source_hits, source_stats = source.search(queries_for_source(queries, "github"))
        hits.extend(source_hits)
        stats.append(source_stats)

    if "google" in requested_sources and cfg.google.enabled:
        source = GoogleSerpApiSource(
            load_serpapi_keys(),
            cfg.google.per_query,
            cfg.google.delay_seconds,
            cfg.google.fetch_pages,
            cfg.timezone,
        )
        source_hits, source_stats = source.search(queries_for_source(queries, "google"))
        hits.extend(source_hits)
        stats.append(source_stats)

    return hits, stats


def query_text_value(query: Any) -> str:
    return str(getattr(query, "text", query))


def query_source_value(query: Any) -> str:
    return str(getattr(query, "source", "all"))


def queries_for_source(queries: Iterable[Any], source: str) -> list[Any]:
    out = []
    for query in queries:
        query_source = query_source_value(query)
        if query_source in {"all", source}:
            out.append(query)
    return out


def utc_now(timezone_name: str = DEFAULT_TIMEZONE) -> str:
    return now_iso(timezone_name)


def github_search_url(query: str) -> str:
    return "https://github.com/search?q=" + quote_plus(query)
