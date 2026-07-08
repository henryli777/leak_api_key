from __future__ import annotations

import base64
import os
import re
import time
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
        stats = SourceStats(source="github")
        if not self.token:
            stats.skipped = True
            stats.message = "GITHUB_TOKEN not configured; skip GitHub API search"
            return [], stats

        hits: list[SearchHit] = []
        for query in queries:
            stats.queries += 1
            hits.extend(self._search_code(query, stats))
            time.sleep(self.delay_seconds)
            hits.extend(self._search_issues(query, stats))
            time.sleep(self.delay_seconds)
        stats.hits = len(hits)
        return hits, stats

    def _search_code(self, query: str, stats: SourceStats) -> list[SearchHit]:
        params = {"q": query, "sort": "indexed", "order": "desc", "per_page": self.per_query}
        try:
            resp = self.session.get("https://api.github.com/search/code", params=params, timeout=20)
            if resp.status_code in (401, 403, 422):
                stats.errors += 1
                stats.message = f"GitHub code search HTTP {resp.status_code}: {resp.text[:160]}"
                return []
            resp.raise_for_status()
            items = resp.json().get("items") or []
        except Exception as exc:
            stats.errors += 1
            stats.message = f"GitHub code search failed: {exc}"
            return []

        hits: list[SearchHit] = []
        for item in items[: self.per_query]:
            content = self._fetch_code_content(item.get("url") or "")
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
            time.sleep(max(0.2, self.delay_seconds / 2))
        return hits

    def _fetch_code_content(self, api_url: str) -> str:
        if not api_url:
            return ""
        try:
            resp = self.session.get(api_url, timeout=20)
            if resp.status_code != 200:
                return ""
            data = resp.json()
            if data.get("encoding") == "base64" and data.get("content"):
                raw = base64.b64decode(data["content"], validate=False)
                return raw[:120_000].decode("utf-8", errors="ignore")
        except Exception:
            return ""
        return ""

    def _search_issues(self, query: str, stats: SourceStats) -> list[SearchHit]:
        params = {"q": query, "sort": "updated", "order": "desc", "per_page": self.per_query}
        try:
            resp = self.session.get("https://api.github.com/search/issues", params=params, timeout=20)
            if resp.status_code in (401, 403, 422):
                stats.errors += 1
                stats.message = f"GitHub issue search HTTP {resp.status_code}: {resp.text[:160]}"
                return []
            resp.raise_for_status()
            items = resp.json().get("items") or []
        except Exception as exc:
            stats.errors += 1
            stats.message = f"GitHub issue search failed: {exc}"
            return []

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
        return hits


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
        stats = SourceStats(source="google_serpapi")
        if not self.api_keys:
            stats.skipped = True
            stats.message = "SERPAPI_KEY or SERPAPI_KEYS not configured; skip Google search"
            return [], stats

        hits: list[SearchHit] = []
        for query in queries:
            stats.queries += 1
            key = self._next_key()
            params = {
                "engine": "google",
                "q": query,
                "num": self.per_query,
                "hl": "zh-cn",
                "gl": "us",
                "api_key": key,
            }
            try:
                resp = self.session.get("https://serpapi.com/search.json", params=params, timeout=30)
                if resp.status_code in (401, 403, 429):
                    stats.errors += 1
                    stats.message = f"SerpAPI HTTP {resp.status_code}: {resp.text[:160]}"
                    continue
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                stats.errors += 1
                stats.message = f"SerpAPI search failed: {exc}"
                continue

            for item in (data.get("organic_results") or [])[: self.per_query]:
                link = item.get("link") or ""
                raw_link = github_raw_content_url(link)
                content = ""
                if raw_link:
                    content = self._fetch_page(raw_link)
                elif self.fetch_pages:
                    content = self._fetch_page(link)
                hits.append(
                    SearchHit(
                        source="google_serpapi",
                        query=query,
                        url=link,
                        title=item.get("title") or "",
                        snippet=item.get("snippet") or "",
                        content=content,
                        fetched_at=utc_now(self.timezone_name),
                        metadata={"position": item.get("position"), "displayed_link": item.get("displayed_link")},
                    )
                )
            time.sleep(self.delay_seconds)
        stats.hits = len(hits)
        return hits, stats

    def _next_key(self) -> str:
        key = self.api_keys[self.key_index % len(self.api_keys)]
        self.key_index += 1
        return key

    def _fetch_page(self, url: str) -> str:
        if not url or not url.startswith(("http://", "https://")):
            return ""
        try:
            resp = self.session.get(url, timeout=15)
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
        source_hits, source_stats = source.search(queries)
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
        source_hits, source_stats = source.search(queries)
        hits.extend(source_hits)
        stats.append(source_stats)

    return hits, stats


def utc_now(timezone_name: str = DEFAULT_TIMEZONE) -> str:
    return now_iso(timezone_name)


def github_search_url(query: str) -> str:
    return "https://github.com/search?q=" + quote_plus(query)
