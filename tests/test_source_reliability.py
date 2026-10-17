import json
from datetime import datetime, timezone
from email.utils import format_datetime

import pytest
import requests

from leak_monitor.models import SourceStats
from leak_monitor.notify import notify_dingtalk
from leak_monitor.report import build_health, render_html
from leak_monitor.sources import GitHubSource, GoogleSerpApiSource


SECRET = "sk-synthetic_abcdefghijklmnopqrstuvwxyz1234567890"
SNAPSHOT = "2026-10-08T21:25:26+08:00"


class Clock:
    def __init__(self):
        self.elapsed = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.elapsed

    def time(self):
        return 1_800_000_000 + self.elapsed

    def sleep(self, seconds):
        assert seconds >= 0
        self.sleeps.append(seconds)
        self.elapsed += seconds


class Response:
    def __init__(self, status=200, data=None, headers=None):
        self.status_code = status
        self.data = {} if data is None else data
        self.headers = headers or {}
        self.text = f"response body {SECRET} https://example.invalid/?api_key={SECRET}"

    def json(self):
        if isinstance(self.data, Exception):
            raise self.data
        return self.data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(self.text)


class Session:
    def __init__(self, events, clock):
        self.events = iter(events)
        self.clock = clock
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs, self.clock.elapsed))
        event = next(self.events)
        if isinstance(event, Exception):
            raise event
        return event


@pytest.fixture
def clock(monkeypatch):
    clock = Clock()
    monkeypatch.setattr("leak_monitor.sources.time.sleep", clock.sleep)
    monkeypatch.setattr("leak_monitor.sources.time.monotonic", clock.monotonic)
    monkeypatch.setattr("leak_monitor.sources.time.time", clock.time)
    monkeypatch.setattr("leak_monitor.sources.utc_now", lambda *_: SNAPSHOT)
    return clock


def google(events, clock, keys=None):
    source = GoogleSerpApiSource(keys or ["synthetic-serp-key"], 2, 1)
    source.session = Session(events, clock)
    return source


def github(events, clock):
    source = GitHubSource("synthetic-github-token", 2, 1)
    source.session = Session(events, clock)
    return source


def test_timeout_and_server_error_recover_with_bounded_backoff(clock):
    source = google([
        requests.Timeout(f"timeout at ?api_key={SECRET}"),
        Response(503),
        Response(data={"organic_results": [{"link": "https://example.invalid/article", "title": "kept"}]}),
    ], clock)
    hits, stats = source.search(["original query"])
    assert [hit.title for hit in hits] == ["kept"]
    assert (stats.queries, stats.completed_queries, stats.failed_queries, stats.deferred_queries) == (1, 1, 0, 0)
    assert (stats.requests, stats.retries, stats.errors, stats.status) == (3, 2, 2, "complete")
    assert clock.sleeps == [2, 4, 1]
    assert [call[1]["params"]["q"] for call in source.session.calls] == ["original query"] * 3
    assert SECRET not in json.dumps(build_health([], [], [stats], 1, "Asia/Shanghai"))


@pytest.mark.parametrize("hint", ["seconds", "date", "reset"])
def test_github_honors_rate_limit_cooldown_before_retry(clock, hint):
    if hint == "seconds":
        headers = {"Retry-After": "6"}
    elif hint == "date":
        headers = {"Retry-After": format_datetime(datetime.fromtimestamp(clock.time() + 6, timezone.utc), usegmt=True)}
    else:
        headers = {"X-RateLimit-Reset": str(int(clock.time() + 6))}
    source = github([Response(429, headers=headers), Response(data={"items": []}), Response(data={"items": []})], clock)
    _, stats = source.search(["one"])
    assert source.session.calls[1][2] == 6
    assert (stats.queries, stats.completed_queries, stats.errors, stats.status) == (1, 1, 1, "complete")


def test_explicit_github_quota_stops_source_and_preserves_first_hit_time(clock):
    source = github([
        Response(data={"items": [{"html_url": "https://github.com/owner/repo/blob/main/a.txt", "url": "https://api.github.com/repos/owner/repo/contents/a.txt", "path": "a.txt"}]}),
        Response(429, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(clock.time() + 5))}),
    ], clock)
    hits, stats = source.search(["one", "two", "three"])
    assert len(hits) == 1 and hits[0].fetched_at == SNAPSHOT
    assert len(source.session.calls) == 2, "quota must stop issue search and later queries too"
    assert (stats.planned_queries, stats.queries, stats.completed_queries, stats.failed_queries, stats.deferred_queries) == (3, 1, 0, 1, 2)
    assert (stats.hits, stats.errors, stats.status) == (1, 1, "partial")
    assert "quota_exhausted" in stats.message


def test_serpapi_quota_does_not_switch_to_another_configured_key(clock):
    source = google([Response(429, headers={"X-RateLimit-Remaining": "0"})], clock, keys=["first-key", "second-key"])
    _, stats = source.search(["one", "two", "three"])
    assert len(source.session.calls) == 1
    assert source.session.calls[0][1]["params"]["api_key"] == "first-key"
    assert (stats.queries, stats.failed_queries, stats.deferred_queries, stats.status) == (1, 1, 2, "failed")


def test_serpapi_success_http_error_payload_is_not_a_successful_query(clock):
    source = google([Response(data={"error": f"Your account has run out of searches. {SECRET}"})], clock)
    _, stats = source.search(["one", "two"])
    assert len(source.session.calls) == 1
    assert (stats.errors, stats.completed_queries, stats.deferred_queries, stats.status) == (1, 0, 1, "failed")
    assert "quota_exhausted" in stats.message and SECRET not in stats.message


@pytest.mark.parametrize("headers", [
    {"Retry-After": "3600"},
    {"X-RateLimit-Reset": "1800003600"},
    {"Retry-After": "4", "X-RateLimit-Reset": "1800003600"},
])
def test_long_cooldown_defers_source_without_shortening_server_delay(clock, headers):
    source = google([Response(429, headers=headers)], clock)
    _, stats = source.search(["one", "two"])
    assert len(source.session.calls) == 1 and clock.sleeps == []
    assert (stats.requests, stats.retries, stats.errors, stats.deferred_queries) == (1, 0, 1, 1)
    assert "cooldown_deferred" in stats.message


@pytest.mark.parametrize("status", [401, 403])
def test_auth_and_permission_errors_stop_without_retry_or_leaking_response(clock, status):
    source = github([Response(status)], clock)
    _, stats = source.search([f"query-{SECRET}", "later"])
    health = build_health([], [], [stats], 2, "Asia/Shanghai")
    assert len(source.session.calls) == 1
    assert (stats.errors, stats.retries, stats.completed_queries, stats.deferred_queries, stats.status) == (1, 0, 0, 1, "failed")
    assert "quota" not in stats.message and str(status) in stats.message
    assert SECRET not in json.dumps(health) and SECRET not in render_html([], health)


def test_invalid_query_is_not_retried_and_failure_path_keeps_pacing(clock):
    source = google([Response(422), Response(data={"organic_results": []})], clock)
    _, stats = source.search(["invalid", "valid"])
    assert len(source.session.calls) == 2 and source.session.calls[1][2] == 1
    assert (stats.queries, stats.completed_queries, stats.failed_queries, stats.status) == (2, 1, 1, "partial")
    assert stats.retries == 0


def test_github_partial_logical_query_cannot_be_reported_complete(clock):
    source = github([Response(data={"items": []}), Response(422)], clock)
    _, stats = source.search(["one"])
    assert (stats.queries, stats.completed_queries, stats.failed_queries, stats.status) == (1, 0, 1, "partial")


def test_repeated_transient_failure_stops_after_three_requests(clock):
    source = google([requests.Timeout(SECRET)] * 3, clock)
    _, stats = source.search(["one", "two", "three"])
    assert len(source.session.calls) == 3 and sum(clock.sleeps) == 6
    assert (stats.errors, stats.retries, stats.failed_queries, stats.deferred_queries, stats.status) == (3, 2, 1, 2, "failed")
    assert SECRET not in stats.message


def test_total_retry_wait_budget_is_shared_across_queries(clock):
    events = []
    for _ in range(3):
        events.extend([Response(429, headers={"Retry-After": "30"}), Response(data={"organic_results": []})])
    source = google(events, clock)
    _, stats = source.search(["one", "two", "three", "four"])
    assert len(source.session.calls) == 5
    assert stats.retry_wait_seconds == 60
    assert (stats.queries, stats.completed_queries, stats.failed_queries, stats.deferred_queries, stats.status) == (3, 2, 1, 1, "partial")


def test_source_elapsed_budget_counts_normal_pacing_and_defers_unstarted_query(clock):
    source = google([Response(data={"organic_results": []})], clock)
    source.delay_seconds = 601
    _, stats = source.search(["one", "two"])
    assert len(source.session.calls) == 1
    assert clock.elapsed <= 600
    assert (stats.queries, stats.completed_queries, stats.failed_queries, stats.deferred_queries, stats.status) == (1, 1, 0, 1, "partial")


@pytest.mark.parametrize("source_name", ["github", "google"])
def test_empty_query_plan_is_distinct_from_failed_and_missing_credentials(clock, source_name):
    source = github([], clock) if source_name == "github" else google([], clock)
    _, stats = source.search([])
    assert stats.status == "no_queries" and stats.queries == 0 and stats.errors == 0
    if source_name == "github":
        source.token = None
    else:
        source.api_keys = []
    _, missing = source.search(["one"])
    assert missing.status == "skipped" and missing.deferred_queries == 1 and missing.errors == 0


def test_health_and_public_summary_expose_incomplete_collection_without_changing_snapshot(clock):
    source = google([Response(429, headers={"Retry-After": "3600"})], clock)
    _, stats = source.search(["one", "two"])
    health = build_health([], [], [stats], 2, "Asia/Shanghai")
    health["build_time"] = health["build_time_cn"] = SNAPSHOT
    public = render_html([], health)
    record = health["source_stats"][0]
    assert record["queries"] == record["attempted_queries"] == 1
    assert record["planned_queries"] == 2 and record["completed_queries"] == 0 and record["deferred_queries"] == 1
    assert record["status"] == "failed" and record["errors"] == 1
    assert 'data-refresh-region="collection-summary"' in public
    assert "采集失败" in public and "延后 1" in public
    assert SNAPSHOT in public
    legacy = render_html([], {"build_time": SNAPSHOT, "source_stats": [{"source": "github", "queries": 7, "hits": 0, "errors": 2, "message": SECRET}]})
    assert "完成情况未知" in legacy and "已尝试 7" in legacy
    assert "采集完成" not in legacy and SECRET not in legacy
    legacy_stats = build_health([], [], [SourceStats(source="github", queries=7)], 7, "Asia/Shanghai")
    assert legacy_stats["source_stats"][0]["status"] == "unknown"


def test_github_secondary_limit_retries_same_request_but_permission_failure_does_not(clock):
    source = github([Response(403, headers={"Retry-After": "3"}), Response(data={"items": []}), Response(data={"items": []})], clock)
    _, stats = source.search(["one"])
    assert [call[0] for call in source.session.calls] == ["https://api.github.com/search/code", "https://api.github.com/search/code", "https://api.github.com/search/issues"]
    assert source.session.calls[1][2] == 3 and stats.status == "complete"


@pytest.mark.parametrize("retry_after, expected_wait", [(None, 2), ("6", 6)])
def test_normal_github_quota_reset_header_does_not_defer_transient_server_error(clock, retry_after, expected_wait):
    headers = {"X-RateLimit-Remaining": "12", "X-RateLimit-Reset": str(int(clock.time() + 3600))}
    if retry_after:
        headers["Retry-After"] = retry_after
    source = github([Response(503, headers=headers), Response(data={"items": []}), Response(data={"items": []})], clock)
    _, stats = source.search(["one"])
    assert len(source.session.calls) == 3 and source.session.calls[1][2] == expected_wait
    assert stats.status == "complete" and stats.retries == 1


def test_unauthorized_response_cannot_be_misreported_as_quota(clock):
    source = google([Response(401, headers={"X-RateLimit-Remaining": "0"})], clock)
    _, stats = source.search(["one", "two"])
    assert len(source.session.calls) == 1 and "unauthorized" in stats.message
    assert "quota" not in stats.message


def test_serpapi_retries_use_same_key_and_do_not_expand_query_or_result_bound(clock):
    items = [{"link": f"https://example.invalid/article-{number}", "title": str(number)} for number in range(3)]
    source = google([Response(429, headers={"Retry-After": "2"}), Response(data={"organic_results": items})], clock, keys=["first-key", "second-key"])
    hits, stats = source.search(["bounded"])
    assert len(hits) == 2 and stats.queries == 1 and stats.completed_queries == 1
    assert [call[1]["params"]["api_key"] for call in source.session.calls] == ["first-key", "first-key"]
    assert [call[1]["params"]["num"] for call in source.session.calls] == [2, 2]


def test_github_incomplete_results_are_visible_as_partial_collection(clock):
    source = github([Response(data={"items": [], "incomplete_results": True}), Response(data={"items": []})], clock)
    _, stats = source.search(["one"])
    assert (stats.queries, stats.completed_queries, stats.failed_queries, stats.status) == (1, 0, 1, "partial")
    assert "incomplete_results" in stats.message


@pytest.mark.parametrize("data", [ValueError(SECRET), [SECRET]])
def test_malformed_response_is_sanitized_and_cannot_count_as_completed(clock, data):
    source = google([Response(data=data), Response(data={"organic_results": []})], clock)
    _, stats = source.search(["one", "two"])
    assert (stats.queries, stats.completed_queries, stats.failed_queries, stats.errors, stats.status) == (2, 1, 1, 1, "partial")
    assert SECRET not in stats.message


def test_network_time_consumes_source_budget_and_clips_next_timeout(clock):
    source = github([Response(data={"items": []}), Response(data={"items": []})], clock)
    original_get = source.session.get

    def slow_get(url, **kwargs):
        response = original_get(url, **kwargs)
        clock.elapsed += 590 if len(source.session.calls) == 1 else 10
        return response

    source.session.get = slow_get
    _, stats = source.search(["one", "two"])
    assert len(source.session.calls) == 2 and source.session.calls[1][1]["timeout"] == 9
    assert (stats.completed_queries, stats.deferred_queries, stats.status) == (1, 1, "partial")


def test_existing_notification_reports_sanitized_collection_counts(monkeypatch, clock):
    source = google([Response(429, headers={"Retry-After": "3600"})], clock)
    _, stats = source.search(["one", "two"])
    health = build_health([], [], [stats], 2, "Asia/Shanghai")
    health["source_stats"][0]["message"] = SECRET
    messages = []
    monkeypatch.setattr("leak_monitor.notify.dingtalk_webhook_from_env", lambda: "https://example.invalid/notify")

    def post(url, *, json, timeout):
        messages.append(json["text"]["content"])
        return Response()

    monkeypatch.setattr("leak_monitor.notify.requests.post", post)
    assert notify_dingtalk(health, [])
    assert "采集: 失败" in messages[0] and "失败查询: 1" in messages[0] and "延后查询: 1" in messages[0]
    assert SECRET not in messages[0]


def test_failed_run_with_historical_findings_labels_report_time_without_new_collection_claim(monkeypatch, clock):
    source = google([Response(401)], clock)
    _, stats = source.search(["one"])
    report_time = "2026-10-17T19:00:00+08:00"
    monkeypatch.setattr("leak_monitor.report.now_iso", lambda *_: report_time)
    finding = {"severity": "high", "type": "api_key", "provider": "example", "key_sha256": "historical-id", "key_redacted": "sk-abc***xyz", "first_seen_at": SNAPSHOT, "last_seen_at": SNAPSHOT}
    health = build_health([finding], [], [stats], 1, "Asia/Shanghai")
    page = render_html([finding], health)
    assert health["total_findings"] == 1 and health["collection_status"] == "failed"
    assert health["build_time"] == report_time and finding["last_seen_at"] == SNAPSHOT
    assert f"本轮检查时间: {report_time}" in page
    assert "数据采集时间" not in page and "采集失败" in page
    assert SNAPSHOT in page
