from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from typing import Any
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import requests

from .storage import severity_rank


def dingtalk_webhook_from_env() -> str:
    webhook = os.getenv("DINGTALK_WEBHOOK", "").strip()
    token = os.getenv("DINGTALK_TOKEN", "").strip()
    if not webhook and token:
        webhook = f"https://oapi.dingtalk.com/robot/send?access_token={token}"
    secret = os.getenv("DINGTALK_SECRET", "").strip()
    if webhook and secret:
        webhook = _sign_webhook(webhook, secret)
    return webhook


def _sign_webhook(webhook: str, secret: str) -> str:
    timestamp = str(round(time.time() * 1000))
    string_to_sign = f"{timestamp}\n{secret}".encode("utf-8")
    sign = base64.b64encode(hmac.new(secret.encode("utf-8"), string_to_sign, hashlib.sha256).digest()).decode("utf-8")
    parsed = urlparse(webhook)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["timestamp"] = timestamp
    query["sign"] = sign
    return urlunparse(parsed._replace(query=urlencode(query)))


def notify_dingtalk(health: dict[str, Any], new_findings: list[dict[str, Any]], min_severity: str = "medium") -> bool:
    webhook = dingtalk_webhook_from_env()
    if not webhook:
        return False

    threshold = severity_rank(min_severity)
    notable = [item for item in new_findings if severity_rank(item.get("severity")) >= threshold]
    lines = [
        "【AI密钥泄露监测】",
        f"时间: {health.get('build_time_cn') or health.get('build_time_utc')}",
        f"新增: {len(new_findings)}  需关注: {len(notable)}  总线索: {health.get('total_findings', 0)}",
        f"高危: {health.get('severity_counts', {}).get('high', 0)}  中危: {health.get('severity_counts', {}).get('medium', 0)}",
        f"来源命中: {health.get('source_hits', {})}",
        _collection_notice(health),
    ]
    if notable:
        lines.append("新增重点:")
        for item in notable[:8]:
            source = (item.get("sources") or [{}])[0]
            title = (source.get("title") or source.get("url") or "")[:80]
            key_value = item.get("key_redacted") or (item.get("value_redacted") if item.get("type") != "base_url" else "")
            base_url = item.get("base_url_redacted") or ",".join(item.get("base_urls_redacted") or [])
            value = f"key={key_value or '-'} base_url={base_url or '-'}"
            lines.append(f"- {item.get('severity')} {item.get('type')} {item.get('provider')}: {value} | {title}")
    else:
        lines.append("本轮没有达到通知阈值的新线索。")

    payload = {"msgtype": "text", "text": {"content": "\n".join(lines)}}
    try:
        resp = requests.post(webhook, json=payload, timeout=15)
        return resp.status_code < 300
    except Exception:
        return False


def _collection_notice(health: dict[str, Any]) -> str:
    labels = {"complete": "完成", "partial": "部分完成", "failed": "失败", "no_queries": "无计划查询", "skipped": "已跳过"}
    status = labels.get(str(health.get("collection_status")), "完成情况未知")
    stats = health.get("source_stats") or []

    def count(field: str) -> str:
        if not stats or any(not isinstance(item.get(field), int) for item in stats):
            return "未知"
        return str(sum(item[field] for item in stats))

    return f"采集: {status}  失败查询: {count('failed_queries')}  延后查询: {count('deferred_queries')}"
