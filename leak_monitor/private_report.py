from __future__ import annotations

import base64
import csv
import io
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .csv_export import csv_safe
from .dedup import dedupe_findings_for_export


PBKDF2_ITERATIONS = 250_000

PRIVATE_CSV_FIELDS = [
    "id",
    "type",
    "provider",
    "provider_name",
    "endpoint_path",
    "severity",
    "value_kind",
    "api_key",
    "key_redacted",
    "key_sha256",
    "base_url",
    "base_url_redacted",
    "base_url_sha256",
    "base_url_source",
    "public_evidence_level",
    "models",
    "first_seen_at",
    "last_seen_at",
    "seen_count",
    "deduped_finding_count",
    "source",
    "source_url",
    "source_title",
    "query",
]


def emit_private_report(output_dir: str | Path, findings: list[dict[str, Any]], health: dict[str, Any]) -> bool:
    password = os.getenv("PRIVATE_REPORT_PASSWORD", "").strip()
    if not password:
        return False

    user = os.getenv("PRIVATE_REPORT_USER", "admin").strip() or "admin"
    payload = {
        "health": health,
        "findings": dedupe_findings_for_export(findings),
    }
    encrypted = encrypt_payload(payload, password)
    html = render_private_html(encrypted, user)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "private.html").write_text(html, encoding="utf-8")
    return True


def encrypt_payload(payload: dict[str, Any], password: str) -> dict[str, Any]:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        "kdf": "PBKDF2-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": _b64(salt),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }


def render_private_html(encrypted: dict[str, Any], user: str) -> str:
    blob = json.dumps(encrypted, separators=(",", ":"))
    user_json = json.dumps(user)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI 泄露线索明文页</title>
  <style>
    body {{ margin: 0; font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #1f2933; background: #f7f8fa; }}
    header {{ padding: 22px 26px; background: #102a43; color: white; }}
    h1 {{ margin: 0 0 6px; font-size: 22px; }}
    main {{ padding: 22px 26px; }}
    form {{ display: grid; gap: 10px; max-width: 360px; background: white; border: 1px solid #d9e2ec; border-radius: 6px; padding: 16px; }}
    label {{ display: grid; gap: 4px; color: #334e68; }}
    input {{ height: 36px; border: 1px solid #bcccdc; border-radius: 4px; padding: 0 10px; font: inherit; }}
    button {{ height: 38px; border: 0; border-radius: 4px; background: #0b63ce; color: white; font-weight: 650; cursor: pointer; }}
    .toolbar {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 18px; }}
    .toolbar button {{ width: auto; padding: 0 12px; }}
    .error {{ color: #ba2525; min-height: 20px; }}
    .summary {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 18px; }}
    .metric {{ background: white; border: 1px solid #d9e2ec; border-radius: 6px; padding: 10px 12px; min-width: 140px; }}
    .metric strong {{ display: block; font-size: 22px; }}
    .table-wrap {{ width: 100%; overflow-x: auto; border: 1px solid #d9e2ec; background: white; }}
    table {{ width: 2300px; table-layout: fixed; border-collapse: collapse; background: white; }}
    th, td {{ padding: 10px; border-bottom: 1px solid #e6edf3; vertical-align: top; text-align: left; }}
    th {{ background: #eef3f8; font-weight: 650; }}
    .col-level {{ width: 72px; }}
    .col-type {{ width: 140px; }}
    .col-provider {{ width: 170px; }}
    .col-key {{ width: 460px; }}
    .col-base-url {{ width: 620px; }}
    .col-models {{ width: 180px; }}
    .col-source {{ width: 480px; }}
    .col-time {{ width: 178px; }}
    .secret-block {{ display: block; max-width: 100%; overflow-x: auto; white-space: pre; overflow-wrap: normal; word-break: normal; background: #f8fafc; border: 1px solid #d9e2ec; border-radius: 4px; padding: 6px 8px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; line-height: 1.45; }}
    .url-cell .secret-block {{ max-height: 144px; }}
    a {{ color: #0b63ce; text-decoration: none; }}
    .excerpt {{ color: #52606d; margin-top: 6px; max-width: 680px; white-space: pre-wrap; }}
    .hidden {{ display: none; }}
  </style>
</head>
<body>
  <header>
    <h1>AI 泄露线索明文页</h1>
    <div>需要登录后本地解密查看</div>
  </header>
  <main>
    <section id="login">
      <form id="loginForm" method="post" action="private.html" autocomplete="on">
        <label>账号<input id="user" name="username" autocomplete="username" required></label>
        <label>密码<input id="password" name="password" type="password" autocomplete="current-password" required></label>
        <button type="submit">登录</button>
        <div id="error" class="error"></div>
      </form>
    </section>
    <section id="report" class="hidden"></section>
  </main>
  <script>
    const expectedUser = {user_json};
    const encryptedBlob = {blob};
    const decoder = new TextDecoder();
    let decryptedPayload = null;

    function b64ToBytes(value) {{
      const binary = atob(value);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes;
    }}

    async function deriveKey(password, salt, iterations) {{
      const material = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
      );
      return crypto.subtle.deriveKey(
        {{ name: "PBKDF2", salt, iterations, hash: "SHA-256" }},
        material,
        {{ name: "AES-GCM", length: 256 }},
        false,
        ["decrypt"]
      );
    }}

    async function decryptPayload(password) {{
      const salt = b64ToBytes(encryptedBlob.salt);
      const nonce = b64ToBytes(encryptedBlob.nonce);
      const ciphertext = b64ToBytes(encryptedBlob.ciphertext);
      const key = await deriveKey(password, salt, encryptedBlob.iterations);
      const plain = await crypto.subtle.decrypt({{ name: "AES-GCM", iv: nonce }}, key, ciphertext);
      return JSON.parse(decoder.decode(plain));
    }}

    function escapeHtml(value) {{
      return String(value ?? "").replace(/[&<>"']/g, (ch) => ({{ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }}[ch]));
    }}

    function codeBlock(value) {{
      const text = String(value ?? "");
      return text ? `<code class="secret-block">${{escapeHtml(text)}}</code>` : "";
    }}

    function csvCell(value) {{
      const text = String(value ?? "");
      const safe = /^[=+\\-@]/.test(text) ? "'" + text : text;
      return `"${{safe.replace(/"/g, '""')}}"`;
    }}

    function privateCsv(payload) {{
      const fields = {json.dumps(PRIVATE_CSV_FIELDS, ensure_ascii=False)};
      const rows = [fields.join(",")];
      for (const item of payload.findings || []) {{
        const source = (item.sources || [{{}}])[0];
        const row = {{
          id: item.id || "",
          type: item.type || "",
          provider: item.provider || "",
          provider_name: item.provider_name || "",
          endpoint_path: item.endpoint_path || "",
          severity: item.severity || "",
          value_kind: item.value_kind || "",
          api_key: item.type === "base_url" ? "" : (item.raw_value || ""),
          key_redacted: item.key_redacted || item.value_redacted || "",
          key_sha256: item.key_sha256 || item.value_sha256 || "",
          base_url: (item.raw_base_urls || []).join("\\n") || item.raw_base_url || "",
          base_url_redacted: (item.base_urls_redacted || []).join("\\n") || item.base_url_redacted || "",
          base_url_sha256: (item.base_url_sha256 || []).join(", "),
          base_url_source: item.base_url_source || "",
          public_evidence_level: item.public_evidence_level || "",
          models: (item.models || []).join(", "),
          first_seen_at: item.first_seen_at || "",
          last_seen_at: item.last_seen_at || "",
          seen_count: item.seen_count || "",
          deduped_finding_count: item.deduped_finding_count || 1,
          source: source.source || "",
          source_url: source.url || "",
          source_title: source.title || "",
          query: source.query || ""
        }};
        rows.push(fields.map((field) => csvCell(row[field])).join(","));
      }}
      return "\\ufeff" + rows.join("\\n") + "\\n";
    }}

    function downloadPrivateCsv() {{
      if (!decryptedPayload) return;
      const blob = new Blob([privateCsv(decryptedPayload)], {{ type: "text/csv;charset=utf-8" }});
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      link.href = url;
      link.download = `private-findings-${{stamp}}.csv`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    }}

    async function storeCredential(form) {{
      if (!("PasswordCredential" in window) || !navigator.credentials || !navigator.credentials.store) return;
      try {{
        await navigator.credentials.store(new PasswordCredential(form));
      }} catch (err) {{
        // Browser declined or policy disabled credential storage.
      }}
    }}

    function render(payload) {{
      decryptedPayload = payload;
      const health = payload.health || {{}};
      const findings = payload.findings || [];
      const rows = findings.map((item) => {{
        const source = (item.sources || [{{}}])[0];
        const keyValue = item.type === "base_url" ? "" : (item.raw_value || item.key_redacted || item.value_redacted || "");
        const baseUrl = (item.raw_base_urls || []).join("\\n") || item.raw_base_url || (item.base_urls_redacted || []).join("\\n") || item.base_url_redacted || (item.type === "base_url" ? item.value_redacted : "");
        const pairSource = item.base_url_source === "same_hit" ? "同一线索发现" : (item.base_url_source === "historical_fallback" ? "历史 base_url 备选" : "");
        const evidence = item.public_evidence_label || "";
        const models = (item.models || []).join(", ");
        return `<tr>
          <td>${{escapeHtml(item.severity)}}</td>
          <td>${{escapeHtml(item.type)}}</td>
          <td>${{escapeHtml(item.provider)}}</td>
          <td class="secret-cell">${{codeBlock(keyValue)}}</td>
          <td class="url-cell">${{codeBlock(baseUrl)}}<div class="excerpt">${{escapeHtml(pairSource)}}</div><div class="excerpt">${{escapeHtml(evidence)}}</div></td>
          <td>${{escapeHtml(models)}}</td>
          <td><a href="${{escapeHtml(source.url)}}">${{escapeHtml(source.title || source.url)}}</a><div class="excerpt">${{escapeHtml(source.excerpt || "")}}</div></td>
          <td>${{escapeHtml(item.last_seen_at || "")}}</td>
        </tr>`;
      }}).join("");
      document.getElementById("report").innerHTML = `
        <div class="summary">
          <div class="metric"><span>总线索</span><strong>${{escapeHtml(health.total_findings || 0)}}</strong></div>
          <div class="metric"><span>去重明文线索</span><strong>${{escapeHtml(findings.length)}}</strong></div>
          <div class="metric"><span>生成时间</span><strong style="font-size:15px">${{escapeHtml(health.build_time_cn || health.build_time_utc || "")}}</strong></div>
        </div>
        <div class="toolbar">
          <button type="button" id="downloadPrivateCsv">下载明文CSV</button>
        </div>
        <div class="table-wrap">
          <table>
            <colgroup>
              <col class="col-level">
              <col class="col-type">
              <col class="col-provider">
              <col class="col-key">
              <col class="col-base-url">
              <col class="col-models">
              <col class="col-source">
              <col class="col-time">
            </colgroup>
            <thead><tr><th>级别</th><th>类型</th><th>平台</th><th>密钥</th><th>base_url</th><th>模型</th><th>来源</th><th>最后发现</th></tr></thead>
            <tbody>${{rows || '<tr><td colspan="8">暂无线索</td></tr>'}}</tbody>
          </table>
        </div>`;
      document.getElementById("login").classList.add("hidden");
      document.getElementById("report").classList.remove("hidden");
      document.getElementById("downloadPrivateCsv").addEventListener("click", downloadPrivateCsv);
    }}

    document.getElementById("loginForm").addEventListener("submit", async (event) => {{
      event.preventDefault();
      const user = document.getElementById("user").value.trim();
      const password = document.getElementById("password").value;
      const error = document.getElementById("error");
      error.textContent = "";
      if (user !== expectedUser) {{
        error.textContent = "账号或密码错误";
        return;
      }}
      try {{
        const payload = await decryptPayload(password);
        await storeCredential(event.target);
        render(payload);
      }} catch (err) {{
        error.textContent = "账号或密码错误";
      }}
    }});
  </script>
</body>
</html>
"""


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def build_private_csv_rows(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows = []
    for item in dedupe_findings_for_export(findings):
        source = (item.get("sources") or [{}])[0]
        row = {
            "id": item.get("id"),
            "type": item.get("type"),
            "provider": item.get("provider"),
            "provider_name": item.get("provider_name") or "",
            "endpoint_path": item.get("endpoint_path") or "",
            "severity": item.get("severity"),
            "value_kind": item.get("value_kind") or "",
            "api_key": "" if item.get("type") == "base_url" else item.get("raw_value") or "",
            "key_redacted": item.get("key_redacted") or item.get("value_redacted") or "",
            "key_sha256": item.get("key_sha256") or item.get("value_sha256") or "",
            "base_url": "\n".join(item.get("raw_base_urls") or []) or item.get("raw_base_url") or "",
            "base_url_redacted": "\n".join(item.get("base_urls_redacted") or []) or item.get("base_url_redacted") or "",
            "base_url_sha256": ", ".join(item.get("base_url_sha256") or []),
            "base_url_source": item.get("base_url_source") or "",
            "public_evidence_level": item.get("public_evidence_level") or "",
            "models": ", ".join(item.get("models") or []),
            "first_seen_at": item.get("first_seen_at") or "",
            "last_seen_at": item.get("last_seen_at") or "",
            "seen_count": item.get("seen_count") or "",
            "deduped_finding_count": item.get("deduped_finding_count") or 1,
            "source": source.get("source") or "",
            "source_url": source.get("url") or "",
            "source_title": source.get("title") or "",
            "query": source.get("query") or "",
        }
        rows.append({key: csv_safe(value) for key, value in row.items()})
    return rows


def render_private_csv(findings: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=PRIVATE_CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(build_private_csv_rows(findings))
    return "\ufeff" + buffer.getvalue()
