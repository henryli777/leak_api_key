from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PBKDF2_ITERATIONS = 250_000


def emit_private_report(output_dir: str | Path, findings: list[dict[str, Any]], health: dict[str, Any]) -> bool:
    password = os.getenv("PRIVATE_REPORT_PASSWORD", "").strip()
    if not password:
        return False

    user = os.getenv("PRIVATE_REPORT_USER", "admin").strip() or "admin"
    payload = {
        "health": health,
        "findings": findings,
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
    .error {{ color: #ba2525; min-height: 20px; }}
    .summary {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 18px; }}
    .metric {{ background: white; border: 1px solid #d9e2ec; border-radius: 6px; padding: 10px 12px; min-width: 140px; }}
    .metric strong {{ display: block; font-size: 22px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #d9e2ec; }}
    th, td {{ padding: 10px; border-bottom: 1px solid #e6edf3; vertical-align: top; text-align: left; }}
    th {{ background: #eef3f8; font-weight: 650; }}
    code {{ word-break: break-all; white-space: pre-wrap; }}
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
      <form id="loginForm">
        <label>账号<input id="user" autocomplete="username" required></label>
        <label>密码<input id="password" type="password" autocomplete="current-password" required></label>
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

    function render(payload) {{
      const health = payload.health || {{}};
      const findings = payload.findings || [];
      const rows = findings.map((item) => {{
        const source = (item.sources || [{{}}])[0];
        const value = item.raw_value || item.value_redacted || (item.raw_base_urls || []).join(", ");
        const models = (item.models || []).join(", ");
        return `<tr>
          <td>${{escapeHtml(item.severity)}}</td>
          <td>${{escapeHtml(item.type)}}</td>
          <td>${{escapeHtml(item.provider)}}</td>
          <td><code>${{escapeHtml(value)}}</code></td>
          <td>${{escapeHtml(models)}}</td>
          <td><a href="${{escapeHtml(source.url)}}">${{escapeHtml(source.title || source.url)}}</a><div class="excerpt">${{escapeHtml(source.excerpt || "")}}</div></td>
          <td>${{escapeHtml(item.last_seen_at || "")}}</td>
        </tr>`;
      }}).join("");
      document.getElementById("report").innerHTML = `
        <div class="summary">
          <div class="metric"><span>总线索</span><strong>${{escapeHtml(health.total_findings || 0)}}</strong></div>
          <div class="metric"><span>本轮明文线索</span><strong>${{escapeHtml(findings.length)}}</strong></div>
          <div class="metric"><span>生成时间</span><strong style="font-size:15px">${{escapeHtml(health.build_time_cn || health.build_time_utc || "")}}</strong></div>
        </div>
        <table>
          <thead><tr><th>级别</th><th>类型</th><th>平台</th><th>明文值</th><th>模型</th><th>来源</th><th>最后发现</th></tr></thead>
          <tbody>${{rows || '<tr><td colspan="7">暂无线索</td></tr>'}}</tbody>
        </table>`;
      document.getElementById("login").classList.add("hidden");
      document.getElementById("report").classList.remove("hidden");
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
        render(await decryptPayload(password));
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
