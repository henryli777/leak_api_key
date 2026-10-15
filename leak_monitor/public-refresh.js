(() => {
  "use strict";
  const snapshot = document.querySelector('meta[name="report-snapshot"]');
  const kind = document.querySelector('meta[name="report-kind"]');
  const status = document.getElementById("refresh-status");
  if (!snapshot || !kind || !status) return;

  let active = null;
  let foregroundPending = false;
  let lastSuccess = "";
  const visible = () => document.visibilityState === "visible";
  const controlKey = (element) => element.id || element.name;

  function apply(next) {
    const regions = [...document.querySelectorAll("[data-refresh-region]")];
    const updates = regions.map((region) => {
      const name = region.dataset.refreshRegion;
      const matches = [...next.querySelectorAll("[data-refresh-region]")].filter((item) => item.dataset.refreshRegion === name);
      if (matches.length !== 1) throw new Error("Incomplete report");
      return [region, matches[0]];
    });
    // Read controls at response time so edits made during a request survive.
    const controls = new Map([...document.querySelectorAll("input, select, textarea")]
      .filter(controlKey).map((element) => [controlKey(element), {value: element.value, checked: element.checked}]));
    for (const [region, source] of updates) {
      source.querySelectorAll("script").forEach((script) => script.remove());
      region.replaceChildren(...source.childNodes);
    }
    for (const element of document.querySelectorAll("input, select, textarea")) {
      const saved = controls.get(controlKey(element));
      if (!saved) continue;
      element.value = saved.value;
      if (typeof saved.checked === "boolean") element.checked = saved.checked;
      element.dispatchEvent(new Event("input", {bubbles: true}));
      element.dispatchEvent(new Event("change", {bubbles: true}));
    }
    document.dispatchEvent(new CustomEvent("report:updated"));
  }

  async function refresh() {
    if (!visible() || active) return;
    const controller = new AbortController();
    active = controller;
    const timeout = setTimeout(() => controller.abort(), 15000);
    try {
      const url = new URL(window.location.href);
      url.hash = "";
      url.searchParams.set("_snapshot", String(Date.now()));
      const response = await fetch(url, {cache: "no-store", credentials: "same-origin", redirect: "error", signal: controller.signal});
      if (!response.ok) throw new Error("Report unavailable");
      const text = await response.text();
      if (!visible() || controller.signal.aborted) return;
      const next = new DOMParser().parseFromString(text, "text/html");
      const nextKind = next.querySelector('meta[name="report-kind"]');
      const nextSnapshot = next.querySelector('meta[name="report-snapshot"]');
      if (nextKind?.content !== kind.content || !nextSnapshot) throw new Error("Invalid report");
      const nextTime = Date.parse(nextSnapshot.content);
      if (!Number.isFinite(nextTime) || nextTime < Date.parse(snapshot.content)) throw new Error("Invalid or older report");
      if (nextSnapshot.content !== snapshot.content) {
        apply(next);
        snapshot.content = nextSnapshot.content;
      }
      lastSuccess = new Date().toLocaleString();
      status.textContent = `检查成功: ${lastSuccess}`;
    } catch (error) {
      if (visible()) status.textContent = `更新检查失败，保留当前数据。上次检查成功: ${lastSuccess || "尚无"}`;
    } finally {
      clearTimeout(timeout);
      active = null;
      if (foregroundPending && visible()) {
        foregroundPending = false;
        queueMicrotask(refresh);
      }
    }
  }

  function foreground() {
    if (!visible()) return;
    if (active?.signal.aborted) foregroundPending = true;
    else refresh();
  }

  document.addEventListener("visibilitychange", () => {
    if (visible()) foreground();
    else active?.abort();
  });
  window.addEventListener("focus", foreground);
  setInterval(refresh, 60000);
  refresh();
})();
