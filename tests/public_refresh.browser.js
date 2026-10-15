async (page) => {
  page.setDefaultTimeout(5000);
  page.setDefaultNavigationTimeout(5000);
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  const origin = "http://127.0.0.1:8766";
  const asset = await (await page.request.get(`${origin}/public-refresh.js`)).text();
  const fixture = (time, value, kind = "index") => `<!doctype html><html><head>
    <meta name="report-kind" content="${kind}"><meta name="report-snapshot" content="${time}"></head><body>
    <header><div data-refresh-region="timestamp">${time}</div><div id="refresh-status"></div></header>
    <main><input id="search" value=""><select id="filter"><option>all</option><option>high</option></select>
    <a id="download" href="findings.csv">Download</a><button id="action">Action</button>
    <div data-refresh-region="results"><span data-value="${value}">${value}</span></div></main></body></html>`;
  const t1 = "2026-10-08T21:25:26+08:00", t2 = "2026-10-15T08:00:00+08:00";
  for (const kind of ["index", "validation"]) {
    await page.route(`${origin}/fixture-${kind}.html`, route => route.fulfill({contentType: "text/html", body: fixture(t1, "old", kind)}));
    await page.goto(`${origin}/fixture-${kind}.html`);
    await page.evaluate(() => {
      window.refreshIntervals = [];
      window.setInterval = (fn, delay) => { window.refreshIntervals.push({fn, delay}); return 1; };
      window.requests = [];
      window.fetch = (url, options) => new Promise((resolve, reject) => { window.requests.push({url: String(url), options, resolve, reject}); });
      window.testVisibility = "visible";
      Object.defineProperty(document, "visibilityState", {get: () => window.testVisibility, configurable: true});
      window.actionCount = 0;
      document.getElementById("action").addEventListener("click", () => window.actionCount++);
      const filter = () => { document.querySelector("[data-value]").hidden = document.getElementById("search").value === "hide"; };
      document.getElementById("search").addEventListener("input", filter);
      document.addEventListener("report:updated", filter);
    });
    await page.addScriptTag({content: asset});
    assert(await page.evaluate(() => window.refreshIntervals[0].delay === 60000), "timer must check every 60 seconds");
    await page.evaluate(() => { window.dispatchEvent(new Event("focus")); window.refreshIntervals[0].fn(); });
    assert(await page.evaluate(() => window.requests.length === 1), "requests must not overlap");
    await page.locator("#search").fill("hide");
    await page.locator("#filter").selectOption("high");
    await page.evaluate(html => window.requests[0].resolve({ok: true, text: async () => html}), fixture(t2, "new", kind));
    await page.waitForFunction(() => document.querySelector('[name="report-snapshot"]').content.includes("2026-10-15"));
    assert(await page.locator("#search").inputValue() === "hide", "latest search edit must survive in-flight response");
    assert(await page.locator("#filter").inputValue() === "high", "filter must survive refresh");
    assert(await page.locator("[data-value]").isHidden(), "search handler must reapply to refreshed rows");
    await page.locator("#action").click();
    assert(await page.evaluate(() => window.actionCount === 1), "existing action handlers must survive refresh");
    assert(await page.locator("#download").getAttribute("href") === "findings.csv", "download remains functional");
    assert(await page.locator("#refresh-status").textContent().then(text => text.includes("检查成功")), "successful check status missing");
    assert(await page.evaluate(() => window.requests.every(request => new URL(request.url).origin === location.origin && request.options.cache === "no-store" && request.options.redirect === "error")), "refresh must stay same-origin and bypass cache");

    await page.evaluate(() => { window.testVisibility = "hidden"; document.dispatchEvent(new Event("visibilitychange")); window.refreshIntervals[0].fn(); window.dispatchEvent(new Event("focus")); });
    assert(await page.evaluate(() => window.requests.length === 1), "hidden page must not poll");
    await page.evaluate(() => { window.testVisibility = "visible"; document.dispatchEvent(new Event("visibilitychange")); });
    assert(await page.evaluate(() => window.requests.length === 2), "foreground must check immediately");
    await page.evaluate(() => window.requests[1].reject(new Error("synthetic network failure")));
    await page.waitForFunction(() => document.getElementById("refresh-status").textContent.includes("失败"));
    assert(await page.locator('[name="report-snapshot"]').getAttribute("content") === t2, "failed check must preserve original data timestamp");
    assert(await page.locator("#refresh-status").textContent().then(text => !text.includes("尚无")), "failure must preserve last successful check status");

    for (const timestamp of [t1, "not-a-timestamp"]) {
      await page.evaluate(() => { window.refreshIntervals[0].fn(); });
      await page.evaluate(html => window.requests.at(-1).resolve({ok: true, text: async () => html}), fixture(timestamp, "stale", kind));
      await page.waitForFunction(() => document.getElementById("refresh-status").textContent.includes("失败"));
      assert(await page.locator('[name="report-snapshot"]').getAttribute("content") === t2, "older or malformed response must not overwrite newer data");
    }
    await page.evaluate(() => { window.dispatchEvent(new Event("focus")); });
    await page.evaluate(() => { window.testVisibility = "hidden"; document.dispatchEvent(new Event("visibilitychange")); });
    assert(await page.evaluate(() => window.requests.at(-1).options.signal.aborted), "backgrounding must cancel in-flight request");
    await page.evaluate(html => window.requests.at(-1).resolve({ok: true, text: async () => html}), fixture("2026-10-16T08:00:00+08:00", "hidden response", kind));
    await page.waitForTimeout(20);
    assert(await page.locator('[name="report-snapshot"]').getAttribute("content") === t2, "cancelled response must never overwrite current state");
    await page.evaluate(() => { window.testVisibility = "visible"; document.dispatchEvent(new Event("visibilitychange")); });
    await page.evaluate(() => {
      window.testVisibility = "hidden";
      document.dispatchEvent(new Event("visibilitychange"));
      window.testVisibility = "visible";
      document.dispatchEvent(new Event("visibilitychange"));
      window.requests.at(-1).reject(new DOMException("synthetic abort", "AbortError"));
    });
    await page.waitForFunction(() => window.requests.length === 7);
    await page.evaluate(html => window.requests.at(-1).resolve({ok: true, text: async () => html}), fixture(t2, "unchanged", kind));
    await page.unroute(`${origin}/fixture-${kind}.html`);
  }
  return "Public refresh browser checks passed for index and validation";
}
