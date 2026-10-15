from html.parser import HTMLParser

from leak_monitor.authorized_validator import render_validation_html
from leak_monitor.report import emit_report, render_html
from leak_monitor.safety import verify_public_exports


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.regions, self.assets, self.snapshots = [], [], []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if "data-refresh-region" in attributes:
            self.regions.append(attributes["data-refresh-region"])
        if tag == "script" and "src" in attributes:
            self.assets.append(attributes["src"])
        if tag == "meta" and attributes.get("name") == "report-snapshot":
            self.snapshots.append(attributes.get("content"))


def test_public_pages_expose_coherent_refresh_regions_and_original_data_time(tmp_path):
    timestamp = "2026-10-08T21:25:26+08:00"
    index = Page(render_html([], {"build_time": timestamp}))
    validation = Page(render_validation_html({"finished_at": timestamp, "results": []}))
    for page in (index, validation):
        assert page.snapshots == [timestamp], "refresh must use snapshot time, not UI deployment time"
        assert "timestamp" in page.regions and "results" in page.regions
        assert len(page.regions) == len(set(page.regions))
        assert page.assets == ["public-refresh.js"]
    emit_report(tmp_path, [], [], {"build_time": timestamp})
    assert (tmp_path / "public-refresh.js").is_file()


def test_export_verifier_also_checks_public_validation_files(tmp_path):
    (tmp_path / "health.json").write_text("{}")
    for name in ("validation.html", "validation.json"):
        path = tmp_path / name
        path.write_text("sk-synthetic_abcdefghijklmnopqrstuvwxyz1234567890")
        try:
            verify_public_exports(tmp_path)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{name} must pass the same public secret gate")
        path.unlink()
