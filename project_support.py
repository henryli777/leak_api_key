"""Public-only support navigation; does not read or change private report pages."""

import argparse
import html
from html.parser import HTMLParser
from pathlib import Path

PUBLIC_PAGES = ("index.html", "validation.html")
HOME = "https://henryli777.github.io/leak_api_key/"
TITLE = "AI 泄露线索监测"
SUPPORT = "https://support.coinexo.top/?project=leak_api_key"
MARKER = "<!-- Henry public support navigation -->"
STYLE = """<style data-project-support>
.project-support-nav{position:sticky;top:0;z-index:100;display:flex;align-items:center;justify-content:space-between;gap:12px;box-sizing:border-box;min-height:48px;padding:8px 20px;background:#fff;color:#17252d;border-bottom:1px solid #dce5df;font:14px/1.5 system-ui,sans-serif}
.project-support-nav .project-support-home{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#17252d;text-decoration:none}
.project-support-link{display:inline-flex;align-items:center;gap:6px;flex-shrink:0;min-height:32px;white-space:nowrap;color:#16745f!important;font:13px/1.5 system-ui,sans-serif;text-decoration:none}
.project-support-link:hover{text-decoration:underline}
.project-support-link:focus-visible,.project-support-home:focus-visible{outline:3px solid #90c7ae;outline-offset:3px}
.project-support-footer{display:flex;align-items:center;justify-content:space-between;gap:12px;box-sizing:border-box;padding:12px 20px;background:#fff;color:#52615a;border-top:1px solid #dce5df;font:12px/1.5 system-ui,sans-serif}
@media(max-width:480px){.project-support-nav,.project-support-footer{padding-left:12px;padding-right:12px}.project-support-home{font-size:12px}.project-support-link{font-size:12px}}
</style>"""


class DocumentBoundaries(HTMLParser):
    def __init__(self, document):
        super().__init__(convert_charrefs=False)
        self.line_offsets = [0] + [index + 1 for index, char in enumerate(document) if char == "\n"]
        self.points = {name: [] for name in ("head_start", "head_end", "body_start", "body_end")}

    def position(self):
        line, column = self.getpos()
        return self.line_offsets[line - 1] + column

    def handle_starttag(self, tag, attrs):
        if tag == "head":
            self.points["head_start"].append(self.position())
        elif tag == "body":
            self.points["body_start"].append(self.position() + len(self.get_starttag_text()))

    def handle_endtag(self, tag):
        if tag in ("head", "body"):
            self.points[tag + "_end"].append(self.position())

    def insertion_points(self):
        if any(len(points) != 1 for points in self.points.values()):
            raise ValueError("Public document must contain exactly one head and body with closing tags")
        points = {name: values[0] for name, values in self.points.items()}
        if not points["head_start"] < points["head_end"] < points["body_start"] <= points["body_end"]:
            raise ValueError("Public document head and body boundaries are out of order")
        return points["head_end"], points["body_start"], points["body_end"]


def support_link():
    return f'<a class="project-support-link" href="{SUPPORT}" target="_blank" rel="noopener noreferrer">支持项目</a>'


def add_public_support(document):
    parser = DocumentBoundaries(document)
    parser.feed(document)
    parser.close()
    head_end, body_start, body_end = parser.insertion_points()
    if MARKER in document:
        return document
    navigation = f'{MARKER}<nav class="project-support-nav" aria-label="项目导航"><a class="project-support-home" href="{HOME}">{html.escape(TITLE)}</a>{support_link()}</nav>'
    footer = f'<footer class="project-support-footer"><span>{html.escape(TITLE)}</span>{support_link()}</footer>'
    # Insert into the untouched source using parser offsets, without serializing HTML.
    for position, content in reversed(((head_end, STYLE), (body_start, navigation), (body_end, footer))):
        document = document[:position] + content + document[position:]
    return document


def render_not_found():
    document = f'<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>页面未找到 · {html.escape(TITLE)}</title></head><body style="margin:0;background:#f7f8fa;color:#17252d;font-family:system-ui,sans-serif"><main style="max-width:900px;margin:auto;padding:40px 20px;min-height:65vh"><h1>页面未找到</h1><p>这个地址不存在，或页面已移动。</p><a href="{HOME}">返回首页</a></main></body></html>'
    return add_public_support(document)


def apply_to_directory(directory):
    root = Path(directory)
    for name in PUBLIC_PAGES:
        path = root / name
        if path.is_file():
            path.write_bytes(add_public_support(path.read_bytes().decode("utf-8")).encode("utf-8"))
    (root / "404.html").write_text(render_not_found(), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    apply_to_directory(parser.parse_args().directory)
