from pathlib import Path
import tempfile
import unittest

from project_support import PUBLIC_PAGES, STYLE, add_public_support, apply_to_directory


class ProjectSupportTest(unittest.TestCase):
    def test_public_html_has_persistent_header_and_footer(self):
        document = "<html><head><title>Fixture</title></head><body><main>Existing content</main></body></html>"
        result = add_public_support(document)
        self.assertIn('class="project-support-nav"', result)
        self.assertIn('class="project-support-footer"', result)
        self.assertIn("position:sticky;top:0", result)
        self.assertIn("https://support.coinexo.top/", result)
        self.assertIn('rel="noopener noreferrer"', result)
        self.assertIn("<main>Existing content</main>", result)
        self.assertEqual(add_public_support(result), result)

    def test_parser_ignores_tag_strings_and_preserves_original_source(self):
        document = "<!DOCTYPE html>\r\n<HTML><HEAD>\n<script>const tags = '<body>fake</body></head>';</script>\n</HEAD><BODY data-note='>'>Existing &amp; content</BODY></HTML>"
        result = add_public_support(document)
        self.assertIn("<script>const tags = '<body>fake</body></head>';</script>", result)
        self.assertIn("<BODY data-note='>'><!-- Henry public support navigation -->", result)
        style_removed = result.replace(STYLE, "", 1)
        navigation_start = style_removed.index("<!-- Henry public support navigation -->")
        navigation_end = style_removed.index("</nav>", navigation_start) + len("</nav>")
        original = style_removed[:navigation_start] + style_removed[navigation_end:]
        footer_start = original.index('<footer class="project-support-footer">')
        footer_end = original.index("</footer>", footer_start) + len("</footer>")
        self.assertEqual(original[:footer_start] + original[footer_end:], document)

    def test_invalid_public_document_fails_visibly(self):
        for document in ("<div>Stub</div>", "<html><head></head><body>Unclosed", "<html><body></body><head></head></html>"):
            with self.subTest(document=document), self.assertRaises(ValueError):
                add_public_support(document)

    def test_directory_preserves_public_source_line_endings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / PUBLIC_PAGES[0]).write_bytes(b"<html>\r\n<head></head>\r\n<body>Existing\r\ncontent</body></html>")
            apply_to_directory(root)
            result = (root / PUBLIC_PAGES[0]).read_bytes()
            self.assertIn(b"<html>\r\n<head>", result)
            self.assertIn(b"</head>\r\n<body>", result)
            self.assertIn(b"Existing\r\ncontent", result)

    def test_only_public_pages_change_and_error_page_is_self_contained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = "<html><head></head><body>Snapshot content</body></html>"
            for name in (*PUBLIC_PAGES, "private.html", "login.html", "key_manager.html"):
                (root / name).write_text(original)
            (root / "health.json").write_bytes(b'{"build":"original"}')
            apply_to_directory(root)
            for name in PUBLIC_PAGES:
                self.assertIn("project-support-nav", (root / name).read_text())
            for name in ("private.html", "login.html", "key_manager.html"):
                self.assertEqual((root / name).read_text(), original)
            self.assertEqual((root / "health.json").read_bytes(), b'{"build":"original"}')
            error = (root / "404.html").read_text()
            self.assertIn("project-support-nav", error)
            self.assertNotIn('<link rel="stylesheet"', error)
            self.assertIn("https://henryli777.github.io/", error)
