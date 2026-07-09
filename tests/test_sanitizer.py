#!/usr/bin/env python3
"""
Comprehensive test suite for eBookSanitizer.

Covers:
- sanitizer/base.py     : Threat, SanitizeReport, SanitizeMode, BaseSanitizer
- sanitizer/epub_sanitizer.py : Layer 1 + Layer 2 (all 3 modes)
- sanitizer/pdf_sanitizer.py  : Layer 3 (all 3 modes, hex de-obfuscation)
- sanitizer/yara_scanner.py   : graceful fallback
- cli.py                      : argument parsing, scan/sanitize commands
- gui/i18n.py                 : translation lookup, language toggle
"""

import os
import sys
import json
import zipfile
import tempfile
import shutil
import io
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


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
        # Inject a /JavaScript name tree into the catalog
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


# ══════════════════════════════════════════════════════════════════════
#  1. BASE MODULE TESTS
# ══════════════════════════════════════════════════════════════════════

@test("Threat.__str__ format")
def test_threat_str():
    t = Threat("JavaScript", "page1.xhtml", "Found script tag", "High")
    assert "[High]" in str(t)
    assert "JavaScript" in str(t)

@test("Threat.to_dict keys")
def test_threat_dict():
    t = Threat("XSS", "ch1.html", "desc", "Medium")
    d = t.to_dict()
    assert d["type"] == "XSS"
    assert d["severity"] == "Medium"
    assert "path" in d and "description" in d

@test("SanitizeReport.add_threat sets has_threats")
def test_report_add_threat():
    r = SanitizeReport("/test.epub")
    assert not r.has_threats
    r.add_threat(Threat("T", "p", "d"))
    assert r.has_threats
    assert len(r.threats) == 1

@test("SanitizeReport.log appends messages")
def test_report_log():
    r = SanitizeReport("/test.epub")
    r.log("msg1")
    r.log("msg2")
    assert len(r.logs) == 2

@test("SanitizeReport.error adds to both logs and errors")
def test_report_error():
    r = SanitizeReport("/test.epub")
    r.error("failure")
    assert len(r.errors) == 1
    assert any("failure" in l for l in r.logs)

@test("SanitizeReport.log_callback fires on log()")
def test_report_log_callback():
    captured = []
    r = SanitizeReport("/test.epub")
    r.set_log_callback(lambda m: captured.append(m))
    r.log("hello")
    r.error("oops")
    assert len(captured) == 2
    assert "hello" in captured[0]

@test("SanitizeReport.threat_summary counts correctly")
def test_report_summary():
    r = SanitizeReport("/test.epub")
    r.add_threat(Threat("A", "p", "d", "High"))
    r.add_threat(Threat("B", "p", "d", "High"))
    r.add_threat(Threat("C", "p", "d", "Medium"))
    s = r.threat_summary()
    assert s == {"High": 2, "Medium": 1, "Low": 0}

@test("SanitizeReport.to_dict includes all fields")
def test_report_to_dict():
    r = SanitizeReport("/test.epub")
    r.add_threat(Threat("T", "p", "d"))
    d = r.to_dict()
    assert "threat_summary" in d
    assert "threats" in d
    assert d["has_threats"] is True

@test("SanitizeMode enum values")
def test_sanitize_mode():
    assert SanitizeMode("standard") == SanitizeMode.STANDARD
    assert SanitizeMode("strict") == SanitizeMode.STRICT
    assert SanitizeMode("paranoid") == SanitizeMode.PARANOID

@test("BaseSanitizer.scan raises NotImplementedError")
def test_base_scan():
    bs = BaseSanitizer("/test.epub")
    try:
        bs.scan()
        assert False, "Should have raised"
    except NotImplementedError:
        pass

@test("BaseSanitizer.sanitize raises NotImplementedError")
def test_base_sanitize():
    bs = BaseSanitizer("/test.epub")
    try:
        bs.sanitize("/out.epub")
        assert False, "Should have raised"
    except NotImplementedError:
        pass


# ══════════════════════════════════════════════════════════════════════
#  2. EPUB SANITIZER TESTS
# ══════════════════════════════════════════════════════════════════════

@test("EPUB scan: clean file has no threats")
def test_epub_clean():
    p = _tmp_path('.epub')
    try:
        _build_epub(p, "<p>Safe content</p>")
        r = EPUBSanitizer(p).scan()
        assert not r.has_threats, f"Expected no threats, got {len(r.threats)}"
    finally:
        os.unlink(p)

@test("EPUB scan: detects <script> tag")
def test_epub_script():
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<script>alert(1)</script>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousTag" in types
    finally:
        os.unlink(p)

@test("EPUB scan: detects <iframe>")
def test_epub_iframe():
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<iframe src="https://evil.com"></iframe>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousTag" in types
    finally:
        os.unlink(p)

@test("EPUB scan: detects <embed> and <object>")
def test_epub_embed_object():
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<embed src="x"/><object data="y"></object>')
        r = EPUBSanitizer(p).scan()
        types = [t.type for t in r.threats if t.type == "DangerousTag"]
        assert len(types) >= 2
    finally:
        os.unlink(p)

@test("EPUB scan: detects on* event handlers")
def test_epub_event_handlers():
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<img src="a.png" onerror="alert(1)"/><p onclick="x()">hi</p>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "EventHandler" in types
    finally:
        os.unlink(p)

@test("EPUB scan: detects javascript: protocol")
def test_epub_js_protocol():
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<a href="javascript:alert(1)">click</a>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousProtocol" in types
    finally:
        os.unlink(p)

@test("EPUB scan: detects data: URI with text/html")
def test_epub_data_uri():
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<embed src="data:text/html;base64,PHNjcmlwdD4="/>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousProtocol" in types or "DangerousTag" in types
    finally:
        os.unlink(p)

@test("EPUB scan: detects external HTTP links")
def test_epub_external_links():
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<a href="https://tracking.com/click">link</a>')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "ExternalLink" in types
    finally:
        os.unlink(p)

@test("EPUB scan: detects dangerous file (.exe) inside archive")
def test_epub_dangerous_file():
    p = _tmp_path('.epub')
    try:
        _build_epub(p, "<p>ok</p>", extra_files={"hidden/payload.exe": b"\x00" * 50})
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DangerousFile" in types
    finally:
        os.unlink(p)

@test("EPUB scan: detects non-standard extension (.dat)")
def test_epub_suspicious_file():
    p = _tmp_path('.epub')
    try:
        _build_epub(p, "<p>ok</p>", extra_files={"data/something.dat": b"data"})
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "SuspiciousFile" in types
    finally:
        os.unlink(p)

@test("EPUB scan: detects ZipSlip directory traversal")
def test_epub_zipslip():
    p = _tmp_path('.epub')
    try:
        # Manually craft a ZIP with traversal path
        with zipfile.ZipFile(p, 'w') as zf:
            zf.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)
            zf.writestr('../../../etc/passwd', 'root:x:0:0')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert "DirectoryTraversal" in types
    finally:
        os.unlink(p)

@test("EPUB scan: non-ZIP file returns error")
def test_epub_invalid_file():
    p = _tmp_path('.epub')
    try:
        with open(p, 'w') as f:
            f.write("not a zip")
        r = EPUBSanitizer(p).scan()
        assert len(r.errors) > 0
    finally:
        os.unlink(p)

@test("EPUB sanitize STANDARD: removes scripts, keeps links")
def test_epub_sanitize_standard():
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        _build_epub(p, '<script>x</script><a href="https://example.com">link</a>')
        r = EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        assert r.success
        # Re-scan
        r2 = EPUBSanitizer(out).scan()
        types = {t.type for t in r2.threats}
        assert "DangerousTag" not in types
        assert "ExternalLink" in types  # Standard keeps links
    finally:
        for f in (p, out):
            if os.path.exists(f): os.unlink(f)

@test("EPUB sanitize STRICT: removes scripts AND external links")
def test_epub_sanitize_strict():
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        _build_epub(p, '<script>x</script><a href="https://evil.com">link</a>')
        r = EPUBSanitizer(p).sanitize(out, SanitizeMode.STRICT)
        assert r.success
        r2 = EPUBSanitizer(out).scan()
        types = {t.type for t in r2.threats}
        assert "DangerousTag" not in types
        assert "ExternalLink" not in types
    finally:
        for f in (p, out):
            if os.path.exists(f): os.unlink(f)

@test("EPUB sanitize PARANOID: removes .exe and non-whitelisted files")
def test_epub_sanitize_paranoid():
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        _build_epub(p, '<script>x</script>',
                    extra_files={"virus.exe": b"\x00", "data.dat": b"x"})
        r = EPUBSanitizer(p).sanitize(out, SanitizeMode.PARANOID)
        assert r.success
        with zipfile.ZipFile(out) as zf:
            names = zf.namelist()
            assert not any(n.endswith('.exe') for n in names)
            assert not any(n.endswith('.dat') for n in names)
    finally:
        for f in (p, out):
            if os.path.exists(f): os.unlink(f)

@test("EPUB sanitize: output is valid EPUB (mimetype first, uncompressed)")
def test_epub_output_validity():
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        _build_epub(p, '<p>content</p>')
        EPUBSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        with zipfile.ZipFile(out) as zf:
            info = zf.infolist()
            assert info[0].filename == 'mimetype'
            assert info[0].compress_type == zipfile.ZIP_STORED
            assert zf.read('mimetype') == b'application/epub+zip'
    finally:
        for f in (p, out):
            if os.path.exists(f): os.unlink(f)

@test("EPUB sanitize PARANOID: removes meta refresh redirects")
def test_epub_meta_refresh():
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        body = '<meta http-equiv="refresh" content="0;url=https://evil.com"/><p>hi</p>'
        # We need this in <head>, let's craft the full xhtml
        xhtml = f'''<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Test</title><meta http-equiv="refresh" content="0;url=https://evil.com"/></head>
<body><p>content</p></body></html>'''
        with zipfile.ZipFile(p, 'w') as zf:
            zf.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)
            zf.writestr('OEBPS/ch1.xhtml', xhtml)
        EPUBSanitizer(p).sanitize(out, SanitizeMode.PARANOID)
        with zipfile.ZipFile(out) as zf:
            content = zf.read('OEBPS/ch1.xhtml').decode('utf-8')
            assert 'refresh' not in content.lower()
    finally:
        for f in (p, out):
            if os.path.exists(f): os.unlink(f)


# ══════════════════════════════════════════════════════════════════════
#  3. PDF SANITIZER TESTS
# ══════════════════════════════════════════════════════════════════════

@test("PDF scan: clean PDF has no threats")
def test_pdf_clean():
    p = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p)
        r = PDFSanitizer(p).scan()
        assert not r.has_threats, f"Expected no threats, got {[str(t) for t in r.threats]}"
    finally:
        os.unlink(p)

@test("PDF scan: detects /JavaScript name tree")
def test_pdf_js():
    p = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p, with_js=True)
        r = PDFSanitizer(p).scan()
        assert r.has_threats
        types = {t.type for t in r.threats}
        assert "JavaScript" in types or "Action" in types
    finally:
        os.unlink(p)

@test("PDF scan: detects /OpenAction")
def test_pdf_openaction():
    p = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p, with_openaction=True)
        r = PDFSanitizer(p).scan()
        assert r.has_threats
        types = {t.type for t in r.threats}
        assert "OpenAction" in types or "Action" in types
    finally:
        os.unlink(p)

@test("PDF hex de-obfuscation: /J#61vaScript -> /JavaScript")
def test_pdf_hex_decode():
    assert PDFSanitizer._normalize_name("/J#61vaScript") == "/JavaScript"
    assert PDFSanitizer._normalize_name("/Open#41ction") == "/OpenAction"
    assert PDFSanitizer._normalize_name("/Normal") == "/Normal"
    assert PDFSanitizer._normalize_name("/#4C#61unch") == "/Launch"

@test("PDF sanitize STANDARD: strips /OpenAction")
def test_pdf_sanitize_standard():
    p = _tmp_path('.pdf')
    out = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p, with_openaction=True)
        r = PDFSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        assert r.success
        # Re-scan
        r2 = PDFSanitizer(out).scan()
        types = {t.type for t in r2.threats}
        assert "OpenAction" not in types
    finally:
        for f in (p, out):
            if os.path.exists(f): os.unlink(f)

@test("PDF sanitize STANDARD: strips /JavaScript")
def test_pdf_sanitize_js():
    p = _tmp_path('.pdf')
    out = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p, with_js=True)
        r = PDFSanitizer(p).sanitize(out, SanitizeMode.STANDARD)
        assert r.success
        r2 = PDFSanitizer(out).scan()
        types = {t.type for t in r2.threats}
        assert "JavaScript" not in types
    finally:
        for f in (p, out):
            if os.path.exists(f): os.unlink(f)

@test("PDF sanitize: output is readable PDF")
def test_pdf_output_valid():
    from pypdf import PdfReader
    p = _tmp_path('.pdf')
    out = _tmp_path('.pdf')
    try:
        _build_simple_pdf(p, with_js=True, with_openaction=True)
        PDFSanitizer(p).sanitize(out, SanitizeMode.STRICT)
        reader = PdfReader(out)
        assert len(reader.pages) == 1
    finally:
        for f in (p, out):
            if os.path.exists(f): os.unlink(f)

@test("PDF scan: non-PDF file returns error")
def test_pdf_invalid_file():
    p = _tmp_path('.pdf')
    try:
        with open(p, 'w') as f:
            f.write("not a pdf")
        r = PDFSanitizer(p).scan()
        assert len(r.errors) > 0
    finally:
        os.unlink(p)


# ══════════════════════════════════════════════════════════════════════
#  4. YARA SCANNER TESTS
# ══════════════════════════════════════════════════════════════════════

@test("YaraScanner: available flag reflects import status")
def test_yara_available():
    ys = YaraScanner()
    # Just check it doesn't crash; availability depends on install
    assert isinstance(ys.available, bool)

@test("YaraScanner: scan_file returns list even if unavailable")
def test_yara_scan_file():
    ys = YaraScanner()
    result = ys.scan_file("/nonexistent/file.pdf")
    assert isinstance(result, list)

@test("YaraScanner: scan_data returns list even if unavailable")
def test_yara_scan_data():
    ys = YaraScanner()
    result = ys.scan_data(b"\x00" * 100)
    assert isinstance(result, list)


# ══════════════════════════════════════════════════════════════════════
#  5. I18N TESTS
# ══════════════════════════════════════════════════════════════════════

@test("I18n: default language is English")
def test_i18n_default():
    i = I18n()
    assert i.lang == "en"

@test("I18n: translate returns English text")
def test_i18n_en():
    i = I18n("en")
    assert "Scan" in i.t("action.scan") or "scan" in i.t("action.scan").lower()

@test("I18n: translate returns Chinese text")
def test_i18n_zh():
    i = I18n("zh")
    result = i.t("app.subtitle")
    assert any(c > '\u4e00' for c in result), f"Expected Chinese chars in: {result}"

@test("I18n: toggle switches language")
def test_i18n_toggle():
    i = I18n("en")
    i.toggle()
    assert i.lang == "zh"
    i.toggle()
    assert i.lang == "en"

@test("I18n: on_change callback fires")
def test_i18n_callback():
    i = I18n("en")
    called = []
    i.on_change(lambda: called.append(1))
    i.lang = "zh"
    assert len(called) == 1
    i.lang = "zh"  # same language, should NOT fire
    assert len(called) == 1

@test("I18n: missing key returns key itself")
def test_i18n_missing_key():
    i = I18n("en")
    assert i.t("nonexistent.key") == "nonexistent.key"

@test("I18n: invalid language falls back to English")
def test_i18n_invalid_lang():
    i = I18n("fr")
    assert i.lang == "en"


# ══════════════════════════════════════════════════════════════════════
#  6. CLI TESTS
# ══════════════════════════════════════════════════════════════════════

@test("CLI parser: scan sub-command parses correctly")
def test_cli_parse_scan():
    parser = build_parser()
    args = parser.parse_args(["scan", "test.epub"])
    assert args.command == "scan"
    assert args.file == "test.epub"
    assert not args.verbose
    assert not args.json

@test("CLI parser: sanitize with all options")
def test_cli_parse_sanitize():
    parser = build_parser()
    args = parser.parse_args(["sanitize", "book.pdf", "-m", "strict", "-o", "out.pdf", "-v", "--json"])
    assert args.command == "sanitize"
    assert args.mode == "strict"
    assert args.output == "out.pdf"
    assert args.verbose
    assert args.json

@test("CLI parser: no arguments -> command is None (GUI)")
def test_cli_parse_none():
    parser = build_parser()
    args = parser.parse_args([])
    assert args.command is None

@test("CLI scan: file not found returns error code")
def test_cli_scan_notfound():
    code = cli_main(["scan", "/nonexistent/file.epub"])
    assert code == 1

@test("CLI sanitize: file not found returns error code")
def test_cli_sanitize_notfound():
    code = cli_main(["sanitize", "/nonexistent/file.epub"])
    assert code == 1

@test("CLI scan: clean EPUB returns 0")
def test_cli_scan_clean():
    p = _tmp_path('.epub')
    try:
        _build_epub(p, "<p>safe</p>")
        # Redirect stdout to suppress output
        f = io.StringIO()
        with redirect_stdout(f):
            code = cli_main(["scan", p])
        assert code == 0
    finally:
        os.unlink(p)

@test("CLI scan: malicious EPUB returns 1")
def test_cli_scan_malicious():
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<script>alert(1)</script>')
        f = io.StringIO()
        with redirect_stdout(f):
            code = cli_main(["scan", p])
        assert code == 1
    finally:
        os.unlink(p)

@test("CLI scan --json: outputs valid JSON")
def test_cli_scan_json():
    p = _tmp_path('.epub')
    try:
        _build_epub(p, '<script>alert(1)</script>')
        f = io.StringIO()
        with redirect_stdout(f):
            cli_main(["scan", p, "--json"])
        output = f.getvalue()
        data = json.loads(output)
        assert "has_threats" in data
        assert "threats" in data
        assert data["has_threats"] is True
    finally:
        os.unlink(p)

@test("CLI sanitize: creates output file")
def test_cli_sanitize_creates():
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        _build_epub(p, '<script>x</script>')
        if os.path.exists(out):
            os.unlink(out)
        f = io.StringIO()
        with redirect_stdout(f):
            code = cli_main(["sanitize", p, "-o", out])
        assert code == 0
        assert os.path.isfile(out)
    finally:
        for path in (p, out):
            if os.path.exists(path): os.unlink(path)

@test("CLI sanitize: unsupported format returns error")
def test_cli_sanitize_unsupported():
    p = _tmp_path('.docx')
    try:
        with open(p, 'w') as fh:
            fh.write("test")
        f = io.StringIO()
        with redirect_stdout(f):
            code = cli_main(["sanitize", p])
        assert code == 1
    finally:
        os.unlink(p)

@test("CLI sanitize --json: outputs valid JSON")
def test_cli_sanitize_json():
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        _build_epub(p, '<script>x</script>')
        f = io.StringIO()
        with redirect_stdout(f):
            cli_main(["sanitize", p, "-o", out, "--json"])
        data = json.loads(f.getvalue())
        assert data["success"] is True
    finally:
        for path in (p, out):
            if os.path.exists(path): os.unlink(path)


# ══════════════════════════════════════════════════════════════════════
#  7. EDGE CASE TESTS
# ══════════════════════════════════════════════════════════════════════

@test("EPUB scan: multiple threat types in single file")
def test_epub_multi_threat():
    p = _tmp_path('.epub')
    try:
        body = '''
        <script>x</script>
        <iframe src="https://evil.com"></iframe>
        <img onerror="alert(1)" src="a.png"/>
        <a href="javascript:void(0)">click</a>
        <a href="https://tracker.com/img.gif">track</a>
        '''
        _build_epub(p, body, extra_files={"payload.bat": b"echo pwned"})
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert len(types) >= 4, f"Expected >= 4 threat types, got {types}"
    finally:
        os.unlink(p)

@test("EPUB sanitize: idempotent (sanitizing twice gives same result)")
def test_epub_idempotent():
    p = _tmp_path('.epub')
    out1 = _tmp_path('.epub')
    out2 = _tmp_path('.epub')
    try:
        _build_epub(p, '<script>x</script><a href="https://evil.com">link</a>')
        EPUBSanitizer(p).sanitize(out1, SanitizeMode.STRICT)
        EPUBSanitizer(out1).sanitize(out2, SanitizeMode.STRICT)
        r1 = EPUBSanitizer(out1).scan()
        r2 = EPUBSanitizer(out2).scan()
        assert len(r1.threats) == len(r2.threats)
    finally:
        for f in (p, out1, out2):
            if os.path.exists(f): os.unlink(f)

@test("EPUB sanitize: preserves non-HTML files (CSS, images)")
def test_epub_preserves_assets():
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        css = "body { font-size: 14px; }"
        _build_epub(p, '<p>content</p>',
                    extra_files={"OEBPS/style.css": css.encode()})
        EPUBSanitizer(p).sanitize(out, SanitizeMode.PARANOID)
        with zipfile.ZipFile(out) as zf:
            assert 'OEBPS/style.css' in zf.namelist()
            assert zf.read('OEBPS/style.css').decode() == css
    finally:
        for f in (p, out):
            if os.path.exists(f): os.unlink(f)

@test("Log callback works with EPUBSanitizer")
def test_epub_log_callback():
    p = _tmp_path('.epub')
    try:
        logs = []
        _build_epub(p, '<script>x</script>')
        s = EPUBSanitizer(p, log_callback=lambda m: logs.append(m))
        s.scan()
        assert len(logs) > 0
    finally:
        os.unlink(p)

@test("Log callback works with PDFSanitizer")
def test_pdf_log_callback():
    p = _tmp_path('.pdf')
    try:
        logs = []
        _build_simple_pdf(p)
        s = PDFSanitizer(p, log_callback=lambda m: logs.append(m))
        s.scan()
        assert len(logs) > 0
    finally:
        os.unlink(p)


# ══════════════════════════════════════════════════════════════════════
#  8. REAL BOOK TESTS (./test data)
# ══════════════════════════════════════════════════════════════════════

def _check_real_book_test(file_path: str, is_epub: bool):
    """General helper to test real books scanning and sanitizing."""
    if not os.path.exists(file_path):
        print(f"    (Skipped: file not found at {file_path})")
        return True # Return true so the test passes as skipped

    sanitizer_cls = EPUBSanitizer if is_epub else PDFSanitizer
    ext = ".epub" if is_epub else ".pdf"
    
    # 1. Test Scan
    s = sanitizer_cls(file_path)
    report = s.scan()
    print(f"    Scanned: {len(report.threats)} threats found.")
    
    # 2. Test Sanitize (Standard)
    out = _tmp_path(ext)
    try:
        s2 = sanitizer_cls(file_path)
        report_s = s2.sanitize(out, SanitizeMode.STANDARD)
        assert report_s.success, f"Sanitization failed for {file_path}"
        assert os.path.isfile(out), f"Sanitized output file not created for {file_path}"
        assert os.path.getsize(out) > 0, "Sanitized file is empty"
        
        # 3. Test verification of sanitized book
        s_verify = sanitizer_cls(out)
        report_v = s_verify.scan()
        # Verify no script or critical threats remain
        for threat in report_v.threats:
            assert threat.severity != "High", f"High severity threat remained in sanitized book: {threat}"
    finally:
        if os.path.exists(out):
            os.unlink(out)
    return True


@test("Real Book: Parenting EPUB")
def test_real_book_parenting_epub():
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(tests_dir, "test_data", "The Five Principles of Parenting Your Essential Guide to Raising Good Humans (Aliza Pressman).epub")
    assert _check_real_book_test(path, is_epub=True)


@test("Real Book: Thinking Fast EPUB")
def test_real_book_thinking_fast_epub():
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(tests_dir, "test_data", "Thinking, Fast and Slow (Daniel Kahneman) (z-library.sk, 1lib.sk, z-lib.sk).epub")
    assert _check_real_book_test(path, is_epub=True)


@test("Real Book: Thinking Fast PDF")
def test_real_book_thinking_fast_pdf():
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(tests_dir, "test_data", "Thinking, Fast and Slow (Daniel Kahneman) (z-library.sk, 1lib.sk, z-lib.sk).pdf")
    assert _check_real_book_test(path, is_epub=False)



# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════

ALL_TESTS = [
    # Base
    test_threat_str, test_threat_dict, test_report_add_threat,
    test_report_log, test_report_error, test_report_log_callback,
    test_report_summary, test_report_to_dict, test_sanitize_mode,
    test_base_scan, test_base_sanitize,
    # EPUB
    test_epub_clean, test_epub_script, test_epub_iframe,
    test_epub_embed_object, test_epub_event_handlers,
    test_epub_js_protocol, test_epub_data_uri, test_epub_external_links,
    test_epub_dangerous_file, test_epub_suspicious_file,
    test_epub_zipslip, test_epub_invalid_file,
    test_epub_sanitize_standard, test_epub_sanitize_strict,
    test_epub_sanitize_paranoid, test_epub_output_validity,
    test_epub_meta_refresh,
    # PDF
    test_pdf_clean, test_pdf_js, test_pdf_openaction,
    test_pdf_hex_decode, test_pdf_sanitize_standard,
    test_pdf_sanitize_js, test_pdf_output_valid, test_pdf_invalid_file,
    # YARA
    test_yara_available, test_yara_scan_file, test_yara_scan_data,
    # I18n
    test_i18n_default, test_i18n_en, test_i18n_zh,
    test_i18n_toggle, test_i18n_callback,
    test_i18n_missing_key, test_i18n_invalid_lang,
    # CLI
    test_cli_parse_scan, test_cli_parse_sanitize, test_cli_parse_none,
    test_cli_scan_notfound, test_cli_sanitize_notfound,
    test_cli_scan_clean, test_cli_scan_malicious,
    test_cli_scan_json, test_cli_sanitize_creates,
    test_cli_sanitize_unsupported, test_cli_sanitize_json,
    # Edge cases
    test_epub_multi_threat, test_epub_idempotent,
    test_epub_preserves_assets, test_epub_log_callback,
    test_pdf_log_callback,
    # Real books
    test_real_book_parenting_epub, test_real_book_thinking_fast_epub,
    test_real_book_thinking_fast_pdf,
]


def main():
    print("=" * 60)
    print("  eBookSanitizer - Comprehensive Test Suite")
    print(f"  {len(ALL_TESTS)} test cases")
    print("=" * 60)

    sections = {
        "Base Module (Threat, Report, Mode)": ALL_TESTS[:11],
        "EPUB Sanitizer (Layer 1 + 2)": ALL_TESTS[11:28],
        "PDF Sanitizer (Layer 3)": ALL_TESTS[28:36],
        "YARA Scanner": ALL_TESTS[36:39],
        "I18n (Bilingual)": ALL_TESTS[39:46],
        "CLI (Command Line Interface)": ALL_TESTS[46:57],
        "Edge Cases & Integration": ALL_TESTS[57:62],
        "Real Book Tests (./test data)": ALL_TESTS[62:],
    }

    for title, tests in sections.items():
        section(title)
        for t in tests:
            run_test(t)

    section("SUMMARY")
    for name, passed, err in _results:
        status = "[PASS]" if passed else "[FAIL]"
        line = f"  {status} {name}"
        if err and not passed:
            line += f"  ({err[:60]})"
        print(line)

    print(f"\n  {_passed}/{_total} tests passed")
    if _passed == _total:
        print("  All tests passed!")
    else:
        print(f"  {_total - _passed} test(s) FAILED")

    return 0 if _passed == _total else 1


if __name__ == "__main__":
    sys.exit(main())
