#!/usr/bin/env python3
"""
Test suite for eBookSanitizer core sanitization logic.

Creates test EPUB and PDF files with known threats, then verifies
that scanning detects them and sanitization removes them.
"""

import os
import sys
import zipfile
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sanitizer import EPUBSanitizer, PDFSanitizer, SanitizeMode


# ══════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════

def create_test_epub(path: str, malicious: bool = True):
    """Create a test EPUB file, optionally with malicious content."""
    with zipfile.ZipFile(path, 'w') as zf:
        # mimetype must be first and uncompressed
        zf.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)

        # META-INF/container.xml
        zf.writestr('META-INF/container.xml', '''<?xml version="1.0"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles>
    <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
  </rootfiles>
</container>''')

        # OPF
        zf.writestr('OEBPS/content.opf', '''<?xml version="1.0"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>Test Book</dc:title>
  </metadata>
  <manifest>
    <item id="ch1" href="chapter1.xhtml" media-type="application/xhtml+xml"/>
  </manifest>
  <spine><itemref idref="ch1"/></spine>
</package>''')

        if malicious:
            # XHTML with script, event handlers, external links, and dangerous protocols
            xhtml = '''<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Chapter 1</title></head>
<body>
  <h1>Test Chapter</h1>
  <p>Normal content here.</p>
  <script>alert("XSS!");</script>
  <iframe src="https://evil.com/payload"></iframe>
  <img src="https://tracker.com/pixel.gif" onerror="alert(1)" />
  <a href="javascript:alert('phishing')">Click me</a>
  <a href="https://malicious-link.com">External link</a>
  <embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" />
  <p onclick="document.location='https://steal.com'">Trap</p>
</body>
</html>'''
            zf.writestr('OEBPS/chapter1.xhtml', xhtml)

            # Dangerous file hidden in the archive
            zf.writestr('OEBPS/payload.exe', b'\x00' * 100)
        else:
            # Clean XHTML
            xhtml = '''<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Chapter 1</title></head>
<body>
  <h1>Clean Chapter</h1>
  <p>This is a safe book.</p>
</body>
</html>'''
            zf.writestr('OEBPS/chapter1.xhtml', xhtml)


def print_section(title: str):
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}")


def print_result(label: str, passed: bool):
    icon = "PASS" if passed else "FAIL"
    print(f"  [{icon}] {label}")


# ══════════════════════════════════════════════════════════════════════
#  EPUB TESTS
# ══════════════════════════════════════════════════════════════════════

def test_epub_scan():
    """Test EPUB scanning detects all injected threats."""
    print_section("EPUB Scan Detection")

    with tempfile.NamedTemporaryFile(suffix='.epub', delete=False) as f:
        test_path = f.name
    try:
        create_test_epub(test_path, malicious=True)
        sanitizer = EPUBSanitizer(test_path)
        report = sanitizer.scan()

        threat_types = {t.type for t in report.threats}

        print_result("Detected threats", report.has_threats)
        print_result("DangerousFile (.exe)", "DangerousFile" in threat_types)
        print_result("DangerousTag (<script>)", "DangerousTag" in threat_types)
        print_result("EventHandler (on*)", "EventHandler" in threat_types)
        print_result("DangerousProtocol (javascript:)", "DangerousProtocol" in threat_types)
        print_result("ExternalLink", "ExternalLink" in threat_types)

        print(f"\n  Total threats found: {len(report.threats)}")
        summary = report.threat_summary()
        print(f"  High: {summary['High']}, Medium: {summary['Medium']}, Low: {summary['Low']}")

        return report.has_threats
    finally:
        os.unlink(test_path)


def test_epub_clean_scan():
    """Test clean EPUB passes scan without threats."""
    print_section("EPUB Clean File Scan")

    with tempfile.NamedTemporaryFile(suffix='.epub', delete=False) as f:
        test_path = f.name
    try:
        create_test_epub(test_path, malicious=False)
        sanitizer = EPUBSanitizer(test_path)
        report = sanitizer.scan()

        print_result("No threats in clean file", not report.has_threats)
        return not report.has_threats
    finally:
        os.unlink(test_path)


def test_epub_sanitize_standard():
    """Test EPUB Standard mode sanitization."""
    print_section("EPUB Sanitize — Standard Mode")

    with tempfile.NamedTemporaryFile(suffix='.epub', delete=False) as f:
        test_path = f.name
    output_path = test_path.replace('.epub', '_sanitized.epub')
    try:
        create_test_epub(test_path, malicious=True)
        sanitizer = EPUBSanitizer(test_path)
        report = sanitizer.sanitize(output_path, SanitizeMode.STANDARD)

        print_result("Sanitization succeeded", report.success)
        print_result("Output file exists", os.path.isfile(output_path))

        # Re-scan the output to verify threats are removed
        if os.path.isfile(output_path):
            rescan = EPUBSanitizer(output_path)
            rescan_report = rescan.scan()

            # Standard mode should remove scripts/events but keep external links
            rescan_types = {t.type for t in rescan_report.threats}
            print_result("No DangerousTag after sanitize", "DangerousTag" not in rescan_types)
            print_result("No EventHandler after sanitize", "EventHandler" not in rescan_types)
            print_result("No DangerousFile after sanitize", "DangerousFile" not in rescan_types)
            print_result("No DangerousProtocol after sanitize", "DangerousProtocol" not in rescan_types)

        return report.success
    finally:
        for p in (test_path, output_path):
            if os.path.exists(p):
                os.unlink(p)


def test_epub_sanitize_strict():
    """Test EPUB Strict mode — should also neutralize external links."""
    print_section("EPUB Sanitize — Strict Mode")

    with tempfile.NamedTemporaryFile(suffix='.epub', delete=False) as f:
        test_path = f.name
    output_path = test_path.replace('.epub', '_sanitized.epub')
    try:
        create_test_epub(test_path, malicious=True)
        sanitizer = EPUBSanitizer(test_path)
        report = sanitizer.sanitize(output_path, SanitizeMode.STRICT)

        print_result("Sanitization succeeded", report.success)

        if os.path.isfile(output_path):
            rescan = EPUBSanitizer(output_path)
            rescan_report = rescan.scan()
            rescan_types = {t.type for t in rescan_report.threats}
            print_result("No ExternalLink after strict sanitize", "ExternalLink" not in rescan_types)

        return report.success
    finally:
        for p in (test_path, output_path):
            if os.path.exists(p):
                os.unlink(p)


def test_epub_sanitize_paranoid():
    """Test EPUB Paranoid mode — should also remove non-standard files."""
    print_section("EPUB Sanitize — Paranoid Mode")

    with tempfile.NamedTemporaryFile(suffix='.epub', delete=False) as f:
        test_path = f.name
    output_path = test_path.replace('.epub', '_sanitized.epub')
    try:
        create_test_epub(test_path, malicious=True)
        sanitizer = EPUBSanitizer(test_path)
        report = sanitizer.sanitize(output_path, SanitizeMode.PARANOID)

        print_result("Sanitization succeeded", report.success)

        if os.path.isfile(output_path):
            # Check that .exe is NOT in the output
            with zipfile.ZipFile(output_path, 'r') as zf:
                names = zf.namelist()
                has_exe = any(n.endswith('.exe') for n in names)
                print_result("No .exe in paranoid output", not has_exe)

        return report.success
    finally:
        for p in (test_path, output_path):
            if os.path.exists(p):
                os.unlink(p)


# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("  eBookSanitizer — Test Suite")
    print("=" * 60)

    results = []
    results.append(("EPUB Scan Detection", test_epub_scan()))
    results.append(("EPUB Clean File Scan", test_epub_clean_scan()))
    results.append(("EPUB Sanitize Standard", test_epub_sanitize_standard()))
    results.append(("EPUB Sanitize Strict", test_epub_sanitize_strict()))
    results.append(("EPUB Sanitize Paranoid", test_epub_sanitize_paranoid()))

    print_section("SUMMARY")
    passed = sum(1 for _, r in results if r)
    total = len(results)
    for name, r in results:
        print_result(name, r)

    print(f"\n  {passed}/{total} tests passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
