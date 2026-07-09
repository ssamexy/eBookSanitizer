#!/usr/bin/env python3
import os
import sys
import zipfile
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, TextStringObject, ArrayObject
from sanitizer.epub_sanitizer import EPUBSanitizer
from sanitizer.pdf_sanitizer import PDFSanitizer
from sanitizer.base import SanitizeMode


def _tmp_path(suffix):
    f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    f.close()
    return f.name


def _cleanup(*paths):
    for path in paths:
        if path and os.path.exists(path):
            os.unlink(path)


def test_epub_meta_refresh_css_scan():
    p = _tmp_path('.epub')
    try:
        xhtml = '''<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <title>Test</title>
  <meta http-equiv="refresh" content="0;url=https://evil.example/phish"/>
  <style>@import url(https://evil.example/track.css); .x { behavior: url(evil.htc); }</style>
</head><body><p style="background:url(//evil.example/pixel.png)">content</p></body></html>'''
        with zipfile.ZipFile(p, 'w') as zf:
            zf.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)
            zf.writestr('OEBPS/ch1.xhtml', xhtml)
            zf.writestr('OEBPS/style.css', 'body { background: url(https://evil.example/bg.png); }')
        r = EPUBSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert r.success is True
        assert 'AutoRedirect' in types
        assert 'ActiveCSS' in types
        assert 'ExternalResource' in types
    finally:
        _cleanup(p)


def test_epub_sanitize_strict_css_refresh():
    p = _tmp_path('.epub')
    out = _tmp_path('.epub')
    try:
        xhtml = '''<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<meta http-equiv="refresh" content="0;url=https://evil.example"/>
<base href="https://evil.example/"/>
<link rel="stylesheet" href="https://evil.example/x.css"/>
<style>@import url(https://evil.example/track.css); .x { behavior: url(evil.htc); }</style>
</head><body><p style="background:url(https://evil.example/pixel.png)">content</p></body></html>'''
        with zipfile.ZipFile(p, 'w') as zf:
            zf.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)
            zf.writestr('OEBPS/ch1.xhtml', xhtml)
            zf.writestr('OEBPS/style.css', '@import url(https://evil.example/a.css); body{background:url(//evil.example/b.png)}')
        r = EPUBSanitizer(p).sanitize(out, SanitizeMode.STRICT)
        assert r.success
        r2 = EPUBSanitizer(out).scan()
        types = {t.type for t in r2.threats}
        assert 'AutoRedirect' not in types
        assert 'ActiveCSS' not in types
        assert 'ExternalResource' not in types
    finally:
        _cleanup(p, out)


def test_pdf_uri_gotor_actions_medium():
    p = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        annots = ArrayObject()
        for action_type, target_key, target_val in (
            ('/URI', '/URI', 'https://evil.example/phish'),
            ('/GoToR', '/F', 'remote.pdf'),
        ):
            annot = DictionaryObject()
            action = DictionaryObject()
            action[NameObject('/S')] = NameObject(action_type)
            action[NameObject(target_key)] = TextStringObject(target_val)
            annot[NameObject('/A')] = action
            annots.append(annot)
        writer.pages[0][NameObject('/Annots')] = annots
        with open(p, 'wb') as f:
            writer.write(f)
        r = PDFSanitizer(p).scan()
        action_threats = [t for t in r.threats if t.type == 'Action']
        assert r.success is True
        assert len(action_threats) >= 2
        assert all(t.severity == 'Medium' for t in action_threats)
    finally:
        _cleanup(p)


def test_pdf_richmedia_embeddedfile_keys():
    p = _tmp_path('.pdf')
    try:
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        writer._root_object[NameObject('/RichMedia')] = DictionaryObject()
        writer._root_object[NameObject('/EmbeddedFile')] = DictionaryObject()
        with open(p, 'wb') as f:
            writer.write(f)
        r = PDFSanitizer(p).scan()
        types = {t.type for t in r.threats}
        assert 'RichMedia' in types
        assert 'EmbeddedFile' in types
    finally:
        _cleanup(p)


if __name__ == '__main__':
    tests = [
        test_epub_meta_refresh_css_scan,
        test_epub_sanitize_strict_css_refresh,
        test_pdf_uri_gotor_actions_medium,
        test_pdf_richmedia_embeddedfile_keys,
    ]
    for test in tests:
        test()
        print(f'[PASS] {test.__name__}')
