"""
EPUB Sanitizer - Layer 1 (Structure Audit) + Layer 2 (Semantic DOM Analysis)

Detection techniques borrowed from:
- Check TXT: ZIP file list traversal, dangerous extension detection
- OWASP XSS Prevention: script/iframe/embed/object tags, on* events,
  javascript: protocol, data: URI, external resource tracking
- Dangerzone (paranoid mode concept): remove all non-whitelisted files
"""

import os
import re
import zipfile
import shutil
import tempfile
import warnings
from typing import Dict, Any, Optional, Callable
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from .base import BaseSanitizer, Threat, SanitizeReport, SanitizeMode

# We intentionally use html.parser for leniency with potentially malformed content
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)


class EPUBSanitizer(BaseSanitizer):
    """Scans and sanitizes EPUB files using Layer 1 + Layer 2 detection."""

    # ── Layer 1: Structure Audit ──────────────────────────────────────

    # Dangerous file extensions that should NEVER appear inside an EPUB
    DANGEROUS_EXTENSIONS = frozenset({
        '.exe', '.dll', '.bat', '.cmd', '.sh', '.py', '.pl', '.php',
        '.js', '.vbs', '.wsf', '.jar', '.scr', '.pif', '.msi', '.com',
        '.ps1', '.cpl', '.hta', '.inf', '.reg', '.rgs', '.sct', '.wsc',
    })

    # Standard EPUB whitelist (files allowed inside the archive)
    SAFE_EXTENSIONS = frozenset({
        '.xhtml', '.html', '.htm', '.xml', '.opf', '.ncx',
        '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.bmp',
        '.otf', '.ttf', '.woff', '.woff2',
        '.mp3', '.mp4', '.ogg', '.wav', '.m4a',
        '.smil', '.pls',
        '',  # files without extension (e.g., mimetype, META-INF/container)
    })

    # ── Layer 2: Semantic DOM Analysis ────────────────────────────────

    # HTML tags that can execute code or load external content
    DANGEROUS_TAGS = ['script', 'iframe', 'embed', 'object', 'applet', 'form', 'foreignobject']

    # Regex for on* event attributes (case-insensitive)
    ON_EVENT_RE = re.compile(r'^on\w+$', re.IGNORECASE)

    # Protocols considered dangerous in href/src attributes
    DANGEROUS_PROTOCOLS = re.compile(
        r'^\s*(javascript|vbscript|data\s*:.*text/html|data\s*:.*application)',
        re.IGNORECASE
    )

    CSS_EXTERNAL_RE = re.compile(
        r'(@import\s+(?:url\()?["\']?\s*(?:https?:)?//|url\(\s*["\']?\s*(?:https?:)?//)',
        re.IGNORECASE
    )

    CSS_ACTIVE_RE = re.compile(
        r'(expression\s*\(|-moz-binding\s*:|behavior\s*:)',
        re.IGNORECASE
    )

    def __init__(self, file_path: str, log_callback: Optional[Callable[[str], None]] = None):
        super().__init__(file_path, log_callback)

    # ══════════════════════════════════════════════════════════════════
    #  SCAN (detection only, does not modify the file)
    # ══════════════════════════════════════════════════════════════════

    def scan(self) -> SanitizeReport:
        self.report.log(f"Starting EPUB scan: {os.path.basename(self.file_path)}")

        if not zipfile.is_zipfile(self.file_path):
            self.report.error("File is not a valid ZIP/EPUB archive")
            return self.report

        try:
            with zipfile.ZipFile(self.file_path, 'r') as zf:
                namelist = zf.namelist()

                for name in namelist:
                    # ── Layer 1: Structure Audit ──
                    self._scan_structure(name)

                    # ── Layer 2: DOM Analysis (for HTML-like files) ──
                    _, ext = os.path.splitext(name.lower())
                    if ext in {'.xhtml', '.html', '.htm', '.xml', '.svg'}:
                        try:
                            content = zf.read(name)
                            self._scan_dom(name, content)
                        except Exception as e:
                            self.report.log(f"Warning: Could not read {name}: {e}")
                    elif ext == '.css':
                        try:
                            content = zf.read(name).decode('utf-8', errors='replace')
                            self._scan_css(name, content)
                        except Exception as e:
                            self.report.log(f"Warning: Could not read {name}: {e}")

            self.report.success = True

        except Exception as e:
            self.report.error(f"Failed to open EPUB archive: {e}")

        self.report.log(
            f"Scan complete. Found {len(self.report.threats)} threat(s): "
            f"{self.report.threat_summary()}"
        )
        return self.report

    # ── Layer 1 helpers ───────────────────────────────────────────────

    def _scan_structure(self, name: str):
        """Check ZIP entry for structural threats (ZipSlip, dangerous files)."""
        # ZipSlip / Directory Traversal
        if '..' in name or name.startswith('/') or name.startswith('\\'):
            self.report.add_threat(Threat(
                "DirectoryTraversal", name,
                "Path contains directory traversal components (../ or absolute path)",
                "High"
            ))

        _, ext = os.path.splitext(name.lower())

        # Known dangerous extensions
        if ext in self.DANGEROUS_EXTENSIONS:
            self.report.add_threat(Threat(
                "DangerousFile", name,
                f"Contains executable/script file: '{ext}'",
                "High"
            ))
        # Non-standard extensions (warning)
        elif ext and ext not in self.SAFE_EXTENSIONS:
            self.report.add_threat(Threat(
                "SuspiciousFile", name,
                f"Non-standard EPUB file extension: '{ext}'",
                "Medium"
            ))

    # ── Layer 2 helpers ───────────────────────────────────────────────

    def _scan_dom(self, file_in_epub: str, content: bytes):
        """Parse HTML/XHTML and detect XSS attack vectors (OWASP-informed)."""
        soup = BeautifulSoup(content, "html.parser")

        # A. Dangerous tags
        for tag_name in self.DANGEROUS_TAGS:
            tags = soup.find_all(tag_name)
            if tags:
                severity = "High" if tag_name in ('script', 'iframe', 'applet') else "Medium"
                self.report.add_threat(Threat(
                    "DangerousTag", file_in_epub,
                    f"Found {len(tags)} <{tag_name}> tag(s)",
                    severity
                ))

        # B. Inline event handlers (on*)
        for tag in soup.find_all(True):
            for attr in list(tag.attrs.keys()):
                if self.ON_EVENT_RE.match(attr):
                    self.report.add_threat(Threat(
                        "EventHandler", file_in_epub,
                        f"Inline event: {attr}=\"{str(tag[attr])[:80]}\"",
                        "High"
                    ))
                if attr.lower() == 'style':
                    self._scan_css(file_in_epub, str(tag[attr]), inline=True)

        # C. Dangerous protocols in href / src / action
        for tag in soup.find_all(True):
            for attr_name in ('href', 'src', 'action', 'xlink:href', 'formaction'):
                val = tag.get(attr_name, '')
                if val and self.DANGEROUS_PROTOCOLS.match(val):
                    self.report.add_threat(Threat(
                        "DangerousProtocol", file_in_epub,
                        f"<{tag.name}> {attr_name}=\"{val[:100]}\"",
                        "High"
                    ))

        # D. External URLs (http/https) — tracking pixels, C2 callbacks
        external_urls = []
        for tag in soup.find_all(True):
            for attr_name in ('href', 'src', 'xlink:href'):
                val = tag.get(attr_name, '')
                if self._is_external_url(val):
                    external_urls.append(val)

        if external_urls:
            self.report.add_threat(Threat(
                "ExternalLink", file_in_epub,
                f"{len(external_urls)} external URL(s), e.g., \"{external_urls[0][:80]}\"",
                "Medium"
            ))

        for meta in soup.find_all("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)}):
            content = str(meta.get("content", ""))
            severity = "High" if self._is_external_url(self._extract_refresh_url(content)) else "Medium"
            self.report.add_threat(Threat(
                "AutoRedirect", file_in_epub,
                f"Meta refresh redirect: \"{content[:100]}\"",
                severity
            ))

        for style in soup.find_all("style"):
            self._scan_css(file_in_epub, style.get_text() or "", inline=True)

    def _scan_css(self, file_in_epub: str, content: str, inline: bool = False):
        """Detect CSS-based active content and external tracking resources."""
        if not content:
            return
        location = f"{file_in_epub} inline style" if inline else file_in_epub
        if self.CSS_ACTIVE_RE.search(content):
            self.report.add_threat(Threat(
                "ActiveCSS", location,
                "CSS contains legacy active content syntax (expression, behavior, or -moz-binding)",
                "High"
            ))
        if self.CSS_EXTERNAL_RE.search(content):
            self.report.add_threat(Threat(
                "ExternalResource", location,
                "CSS imports or references an external URL",
                "Medium"
            ))

    @staticmethod
    def _is_external_url(url: str) -> bool:
        if not url:
            return False
        u = url.lower().strip()
        return u.startswith("http://") or u.startswith("https://") or u.startswith("//")

    @staticmethod
    def _extract_refresh_url(content: str) -> str:
        match = re.search(r'url\s*=\s*([^;]+)', content, re.IGNORECASE)
        return match.group(1).strip().strip('\"\'') if match else ""

    # ══════════════════════════════════════════════════════════════════
    #  SANITIZE (three-tier modes)
    # ══════════════════════════════════════════════════════════════════

    def sanitize(self, output_path: str, mode: SanitizeMode = SanitizeMode.STANDARD, scrub_metadata: bool = False) -> SanitizeReport:
        self.report.log(f"Sanitizing EPUB [{mode.value}]: {os.path.basename(self.file_path)}")

        if not zipfile.is_zipfile(self.file_path):
            self.report.error("File is not a valid ZIP/EPUB archive")
            return self.report

        temp_dir = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(self.file_path, 'r') as zf:
                for item in zf.infolist():
                    name = item.filename

                    # Skip directory traversal paths
                    if '..' in name or name.startswith('/') or name.startswith('\\'):
                        self.report.log(f"SKIP (ZipSlip): {name}")
                        continue

                    _, ext = os.path.splitext(name.lower())

                    # Remove dangerous files (all modes)
                    if ext in self.DANGEROUS_EXTENSIONS:
                        self.report.log(f"REMOVED dangerous file: {name}")
                        continue

                    # PARANOID: also remove non-whitelisted extensions
                    if mode == SanitizeMode.PARANOID and ext and ext not in self.SAFE_EXTENSIONS:
                        self.report.log(f"REMOVED non-whitelisted file (paranoid): {name}")
                        continue

                    # Create output directory
                    target_path = os.path.join(temp_dir, name)
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)

                    file_data = zf.read(name)

                    # Sanitize HTML-like content
                    if ext in {'.xhtml', '.html', '.htm', '.xml', '.svg'}:
                        file_data = self._sanitize_html(name, file_data, mode)
                    elif ext == '.css':
                        file_data = self._sanitize_css(name, file_data, mode)

                    # Scrub metadata from OPF manifest file
                    if ext == '.opf' and scrub_metadata:
                        file_data = self._scrub_opf_metadata(file_data)

                    with open(target_path, 'wb') as f:
                        f.write(file_data)

            # Repackage as EPUB (spec-compliant)
            self._repackage_epub(temp_dir, output_path)

            self.report.sanitized_path = output_path
            self.report.success = True
            self.report.log("EPUB sanitization completed successfully.")

        except Exception as e:
            self.report.error(f"Sanitization failed: {e}")
            self.report.success = False
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

        return self.report

    def _scrub_opf_metadata(self, file_data: bytes) -> bytes:
        import xml.etree.ElementTree as ET
        try:
            # Register namespaces to keep output formatted correctly
            namespaces = {
                '': 'http://www.idpf.org/2007/opf',
                'dc': 'http://purl.org/dc/elements/1.1/',
                'opf': 'http://www.idpf.org/2007/opf',
                'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
                'dcterms': 'http://purl.org/dc/terms/'
            }
            for prefix, uri in namespaces.items():
                ET.register_namespace(prefix, uri)

            root = ET.fromstring(file_data)
            metadata = root.find('.//{http://www.idpf.org/2007/opf}metadata')
            if metadata is None:
                metadata = root.find('.//metadata')

            if metadata is not None:
                to_remove = []
                for elem in metadata:
                    tag_local = elem.tag.split('}')[-1]
                    if tag_local in ('creator', 'contributor', 'date', 'publisher', 'rights', 'identifier'):
                        to_remove.append(elem)
                    elif tag_local == 'meta' and 'refines' not in elem.attrib:
                        prop = elem.get('property', '')
                        name_attr = elem.get('name', '')
                        if 'modified' in prop or 'date' in prop or name_attr in ('calibre:title_sort', 'calibre:timestamp', 'calibre:series'):
                            to_remove.append(elem)

                for elem in to_remove:
                    metadata.remove(elem)

                # Re-insert safe dc:identifier (pub-id)
                id_elem = ET.Element('{http://purl.org/dc/elements/1.1/}identifier', id='pub-id')
                id_elem.text = 'urn:uuid:00000000-0000-0000-0000-000000000000'
                metadata.append(id_elem)

                self.report.log("EPUB: Anonymized metadata inside OPF manifest.")

            return ET.tostring(root, encoding='utf-8')
        except Exception as e:
            self.report.log(f"Warning: Failed to scrub OPF metadata: {e}")
            return file_data

    def _sanitize_html(self, file_in_epub: str, content: bytes, mode: SanitizeMode) -> bytes:
        """Clean HTML content according to the selected sanitization mode."""
        soup = BeautifulSoup(content, "html.parser")
        modified = False

        # ── All modes: remove dangerous tags ──
        for tag_name in self.DANGEROUS_TAGS:
            for tag in soup.find_all(tag_name):
                tag.decompose()
                modified = True
                self.report.log(f"[{file_in_epub}] Removed <{tag_name}>")

        # ── All modes: strip on* event handlers ──
        for tag in soup.find_all(True):
            for attr in list(tag.attrs.keys()):
                if self.ON_EVENT_RE.match(attr):
                    del tag[attr]
                    modified = True

        # ── All modes: remove dangerous protocols ──
        for tag in soup.find_all(True):
            for attr_name in ('href', 'src', 'action', 'xlink:href', 'formaction'):
                val = tag.get(attr_name, '')
                if val and self.DANGEROUS_PROTOCOLS.match(val):
                    tag[attr_name] = "#disabled_by_sanitizer"
                    modified = True
                    self.report.log(f"[{file_in_epub}] Neutralized {attr_name}=\"{val[:60]}\"")

        # ── STRICT + PARANOID: neutralize external URLs ──
        # Remove auto-redirects in every mode; they execute on document open.
        for meta in soup.find_all("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)}):
            meta.decompose()
            modified = True
            self.report.log(f"[{file_in_epub}] Removed meta refresh redirect")

        for style in soup.find_all("style"):
            original = style.get_text() or ""
            cleaned = self._sanitize_css_text(original, mode)
            if cleaned != original:
                style.string = cleaned
                modified = True
                self.report.log(f"[{file_in_epub}] Sanitized CSS in <style>")

        for tag in soup.find_all(True):
            if tag.has_attr("style"):
                original = str(tag["style"])
                cleaned = self._sanitize_css_text(original, mode)
                if cleaned != original:
                    tag["style"] = cleaned
                    modified = True

        if mode in (SanitizeMode.STRICT, SanitizeMode.PARANOID):
            for tag in soup.find_all("a", href=True):
                if self._is_external_url(tag["href"]):
                    original = tag["href"]
                    tag["href"] = "#"
                    modified = True
                    self.report.log(f"[{file_in_epub}] Neutralized link: {original[:60]}")

            # Block external images (tracking pixels / SSRF)
            for tag in soup.find_all(["img", "image"]):
                for attr_name in ('src', 'xlink:href', 'href'):
                    val = tag.get(attr_name, '')
                    if self._is_external_url(val):
                        tag[attr_name] = ""
                        modified = True
                        self.report.log(f"[{file_in_epub}] Blocked external image: {val[:60]}")

            # Block external CSS
            for link in soup.find_all("link", href=True):
                if self._is_external_url(link["href"]):
                    link.decompose()
                    modified = True
                    self.report.log(f"[{file_in_epub}] Blocked external CSS stylesheet")

            for base in soup.find_all("base", href=True):
                if self._is_external_url(base["href"]):
                    base.decompose()
                    modified = True
                    self.report.log(f"[{file_in_epub}] Removed external <base> href")

        if not modified:
            return content
        return str(soup).encode('utf-8')

    def _sanitize_css(self, file_in_epub: str, content: bytes, mode: SanitizeMode) -> bytes:
        text = content.decode('utf-8', errors='replace')
        cleaned = self._sanitize_css_text(text, mode)
        if cleaned != text:
            self.report.log(f"[{file_in_epub}] Sanitized CSS")
        return cleaned.encode('utf-8')

    def _sanitize_css_text(self, text: str, mode: SanitizeMode) -> str:
        cleaned = self.CSS_ACTIVE_RE.sub('/* active css removed */', text)
        if mode in (SanitizeMode.STRICT, SanitizeMode.PARANOID):
            cleaned = re.sub(
                r'@import\s+(?:url\()?["\']?\s*(?:https?:)?//[^;)]*\)?\s*;?',
                '/* external import removed */',
                cleaned,
                flags=re.IGNORECASE
            )
            cleaned = re.sub(
                r'url\(\s*["\']?\s*(?:https?:)?//[^)]*\)',
                'url("")',
                cleaned,
                flags=re.IGNORECASE
            )
        return cleaned

    @staticmethod
    def _repackage_epub(temp_dir: str, output_path: str):
        """Repackage directory as a valid EPUB archive.
        
        EPUB spec requirements:
        1. First entry MUST be 'mimetype'
        2. mimetype content MUST be 'application/epub+zip'
        3. mimetype MUST NOT be compressed (ZIP_STORED)
        """
        mimetype_path = os.path.join(temp_dir, 'mimetype')
        if not os.path.exists(mimetype_path):
            with open(mimetype_path, 'w', encoding='utf-8') as f:
                f.write('application/epub+zip')

        with zipfile.ZipFile(output_path, 'w') as zf:
            # Write mimetype first, uncompressed
            zf.write(mimetype_path, 'mimetype', compress_type=zipfile.ZIP_STORED)

            # Write everything else with DEFLATE
            for root, _dirs, files in os.walk(temp_dir):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, temp_dir).replace(os.sep, '/')
                    if rel_path == 'mimetype':
                        continue
                    zf.write(full_path, rel_path, compress_type=zipfile.ZIP_DEFLATED)
