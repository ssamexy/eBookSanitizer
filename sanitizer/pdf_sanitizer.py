"""
PDF Sanitizer - Layer 3 (Hex-Decoded Keyword Engine)

Detection techniques borrowed from:
- PDFiD (Didier Stevens): Hex de-obfuscation (#XX decoding), keyword counting
  for /JavaScript, /JS, /OpenAction, /AA, /Launch, /EmbeddedFile, /XFA
- Dangerzone (paranoid mode concept): full object-tree rebuild keeping only
  safe rendering keys (/Page, /Pages, /Contents, /Resources, /MediaBox, etc.)

Extended with:
- /SubmitForm, /ImportData detection
- Recursive object tree traversal (including Annotations)
- Action /S sub-type analysis (/S = JavaScript | Launch | URI | SubmitForm)
"""

import os
import re
from typing import Dict, Any, Optional, Callable, Set, Union
from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    DictionaryObject, NameObject, ArrayObject,
    IndirectObject, NumberObject,
)
from .base import BaseSanitizer, Threat, SanitizeReport, SanitizeMode


class PDFSanitizer(BaseSanitizer):
    """Scans and sanitizes PDF files using Layer 3 keyword engine."""

    # ── Dangerous PDF keys (normalized names) ─────────────────────────
    # High severity: code execution / auto-action
    HIGH_KEYS = frozenset({
        "/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch",
    })
    # Medium severity: data exfiltration / embedded payloads
    MEDIUM_KEYS = frozenset({
        "/EmbeddedFiles", "/EmbeddedFile", "/XFA", "/SubmitForm", "/ImportData",
        "/RichMedia", "/Rendition",
    })
    ALL_DANGEROUS_KEYS = HIGH_KEYS | MEDIUM_KEYS

    # Action sub-types that execute code or launch local programs.
    HIGH_ACTION_TYPES = frozenset({
        "/JavaScript", "/JS", "/Launch",
    })

    # Action sub-types that can open external content or exfiltrate form data.
    MEDIUM_ACTION_TYPES = frozenset({
        "/URI", "/SubmitForm", "/ImportData", "/GoToR", "/GoToE", "/Rendition",
    })

    DANGEROUS_ACTION_TYPES = HIGH_ACTION_TYPES | MEDIUM_ACTION_TYPES

    # Keys safe to keep in PARANOID mode page rebuild
    PARANOID_SAFE_PAGE_KEYS = frozenset({
        "/Type", "/Parent", "/Contents", "/Resources", "/MediaBox",
        "/CropBox", "/BleedBox", "/TrimBox", "/ArtBox", "/Rotate",
        "/UserUnit",
    })

    # Keys safe to keep in PARANOID mode root rebuild
    PARANOID_SAFE_ROOT_KEYS = frozenset({
        "/Type", "/Pages", "/PageLayout", "/PageMode",
        "/Metadata", "/MarkInfo", "/StructTreeRoot", "/Lang",
    })

    def __init__(self, file_path: str, log_callback: Optional[Callable[[str], None]] = None):
        super().__init__(file_path, log_callback)

    # ══════════════════════════════════════════════════════════════════
    #  HEX DE-OBFUSCATION (borrowed from PDFiD)
    # ══════════════════════════════════════════════════════════════════

    @staticmethod
    def _normalize_name(name: str) -> str:
        """Decode PDF hex-obfuscated names: /J#61vaScript → /JavaScript"""
        if '#' not in name:
            return name
        return re.sub(
            r'#([0-9a-fA-F]{2})',
            lambda m: chr(int(m.group(1), 16)),
            name
        )

    # ══════════════════════════════════════════════════════════════════
    #  SCAN
    # ══════════════════════════════════════════════════════════════════

    def scan(self) -> SanitizeReport:
        self.report.log(f"Starting PDF scan: {os.path.basename(self.file_path)}")
        try:
            reader = PdfReader(self.file_path)
            visited: Set[int] = set()

            # 1. Document Root (Catalog)
            if reader.root_object:
                self._scan_dict("Document Root", reader.root_object, visited)

            # 2. All pages + annotations
            for i, page in enumerate(reader.pages):
                page_obj = page.get_object()
                self._scan_dict(f"Page {i + 1}", page_obj, visited)

                annots = page_obj.get("/Annots")
                if isinstance(annots, ArrayObject):
                    for j, ref in enumerate(annots):
                        annot = ref.get_object() if hasattr(ref, 'get_object') else ref
                        if isinstance(annot, DictionaryObject):
                            self._scan_dict(f"Page {i + 1} Annot {j + 1}", annot, visited)

            self.report.success = True

        except Exception as e:
            self.report.error(f"Failed to scan PDF: {e}")

        self.report.log(
            f"Scan complete. Found {len(self.report.threats)} threat(s): "
            f"{self.report.threat_summary()}"
        )
        return self.report

    def _scan_dict(self, location: str, obj: DictionaryObject, visited: Set[int]):
        obj_id = id(obj)
        if obj_id in visited:
            return
        visited.add(obj_id)

        for key, value in obj.items():
            norm = self._normalize_name(key)

            # Check if the key itself is dangerous
            if norm in self.ALL_DANGEROUS_KEYS:
                severity = "High" if norm in self.HIGH_KEYS else "Medium"
                self.report.add_threat(Threat(
                    norm.replace("/", ""), location,
                    f"Key '{key}' (normalized: '{norm}')",
                    severity
                ))

            # Check Action sub-type: /A { /S /JavaScript ... }
            if norm == "/A":
                self._scan_action(location, value)

            # Recurse
            resolved = value.get_object() if hasattr(value, 'get_object') else value
            if isinstance(resolved, DictionaryObject):
                self._scan_dict(location, resolved, visited)
            elif isinstance(resolved, ArrayObject):
                self._scan_array(location, resolved, visited)

    def _scan_action(self, location: str, value):
        action = value.get_object() if hasattr(value, 'get_object') else value
        if not isinstance(action, DictionaryObject):
            return
        s_type = self._normalize_name(str(action.get("/S", "")))
        if s_type in self.DANGEROUS_ACTION_TYPES:
            severity = "High" if s_type in self.HIGH_ACTION_TYPES else "Medium"
            self.report.add_threat(Threat(
                "Action", location,
                f"Action /S = {s_type}",
                severity
            ))

    def _scan_array(self, location: str, arr: ArrayObject, visited: Set[int]):
        for item in arr:
            resolved = item.get_object() if hasattr(item, 'get_object') else item
            if isinstance(resolved, DictionaryObject):
                self._scan_dict(location, resolved, visited)
            elif isinstance(resolved, ArrayObject):
                self._scan_array(location, resolved, visited)

    # ══════════════════════════════════════════════════════════════════
    #  SANITIZE (three-tier modes)
    # ══════════════════════════════════════════════════════════════════

    def sanitize(self, output_path: str, mode: SanitizeMode = SanitizeMode.STANDARD, scrub_metadata: bool = False) -> SanitizeReport:
        self.report.log(f"Sanitizing PDF [{mode.value}]: {os.path.basename(self.file_path)}")

        try:
            reader = PdfReader(self.file_path)
            writer = PdfWriter()

            # ── In-place clean pages and add to writer ──
            for i, page in enumerate(reader.pages):
                if mode == SanitizeMode.PARANOID:
                    self._paranoid_rebuild_page_inplace(i, page)
                else:
                    self._clean_page_inplace(i, page, mode)

                writer.add_page(page)

            # ── Clean document root ──
            self._clean_root(reader, writer, mode, scrub_metadata)

            # ── Document Information (/Info) ──
            if scrub_metadata:
                writer._info.clear()
                self.report.log("Trailer: Cleared Document Info dictionary (/Info) for metadata scrubbing.")
            elif reader.metadata:
                writer.add_metadata(reader.metadata)

            # ── Write output ──
            with open(output_path, "wb") as f:
                writer.write(f)

            self.report.sanitized_path = output_path
            self.report.success = True
            self.report.log("PDF sanitization completed successfully.")

        except Exception as e:
            self.report.error(f"Sanitization failed: {e}")
            self.report.success = False

        return self.report

    # ── Page-level cleaning (in-place) ────────────────────────────────

    def _clean_page_inplace(self, page_idx: int, page: DictionaryObject,
                            mode: SanitizeMode):
        """Clean a page dict in-place by removing dangerous keys."""
        for k in list(page.keys()):
            norm = self._normalize_name(k)

            # All modes: strip /AA (Additional Actions)
            if norm == "/AA":
                del page[k]
                self.report.log(f"Page {page_idx + 1}: Stripped /AA")
                continue

            # Handle annotations
            if norm == "/Annots":
                annots_val = page[k]
                annots = annots_val.get_object() if hasattr(annots_val, 'get_object') else annots_val
                if isinstance(annots, ArrayObject):
                    self._clean_annotations_inplace(page_idx, annots, mode)

    def _clean_annotations_inplace(self, page_idx: int, annots: ArrayObject,
                                   mode: SanitizeMode):
        """Clean page annotations in-place."""
        for i, ref in enumerate(list(annots)):
            annot = ref.get_object() if hasattr(ref, 'get_object') else ref
            if isinstance(annot, DictionaryObject):
                self._clean_dict_obj_inplace(
                    f"Page {page_idx + 1} Annot {i + 1}", annot, mode
                )

    def _clean_dict_obj_inplace(self, location: str, obj: DictionaryObject,
                                mode: SanitizeMode):
        """Recursively clean a dictionary object in-place."""
        for k in list(obj.keys()):
            norm = self._normalize_name(k)

            # STANDARD: remove JS, AA, OpenAction, Launch
            if norm in self.HIGH_KEYS:
                del obj[k]
                self.report.log(f"{location}: Stripped {norm}")
                continue

            # STRICT / PARANOID: also remove medium-severity keys
            if mode in (SanitizeMode.STRICT, SanitizeMode.PARANOID):
                if norm in self.MEDIUM_KEYS:
                    del obj[k]
                    self.report.log(f"{location}: Stripped {norm}")
                    continue

            # Handle /A (Action) sub-dictionaries
            if norm == "/A":
                action = obj[k].get_object() if hasattr(obj[k], 'get_object') else obj[k]
                if isinstance(action, DictionaryObject):
                    s_type = self._normalize_name(str(action.get("/S", "")))

                    # Always remove code execution / local launch actions.
                    if s_type in self.HIGH_ACTION_TYPES:
                        del obj[k]
                        self.report.log(f"{location}: Stripped action /S={s_type}")
                        continue

                    # STRICT+: also remove external navigation and form/data actions.
                    if mode in (SanitizeMode.STRICT, SanitizeMode.PARANOID):
                        if s_type in self.MEDIUM_ACTION_TYPES:
                            del obj[k]
                            self.report.log(f"{location}: Stripped action /S={s_type}")
                            continue

            # Recurse into sub-dicts
            v = obj[k]
            resolved = v.get_object() if hasattr(v, 'get_object') else v
            if isinstance(resolved, DictionaryObject):
                self._clean_dict_obj_inplace(location, resolved, mode)

    # ── PARANOID: full page rebuild (in-place) ────────────────────────

    def _paranoid_rebuild_page_inplace(self, page_idx: int, page: DictionaryObject):
        """Rebuild page dict in-place keeping ONLY safe rendering keys."""
        for k in list(page.keys()):
            norm = self._normalize_name(k)
            if norm not in self.PARANOID_SAFE_PAGE_KEYS:
                del page[k]
                self.report.log(f"Page {page_idx + 1} (paranoid): Dropped {norm}")

    # ── Root (Catalog) cleaning ───────────────────────────────────────

    def _clean_root(self, reader: PdfReader, writer: PdfWriter,
                    mode: SanitizeMode, scrub_metadata: bool = False):
        """Clean the document catalog / root object."""
        root = writer._root_object
        orig_root = reader.root_object

        for k, v in orig_root.items():
            norm = self._normalize_name(k)

            # Skip keys already managed by PdfWriter
            if k in root:
                continue

            # Skip metadata stream if scrubbing
            if norm == "/Metadata" and scrub_metadata:
                self.report.log("Root: Stripped /Metadata stream (Metadata Scrubbing)")
                continue

            # STANDARD: strip high-severity root keys
            if norm in self.HIGH_KEYS:
                self.report.log(f"Root: Stripped {norm}")
                continue

            # All modes: clean /Names subtree
            if norm == "/Names":
                names = v.get_object() if hasattr(v, 'get_object') else v
                if isinstance(names, DictionaryObject):
                    clean_names = self._clean_names_tree(names, mode)
                    root[NameObject(k)] = clean_names
                    continue

            # STRICT+: strip medium-severity root keys
            if mode in (SanitizeMode.STRICT, SanitizeMode.PARANOID):
                if norm in self.MEDIUM_KEYS:
                    self.report.log(f"Root: Stripped {norm}")
                    continue

            # PARANOID: only keep safe root keys
            if mode == SanitizeMode.PARANOID:
                if norm not in self.PARANOID_SAFE_ROOT_KEYS:
                    self.report.log(f"Root (paranoid): Dropped {norm}")
                    continue

            root[NameObject(k)] = v

    def _clean_names_tree(self, names: DictionaryObject,
                          mode: SanitizeMode) -> DictionaryObject:
        """Clean the /Names dictionary (JS name tree, embedded files, etc.) in-place."""
        clean = DictionaryObject()
        for k, v in names.items():
            norm = self._normalize_name(k)

            # Always remove JS name tree
            if norm == "/JavaScript":
                self.report.log("Root/Names: Stripped /JavaScript name tree")
                continue

            # STRICT+: remove embedded files
            if mode in (SanitizeMode.STRICT, SanitizeMode.PARANOID):
                if norm == "/EmbeddedFiles":
                    self.report.log("Root/Names: Stripped /EmbeddedFiles")
                    continue

            clean[NameObject(k)] = v
        return clean

