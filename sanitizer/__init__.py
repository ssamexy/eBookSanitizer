"""eBookSanitizer - Sanitizer core package."""

from .base import Threat, SanitizeReport, BaseSanitizer, SanitizeMode
from .epub_sanitizer import EPUBSanitizer
from .pdf_sanitizer import PDFSanitizer
from .yara_scanner import YaraScanner

__version__ = "1.0.0"

__all__ = [
    "Threat", "SanitizeReport", "BaseSanitizer", "SanitizeMode",
    "EPUBSanitizer", "PDFSanitizer", "YaraScanner", "__version__",
]
