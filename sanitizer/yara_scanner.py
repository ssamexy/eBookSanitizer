"""
YARA Scanner - Optional extension for known malware signature detection.

Borrowed from QuickSand's approach: use YARA rules to detect known exploit
byte signatures in decoded PDF/EPUB streams.

This module is OPTIONAL. If yara-python is not installed, all functions
gracefully return empty results. The rest of eBookSanitizer works without it.
"""

import os
from typing import List, Dict, Any, Optional

# Graceful import — YARA is an optional dependency
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class YaraScanner:
    """Optional YARA rule scanner for known malware byte signatures."""

    def __init__(self, rules_dir: Optional[str] = None):
        """Initialize with a directory containing .yar / .yara rule files.
        
        Args:
            rules_dir: Path to a directory of YARA rule files.
                       If None, uses the built-in rules directory.
        """
        self.available = YARA_AVAILABLE
        self._rules = None

        if not self.available:
            return

        if rules_dir is None:
            # Default: look for a 'yara_rules' folder next to this file
            rules_dir = os.path.join(os.path.dirname(__file__), 'yara_rules')

        if os.path.isdir(rules_dir):
            self._compile_rules(rules_dir)

    def _compile_rules(self, rules_dir: str):
        """Compile all .yar/.yara files in the directory."""
        filepaths = {}
        for fname in os.listdir(rules_dir):
            if fname.endswith(('.yar', '.yara')):
                ns = os.path.splitext(fname)[0]
                filepaths[ns] = os.path.join(rules_dir, fname)

        if filepaths:
            try:
                self._rules = yara.compile(filepaths=filepaths)
            except Exception as e:
                print(f"[YaraScanner] Failed to compile YARA rules: {e}")
                self._rules = None

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a file against loaded YARA rules.
        
        Returns:
            List of match dicts: [{"rule": str, "namespace": str, "tags": list, "meta": dict}]
        """
        if not self.available or self._rules is None:
            return []

        try:
            matches = self._rules.match(file_path)
            return [
                {
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": m.tags,
                    "meta": m.meta,
                }
                for m in matches
            ]
        except Exception as e:
            print(f"[YaraScanner] Scan error on {file_path}: {e}")
            return []

    def scan_data(self, data: bytes) -> List[Dict[str, Any]]:
        """Scan raw bytes against loaded YARA rules.
        
        Useful for scanning individual streams extracted from PDFs or EPUB entries.
        """
        if not self.available or self._rules is None:
            return []

        try:
            matches = self._rules.match(data=data)
            return [
                {
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": m.tags,
                    "meta": m.meta,
                }
                for m in matches
            ]
        except Exception as e:
            print(f"[YaraScanner] Data scan error: {e}")
            return []
