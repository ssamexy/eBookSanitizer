#!/usr/bin/env python3
"""
eBookSanitizer — Scan & sanitize eBooks for malicious content.

Dual-mode entry point:
  - No arguments → launch GUI
  - With sub-commands → run CLI

Usage:
    python main.py                         # Launch GUI
    python main.py gui                     # Launch GUI (explicit)
    python main.py scan <file>             # Scan only (CLI)
    python main.py sanitize <file>         # Scan & sanitize (CLI)
    python main.py sanitize <file> -m strict -v  # Strict mode, verbose
    python main.py scan <file> --json      # JSON output
"""

import sys
import os

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli import cli_main


if __name__ == "__main__":
    sys.exit(cli_main())
