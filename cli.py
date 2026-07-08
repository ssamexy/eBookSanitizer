#!/usr/bin/env python3
"""
eBookSanitizer CLI — Command-line interface for scanning and sanitizing eBooks.

Usage examples:
    # Scan only
    python main.py scan book.epub
    python main.py scan book.pdf

    # Scan and sanitize (standard mode)
    python main.py sanitize book.epub

    # Sanitize with strict mode
    python main.py sanitize book.pdf --mode strict

    # Sanitize with custom output path
    python main.py sanitize book.epub -o clean_book.epub --mode paranoid

    # Output as JSON
    python main.py scan book.pdf --json

    # Launch GUI (default when no arguments given)
    python main.py
    python main.py gui
"""

import argparse
import json
import os
import sys
from typing import Optional

from sanitizer import EPUBSanitizer, PDFSanitizer, SanitizeMode, SanitizeReport, YaraScanner


# ── ANSI Colors for terminal output ──────────────────────────────────

class TermColors:
    """ANSI color codes — gracefully degrades on Windows without ANSI support."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    DIM = "\033[2m"

    @classmethod
    def disable(cls):
        for attr in ('RESET', 'BOLD', 'RED', 'GREEN', 'YELLOW', 'BLUE', 'CYAN', 'DIM'):
            setattr(cls, attr, '')


# Disable colors if output is not a terminal (e.g., piped to file)
if not sys.stdout.isatty():
    TermColors.disable()


# ── CLI Logic ─────────────────────────────────────────────────────────

def create_sanitizer(file_path: str, verbose: bool = False, as_json: bool = False):
    """Create the appropriate sanitizer based on file extension."""
    ext = os.path.splitext(file_path)[1].lower()
    
    # In JSON mode, write verbose logs to stderr to avoid polluting stdout
    if as_json:
        log_cb = (lambda msg: print(f"  {TermColors.DIM}{msg}{TermColors.RESET}", file=sys.stderr)) if verbose else None
    else:
        log_cb = (lambda msg: print(f"  {TermColors.DIM}{msg}{TermColors.RESET}")) if verbose else None

    if ext == '.epub':
        return EPUBSanitizer(file_path, log_callback=log_cb)
    elif ext == '.pdf':
        return PDFSanitizer(file_path, log_callback=log_cb)
    else:
        return None


def print_report(report: SanitizeReport, as_json: bool = False):
    """Print scan/sanitize report to terminal."""
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        return

    C = TermColors
    summary = report.threat_summary()
    total = len(report.threats)

    print()
    if report.has_threats:
        print(f"  {C.YELLOW}{C.BOLD}Threats detected: {total}{C.RESET}")
        print(f"    {C.RED}High: {summary['High']}{C.RESET}  "
              f"{C.YELLOW}Medium: {summary['Medium']}{C.RESET}  "
              f"{C.GREEN}Low: {summary['Low']}{C.RESET}")
        print()

        for t in report.threats:
            if t.severity == "High":
                icon, color = "[!]", C.RED
            elif t.severity == "Medium":
                icon, color = "[~]", C.YELLOW
            else:
                icon, color = "[.]", C.GREEN

            print(f"    {color}{icon} [{t.type}]{C.RESET} {t.path}")
            print(f"        {C.DIM}{t.description}{C.RESET}")
    else:
        print(f"  {C.GREEN}{C.BOLD}No threats detected.{C.RESET}")

    if report.sanitized_path:
        print()
        if report.success:
            print(f"  {C.GREEN}{C.BOLD}Sanitized file saved:{C.RESET} {report.sanitized_path}")
        else:
            print(f"  {C.RED}{C.BOLD}Sanitization failed.{C.RESET}")
            for err in report.errors:
                print(f"    {C.RED}{err}{C.RESET}")

    if report.errors and not report.sanitized_path:
        print()
        for err in report.errors:
            print(f"  {C.RED}ERROR: {err}{C.RESET}")

    print()


def cmd_scan(args):
    """Handle the 'scan' sub-command."""
    C = TermColors
    file_path = args.file

    if not os.path.isfile(file_path):
        print(f"{C.RED}Error: File not found: {file_path}{C.RESET}", file=sys.stderr)
        return 1

    if not args.json:
        print(f"{C.CYAN}{C.BOLD}Scanning:{C.RESET} {file_path}")

    sanitizer = create_sanitizer(file_path, verbose=args.verbose, as_json=args.json)
    if sanitizer is None:
        print(f"{C.RED}Error: Unsupported format. Use EPUB or PDF.{C.RESET}", file=sys.stderr)
        return 1

    report = sanitizer.scan()
    print_report(report, as_json=args.json)

    return 1 if report.has_threats else 0


def cmd_sanitize(args):
    """Handle the 'sanitize' sub-command."""
    C = TermColors
    file_path = args.file

    if not os.path.isfile(file_path):
        print(f"{C.RED}Error: File not found: {file_path}{C.RESET}", file=sys.stderr)
        return 1

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        base, ext = os.path.splitext(file_path)
        output_path = f"{base}_sanitized{ext}"

    # Parse mode
    try:
        mode = SanitizeMode(args.mode)
    except ValueError:
        print(f"{C.RED}Error: Invalid mode '{args.mode}'. "
              f"Use: standard, strict, paranoid{C.RESET}", file=sys.stderr)
        return 1

    if not args.json:
        print(f"{C.CYAN}{C.BOLD}Sanitizing:{C.RESET} {file_path}")
        print(f"  Mode: {C.BOLD}{mode.value}{C.RESET}  Output: {output_path}")

    sanitizer = create_sanitizer(file_path, verbose=args.verbose, as_json=args.json)
    if sanitizer is None:
        print(f"{C.RED}Error: Unsupported format. Use EPUB or PDF.{C.RESET}", file=sys.stderr)
        return 1

    report = sanitizer.sanitize(output_path, mode)
    print_report(report, as_json=args.json)

    return 0 if report.success else 1



def cmd_gui(_args):
    """Handle the 'gui' sub-command — launch the GUI."""
    from gui.app import App
    app = App()
    app.mainloop()
    return 0


# ── Argument Parser ───────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eBookSanitizer",
        description="Scan & sanitize eBooks (EPUB/PDF) for malicious content.",
        epilog="Run without arguments to launch the GUI.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── scan ──
    scan_parser = subparsers.add_parser(
        "scan", help="Scan a file for threats (detection only, no modification)"
    )
    scan_parser.add_argument("file", help="Path to the EPUB or PDF file")
    scan_parser.add_argument("-v", "--verbose", action="store_true",
                             help="Show detailed scan logs")
    scan_parser.add_argument("--json", action="store_true",
                             help="Output results as JSON")

    # ── sanitize ──
    sanitize_parser = subparsers.add_parser(
        "sanitize", help="Scan and sanitize a file, saving a clean copy"
    )
    sanitize_parser.add_argument("file", help="Path to the EPUB or PDF file")
    sanitize_parser.add_argument("-o", "--output", help="Output file path (default: <name>_sanitized.<ext>)")
    sanitize_parser.add_argument("-m", "--mode", default="standard",
                                 choices=["standard", "strict", "paranoid"],
                                 help="Sanitization mode (default: standard)")
    sanitize_parser.add_argument("-v", "--verbose", action="store_true",
                                 help="Show detailed sanitization logs")
    sanitize_parser.add_argument("--json", action="store_true",
                                 help="Output results as JSON")

    # ── gui ──
    subparsers.add_parser("gui", help="Launch the graphical user interface")

    return parser


def cli_main(argv=None) -> int:
    """CLI entry point. Returns exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        # No sub-command → launch GUI
        return cmd_gui(args)
    elif args.command == "scan":
        return cmd_scan(args)
    elif args.command == "sanitize":
        return cmd_sanitize(args)
    elif args.command == "gui":
        return cmd_gui(args)
    else:
        parser.print_help()
        return 0
