#!/usr/bin/env python3
"""
eBookSanitizer — Scan & sanitize eBooks for malicious content.

This is the main entry point. Launch the GUI application.
"""

import sys
import os

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.app import App


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
