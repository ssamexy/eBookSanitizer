"""
Theme configuration for eBookSanitizer GUI.
Modern dark/light color palette with glassmorphism-inspired accents.
"""


class Colors:
    """Color palette — curated HSL-based colors for a premium feel."""

    # ── Dark Mode ─────────────────────────────────────
    DARK_BG = "#0F1117"           # Deep space black
    DARK_BG_SECONDARY = "#1A1D27" # Card/panel background
    DARK_BG_TERTIARY = "#252836"  # Input fields, hover states
    DARK_TEXT = "#E8EAED"         # Primary text
    DARK_TEXT_SECONDARY = "#9AA0A6"  # Muted text
    DARK_BORDER = "#2D3140"       # Subtle borders

    # ── Light Mode ────────────────────────────────────
    LIGHT_BG = "#F8F9FA"
    LIGHT_BG_SECONDARY = "#FFFFFF"
    LIGHT_BG_TERTIARY = "#E8EAED"
    LIGHT_TEXT = "#1F2937"
    LIGHT_TEXT_SECONDARY = "#6B7280"
    LIGHT_BORDER = "#D1D5DB"

    # ── Accent Colors ─────────────────────────────────
    PRIMARY = "#6C5CE7"           # Royal purple — brand color
    PRIMARY_HOVER = "#5A4BD1"
    PRIMARY_LIGHT = "#A29BFE"     # Lighter variant for badges

    SUCCESS = "#00B894"           # Tiffany green — scan passed
    SUCCESS_BG = "#0D3B2E"       # Dark bg for success badges

    WARNING = "#FDCB6E"          # Amber — medium threats
    WARNING_BG = "#3B3218"

    DANGER = "#E17055"           # Warm red — high threats
    DANGER_BG = "#3B1E18"

    INFO = "#74B9FF"             # Sky blue — info/links
    INFO_BG = "#1A2B3B"

    # ── Severity Colors ───────────────────────────────
    SEVERITY_HIGH = "#FF6B6B"
    SEVERITY_MEDIUM = "#FFA94D"
    SEVERITY_LOW = "#69DB7C"

    # ── Mode Indicator Colors ─────────────────────────
    MODE_STANDARD = "#00B894"    # Green
    MODE_STRICT = "#FDCB6E"     # Amber
    MODE_PARANOID = "#E17055"   # Red


class Fonts:
    """Typography settings."""
    FAMILY = ("Segoe UI", "Inter", "SF Pro Display", "Arial")
    FAMILY_MONO = ("Cascadia Code", "Fira Code", "Consolas", "monospace")

    SIZE_TITLE = 22
    SIZE_HEADING = 16
    SIZE_BODY = 13
    SIZE_SMALL = 11
    SIZE_MONO = 11


class Layout:
    """Spacing and sizing constants."""
    WINDOW_WIDTH = 900
    WINDOW_HEIGHT = 700
    PADDING = 16
    PADDING_SMALL = 8
    CORNER_RADIUS = 10
    BORDER_WIDTH = 1
