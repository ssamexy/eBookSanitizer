"""
eBookSanitizer GUI — Modern CustomTkinter interface with bilingual support.

Features:
- File selection (click or browse)
- Three-tier sanitization mode selector (Standard / Strict / Paranoid)
- Real-time activity log with color-coded entries
- Scan report with threat summary
- Dark / Light theme toggle
- Chinese / English language toggle
"""

import sys
import os

# If this file is run directly instead of main.py, redirect to main.py
if __name__ == "__main__" and __package__ is None:
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, parent_dir)
    import subprocess
    sys.exit(subprocess.call([sys.executable, os.path.join(parent_dir, "main.py")] + sys.argv[1:]))

import os
import threading
import subprocess
import platform
from tkinter import filedialog, messagebox
import customtkinter as ctk

from .theme import Colors, Fonts, Layout
from .i18n import I18n
from sanitizer import EPUBSanitizer, PDFSanitizer, SanitizeMode, YaraScanner


class App(ctk.CTk):
    """Main application window."""

    def __init__(self):
        super().__init__()

        # ── State ──
        self.i18n = I18n("en")
        self.selected_files: list[str] = []
        self.mode = SanitizeMode.STANDARD
        self.yara_scanner = YaraScanner()

        # ── Window Setup ──
        self.title("eBookSanitizer")
        self.geometry(f"{Layout.WINDOW_WIDTH}x{Layout.WINDOW_HEIGHT}")
        self.minsize(750, 600)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # ── Build UI ──
        self._build_ui()
        self.i18n.on_change(self._refresh_texts)
        self._setup_drag_and_drop()

    # ══════════════════════════════════════════════════════════════════
    #  UI CONSTRUCTION
    # ══════════════════════════════════════════════════════════════════

    def _build_ui(self):
        # Main container
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)  # Log panel expands

        self._build_header()
        self._build_file_section()
        self._build_mode_section()
        self._build_action_buttons()
        self._build_log_panel()

    # ── Header ────────────────────────────────────────────────────────

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=Layout.PADDING, pady=(Layout.PADDING, 4))
        header.grid_columnconfigure(1, weight=1)

        # Title
        self.title_label = ctk.CTkLabel(
            header, text="🛡️ eBookSanitizer",
            font=ctk.CTkFont(family=Fonts.FAMILY[0], size=Fonts.SIZE_TITLE, weight="bold"),
        )
        self.title_label.grid(row=0, column=0, sticky="w")

        # Subtitle
        self.subtitle_label = ctk.CTkLabel(
            header, text=self.i18n.t("app.subtitle"),
            font=ctk.CTkFont(size=Fonts.SIZE_SMALL),
            text_color=Colors.DARK_TEXT_SECONDARY,
        )
        self.subtitle_label.grid(row=1, column=0, sticky="w")

        # Right side: Language + Theme toggles (wrapped in right_panel to avoid grid overlap)
        right_panel = ctk.CTkFrame(header, fg_color="transparent")
        right_panel.grid(row=0, column=2, rowspan=2, sticky="ne")

        toggle_frame = ctk.CTkFrame(right_panel, fg_color="transparent")
        toggle_frame.pack(side="top", anchor="e", pady=(0, 2))

        self.lang_button = ctk.CTkButton(
            toggle_frame, text="中文", width=60, height=28,
            font=ctk.CTkFont(size=Fonts.SIZE_SMALL),
            fg_color=Colors.DARK_BG_TERTIARY,
            hover_color=Colors.PRIMARY,
            command=self._toggle_language,
        )
        self.lang_button.pack(side="left", padx=4)

        self.theme_button = ctk.CTkButton(
            toggle_frame, text="☀️", width=36, height=28,
            font=ctk.CTkFont(size=14),
            fg_color=Colors.DARK_BG_TERTIARY,
            hover_color=Colors.PRIMARY,
            command=self._toggle_theme,
        )
        self.theme_button.pack(side="left", padx=4)

        # YARA status
        yara_text = self.i18n.t("yara.available" if self.yara_scanner.available else "yara.unavailable")
        yara_color = Colors.SUCCESS if self.yara_scanner.available else Colors.DARK_TEXT_SECONDARY
        self.yara_label = ctk.CTkLabel(
            right_panel, text=yara_text,
            font=ctk.CTkFont(size=Fonts.SIZE_SMALL - 1),
            text_color=yara_color,
        )
        self.yara_label.pack(side="top", anchor="e", pady=(2, 0))

    # ── File Selection ────────────────────────────────────────────────

    def _build_file_section(self):
        file_frame = ctk.CTkFrame(self, corner_radius=Layout.CORNER_RADIUS)
        file_frame.grid(row=1, column=0, sticky="ew", padx=Layout.PADDING, pady=Layout.PADDING_SMALL)
        file_frame.grid_columnconfigure(0, weight=1)

        # Drop zone (simulated with a button)
        self.file_drop = ctk.CTkButton(
            file_frame,
            text=f"📂  {self.i18n.t('file.drop_title')}\n\n{self.i18n.t('file.drop_subtitle')}",
            font=ctk.CTkFont(size=Fonts.SIZE_BODY),
            height=80,
            fg_color=Colors.DARK_BG_TERTIARY,
            hover_color=Colors.DARK_BG_SECONDARY,
            border_width=2,
            border_color=Colors.DARK_BORDER,
            text_color=Colors.DARK_TEXT_SECONDARY,
            command=self._select_file,
        )
        self.file_drop.grid(row=0, column=0, sticky="ew", padx=Layout.PADDING, pady=Layout.PADDING)

        # File path label
        self.file_label = ctk.CTkLabel(
            file_frame, text="",
            font=ctk.CTkFont(family=Fonts.FAMILY_MONO[0], size=Fonts.SIZE_SMALL),
            text_color=Colors.PRIMARY_LIGHT,
        )
        self.file_label.grid(row=1, column=0, sticky="w", padx=Layout.PADDING, pady=(0, 8))

    # ── Mode Selection ────────────────────────────────────────────────

    def _build_mode_section(self):
        mode_frame = ctk.CTkFrame(self, fg_color="transparent")
        mode_frame.grid(row=2, column=0, sticky="ew", padx=Layout.PADDING, pady=Layout.PADDING_SMALL)
        mode_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.mode_var = ctk.StringVar(value="standard")

        modes = [
            ("standard", "mode.standard", "mode.standard_desc", Colors.MODE_STANDARD),
            ("strict", "mode.strict", "mode.strict_desc", Colors.MODE_STRICT),
            ("paranoid", "mode.paranoid", "mode.paranoid_desc", Colors.MODE_PARANOID),
        ]

        self.mode_buttons = []
        self.mode_desc_labels = []

        for col, (value, title_key, desc_key, color) in enumerate(modes):
            card = ctk.CTkFrame(mode_frame, corner_radius=Layout.CORNER_RADIUS)
            card.grid(row=0, column=col, sticky="nsew", padx=4)
            card.grid_columnconfigure(0, weight=1)

            btn = ctk.CTkRadioButton(
                card, text=self.i18n.t(title_key),
                variable=self.mode_var, value=value,
                font=ctk.CTkFont(size=Fonts.SIZE_BODY, weight="bold"),
                border_color=color,
                fg_color=color,
                hover_color=color,
                command=self._on_mode_change,
            )
            btn.grid(row=0, column=0, sticky="w", padx=12, pady=(10, 2))
            self.mode_buttons.append((btn, title_key))

            desc = ctk.CTkLabel(
                card, text=self.i18n.t(desc_key),
                font=ctk.CTkFont(size=Fonts.SIZE_SMALL - 1),
                text_color=Colors.DARK_TEXT_SECONDARY,
                wraplength=220, justify="left",
            )
            desc.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 10))
            self.mode_desc_labels.append((desc, desc_key))

    # ── Action Buttons ────────────────────────────────────────────────

    def _build_action_buttons(self):
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=3, column=0, sticky="ew", padx=Layout.PADDING, pady=Layout.PADDING_SMALL)
        btn_frame.grid_columnconfigure((0, 1), weight=1)

        self.scan_btn = ctk.CTkButton(
            btn_frame, text=self.i18n.t("action.scan"),
            font=ctk.CTkFont(size=Fonts.SIZE_BODY, weight="bold"),
            height=42,
            fg_color=Colors.INFO,
            hover_color=Colors.PRIMARY,
            command=self._on_scan,
        )
        self.scan_btn.grid(row=0, column=0, sticky="ew", padx=(0, 4))

        self.sanitize_btn = ctk.CTkButton(
            btn_frame, text=self.i18n.t("action.sanitize"),
            font=ctk.CTkFont(size=Fonts.SIZE_BODY, weight="bold"),
            height=42,
            fg_color=Colors.PRIMARY,
            hover_color=Colors.PRIMARY_HOVER,
            command=self._on_sanitize,
        )
        self.sanitize_btn.grid(row=0, column=1, sticky="ew", padx=(4, 0))

    # ── Log Panel ─────────────────────────────────────────────────────

    def _build_log_panel(self):
        log_frame = ctk.CTkFrame(self, corner_radius=Layout.CORNER_RADIUS)
        log_frame.grid(row=4, column=0, sticky="nsew", padx=Layout.PADDING,
                       pady=(Layout.PADDING_SMALL, Layout.PADDING))
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(4, weight=1)

        # Header row
        log_header = ctk.CTkFrame(log_frame, fg_color="transparent")
        log_header.grid(row=0, column=0, sticky="ew", padx=12, pady=(8, 0))
        log_header.grid_columnconfigure(0, weight=1)

        self.log_title = ctk.CTkLabel(
            log_header, text=self.i18n.t("log.title"),
            font=ctk.CTkFont(size=Fonts.SIZE_BODY, weight="bold"),
        )
        self.log_title.grid(row=0, column=0, sticky="w")

        self.clear_btn = ctk.CTkButton(
            log_header, text=self.i18n.t("log.clear"), width=60, height=24,
            font=ctk.CTkFont(size=Fonts.SIZE_SMALL),
            fg_color=Colors.DARK_BG_TERTIARY,
            hover_color=Colors.DANGER,
            command=self._clear_log,
        )
        self.clear_btn.grid(row=0, column=1, sticky="e")

        # Log textbox
        self.log_box = ctk.CTkTextbox(
            log_frame,
            font=ctk.CTkFont(family=Fonts.FAMILY_MONO[0], size=Fonts.SIZE_MONO),
            activate_scrollbars=True,
            wrap="word",
        )
        self.log_box.grid(row=1, column=0, sticky="nsew", padx=8, pady=(4, 8))
        self.log_box.configure(state="disabled")

    # ══════════════════════════════════════════════════════════════════
    #  ACTIONS
    # ══════════════════════════════════════════════════════════════════

    def _select_file(self):
        paths = filedialog.askopenfilenames(
            title="Select eBooks",
            filetypes=[
                ("eBook files", "*.epub *.pdf"),
                ("EPUB", "*.epub"),
                ("PDF", "*.pdf"),
                ("All files", "*.*"),
            ]
        )
        if paths:
            self.selected_files = list(paths)
            self._update_file_labels()

    def _update_file_labels(self):
        count = len(self.selected_files)
        if count == 0:
            self.file_label.configure(text="")
            self.file_drop.configure(
                text=f"📂  {self.i18n.t('file.drop_title')}\n\n{self.i18n.t('file.drop_subtitle')}",
                border_color=Colors.DARK_BORDER,
                text_color=Colors.DARK_TEXT_SECONDARY,
            )
        elif count == 1:
            filename = os.path.basename(self.selected_files[0])
            self.file_label.configure(
                text=f"📄 {self.i18n.t('file.selected')}: {filename}"
            )
            self.file_drop.configure(
                text=f"📂 {filename}",
                border_color=Colors.PRIMARY,
                text_color=Colors.PRIMARY_LIGHT,
            )
            self._log(f"File selected: {self.selected_files[0]}")
        else:
            self.file_label.configure(
                text=f"📚 {self.i18n.t('file.selected_count').format(count)}"
            )
            self.file_drop.configure(
                text=self.i18n.t('file.batch_mode').format(count),
                border_color=Colors.PRIMARY,
                text_color=Colors.PRIMARY_LIGHT,
            )
            self._log(f"Batch files selected ({count} files):")
            for f in self.selected_files:
                self._log(f"  - {f}")

    def _setup_drag_and_drop(self):
        if platform.system() == "Windows":
            try:
                import windnd
                windnd.hook_dropfiles(self, self._on_file_dropped)
                self._log("Drag & Drop support enabled.")
            except ImportError:
                self._log("Install 'windnd' to enable drag & drop support.")

    def _on_file_dropped(self, files):
        valid_files = []
        for f in files:
            path = f.decode('utf-8') if isinstance(f, bytes) else f
            ext = os.path.splitext(path.lower())[1]
            if ext in ('.epub', '.pdf'):
                valid_files.append(path)
        
        if valid_files:
            self.selected_files = valid_files
            self._update_file_labels()
        else:
            messagebox.showwarning(
                self.i18n.t("dialog.error"),
                self.i18n.t("dialog.unsupported")
            )

    def _on_mode_change(self):
        val = self.mode_var.get()
        self.mode = SanitizeMode(val)
        self._log(f"Mode changed to: {val}")

    def _on_scan(self):
        if not self._validate_file():
            return
        self._set_buttons_state(False)
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _on_sanitize(self):
        if not self._validate_file():
            return
        self._set_buttons_state(False)
        threading.Thread(target=self._run_sanitize, daemon=True).start()

    def _run_scan(self):
        total = len(self.selected_files)
        self.after(0, lambda: self._log("=" * 50))
        self.after(0, lambda: self._log(f"Batch Scan Started: {total} files"))
        self.after(0, lambda: self._log("=" * 50))
        
        for idx, file_path in enumerate(self.selected_files):
            try:
                self.after(0, lambda f=file_path, i=idx: self._log(f"\n[{i+1}/{total}] Scanning: {os.path.basename(f)}"))
                sanitizer = self._create_sanitizer_for_file(file_path)
                if sanitizer is None:
                    continue
                report = sanitizer.scan()
                self.after(0, lambda r=report: self._show_results(r, scan_only=True))
            except Exception as e:
                self.after(0, lambda m=file_path, err=e: self._log(f"ERROR on {os.path.basename(m)}: {err}"))
        
        self.after(0, lambda: self._log("\n" + "=" * 50))
        self.after(0, lambda: self._log("Batch Scan Completed."))
        self.after(0, lambda: self._log("=" * 50))
        self.after(0, lambda: self._set_buttons_state(True))

    def _run_sanitize(self):
        total = len(self.selected_files)
        self.after(0, lambda: self._log("=" * 50))
        self.after(0, lambda: self._log(f"Batch Sanitization Started: {total} files [{self.mode.value}]"))
        self.after(0, lambda: self._log("=" * 50))

        success_count = 0
        for idx, file_path in enumerate(self.selected_files):
            try:
                self.after(0, lambda f=file_path, i=idx: self._log(f"\n[{i+1}/{total}] Sanitizing: {os.path.basename(f)}"))
                sanitizer = self._create_sanitizer_for_file(file_path)
                if sanitizer is None:
                    continue

                # Generate output path
                base, ext = os.path.splitext(file_path)
                output_path = f"{base}_sanitized{ext}"

                report = sanitizer.sanitize(output_path, self.mode)
                if report.success:
                    success_count += 1
                self.after(0, lambda r=report: self._show_results(r, scan_only=False))
            except Exception as e:
                self.after(0, lambda m=file_path, err=e: self._log(f"ERROR on {os.path.basename(m)}: {err}"))

        self.after(0, lambda: self._log("\n" + "=" * 50))
        self.after(0, lambda: self._log(f"Batch Sanitization Completed. Success: {success_count}/{total}"))
        self.after(0, lambda: self._log("=" * 50))
        self.after(0, lambda: self._set_buttons_state(True))

    def _create_sanitizer_for_file(self, file_path: str):
        ext = os.path.splitext(file_path)[1].lower()
        log_cb = lambda msg: self.after(0, lambda m=msg: self._log(m))

        if ext == '.epub':
            return EPUBSanitizer(file_path, log_callback=log_cb)
        elif ext == '.pdf':
            return PDFSanitizer(file_path, log_callback=log_cb)
        else:
            self.after(0, lambda f=file_path: self._log(f"Skipped: Unsupported format for {os.path.basename(f)}"))
            return None

    def _validate_file(self) -> bool:
        if not self.selected_files:
            messagebox.showwarning(
                self.i18n.t("dialog.error"),
                self.i18n.t("dialog.no_file")
            )
            return False
        return True

    # ══════════════════════════════════════════════════════════════════
    #  RESULTS DISPLAY
    # ══════════════════════════════════════════════════════════════════

    def _show_results(self, report, scan_only: bool):
        self._log("─" * 50)

        if report.has_threats:
            summary = report.threat_summary()
            self._log(f"⚠️  {self.i18n.t('result.threats_found')}:")
            self._log(f"   🔴 {self.i18n.t('result.high')}: {summary['High']}  "
                      f"🟡 {self.i18n.t('result.medium')}: {summary['Medium']}  "
                      f"🟢 {self.i18n.t('result.low')}: {summary['Low']}")
            self._log("")
            for t in report.threats:
                icon = "🔴" if t.severity == "High" else ("🟡" if t.severity == "Medium" else "🟢")
                self._log(f"   {icon} [{t.type}] {t.path}")
                self._log(f"      {t.description}")
        else:
            self._log(self.i18n.t("result.no_threats"))

        if not scan_only:
            self._log("")
            if report.success:
                self._log(self.i18n.t("result.sanitized_ok"))
                self._log(f"   {self.i18n.t('result.saved_to')}: {report.sanitized_path}")
            else:
                self._log(self.i18n.t("result.sanitized_fail"))
                for err in report.errors:
                    self._log(f"   ❌ {err}")

        self._log("─" * 50)

    # ══════════════════════════════════════════════════════════════════
    #  UTILITIES
    # ══════════════════════════════════════════════════════════════════

    def _log(self, message: str):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", message + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    def _set_buttons_state(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        self.scan_btn.configure(state=state)
        self.sanitize_btn.configure(state=state)

    def _toggle_language(self):
        self.i18n.toggle()
        new_label = "English" if self.i18n.lang == "zh" else "中文"
        self.lang_button.configure(text=new_label)

    def _toggle_theme(self):
        current = ctk.get_appearance_mode()
        if current == "Dark":
            ctk.set_appearance_mode("light")
            self.theme_button.configure(text="🌙")
        else:
            ctk.set_appearance_mode("dark")
            self.theme_button.configure(text="☀️")

    def _refresh_texts(self):
        """Called when language changes — update all translatable widgets."""
        self.subtitle_label.configure(text=self.i18n.t("app.subtitle"))
        self.file_drop.configure(
            text=f"📂  {self.i18n.t('file.drop_title')}\n\n{self.i18n.t('file.drop_subtitle')}"
        )
        self.scan_btn.configure(text=self.i18n.t("action.scan"))
        self.sanitize_btn.configure(text=self.i18n.t("action.sanitize"))
        self.log_title.configure(text=self.i18n.t("log.title"))
        self.clear_btn.configure(text=self.i18n.t("log.clear"))

        yara_key = "yara.available" if self.yara_scanner.available else "yara.unavailable"
        self.yara_label.configure(text=self.i18n.t(yara_key))

        # Update mode buttons and descriptions
        for btn, key in self.mode_buttons:
            btn.configure(text=self.i18n.t(key))
        for lbl, key in self.mode_desc_labels:
            lbl.configure(text=self.i18n.t(key))

        # Update file label if files are selected
        if self.selected_files:
            self._update_file_labels()
