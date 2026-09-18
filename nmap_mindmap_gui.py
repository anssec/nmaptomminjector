#!/usr/bin/env python3
"""Desktop interface for the portable Nmap MindMap Injector.

The application uses only the Python standard library. Build this entry point
with ``build_portable.ps1`` to create a Windows executable that recipients can
run without installing Python, pip packages, or Nmap.
"""

from __future__ import annotations

import os
import queue
import threading
import webbrowser
from pathlib import Path
from typing import Optional

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from nmap_to_mindmap import (
    APP_NAME,
    DB_LOADED,
    InjectionSummary,
    MindMapInjectorError,
    inject_nmap_into_mindmap,
    load_extra_test_cases,
)


# A quiet, high-contrast palette that remains readable on ordinary Windows PCs.
BG = "#1e1e2e"
PANEL = "#2a2a3d"
ACCENT = "#89b4fa"
ACCENT2 = "#a6e3a1"
TEXT = "#cdd6f4"
MUTED = "#a6adc8"
ENTRY_BG = "#313244"
BUTTON_BG = "#45475a"
BUTTON_ACTIVE = "#585b70"
CHK_BG = "#313244"
LOG_OK = "#a6e3a1"
LOG_ERROR = "#f38ba8"
LOG_WARNING = "#fab387"
LOG_INFO = "#89dceb"


class NmapMindmapApp(tk.Tk):
    """A responsive GUI that never calls Tk from its worker thread."""

    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self.configure(bg=BG)
        self.minsize(800, 680)
        self.geometry("980x780")

        # ── File path variables ─────────────────────────────────────────────
        self._nmap_var = tk.StringVar()
        self._nessus_var = tk.StringVar()
        self._source_var = tk.StringVar()
        self._output_var = tk.StringVar()

        # ── Option toggle variables ─────────────────────────────────────────
        self._use_nmap_var = tk.BooleanVar(value=True)
        self._use_nessus_var = tk.BooleanVar(value=False)
        self._add_tc_var = tk.BooleanVar(value=True)

        # ── Internal state ──────────────────────────────────────────────────
        self._events: queue.Queue[tuple[object, ...]] = queue.Queue()
        self._running = False
        self._last_output: Optional[Path] = None

        # Widget references for enable/disable (populated in _build_ui)
        self._nmap_entry: Optional[tk.Entry] = None
        self._nmap_btn: Optional[tk.Button] = None
        self._nessus_entry: Optional[tk.Entry] = None
        self._nessus_btn: Optional[tk.Button] = None

        self._build_ui()
        self._centre_window()
        self.after(75, self._poll_events)

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # Header ─────────────────────────────────────────────────────────────
        header = tk.Frame(self, bg=PANEL, pady=14)
        header.pack(fill="x")
        tk.Label(
            header,
            text=APP_NAME,
            font=("Segoe UI", 16, "bold"),
            fg=ACCENT,
            bg=PANEL,
        ).pack()

        # ── Input sources section ────────────────────────────────────────────

        src_frame = tk.LabelFrame(
            self,
            text="  Input Sources  ",
            font=("Segoe UI", 9, "bold"),
            fg=ACCENT,
            bg=BG,
            bd=1,
            relief="groove",
            padx=16,
            pady=10,
        )
        src_frame.pack(fill="x", padx=20, pady=(14, 0))

        # Row 0 — Nmap
        self._nmap_entry, self._nmap_btn = self._toggle_file_row(
            src_frame, row=0,
            chk_text="Include Nmap output",
            chk_var=self._use_nmap_var,
            path_var=self._nmap_var,
            command=self._browse_nmap,
            btn_label="Browse…",
            toggle_cmd=self._on_nmap_toggle,
        )

        # Row 1 — Nessus
        self._nessus_entry, self._nessus_btn = self._toggle_file_row(
            src_frame, row=1,
            chk_text="Include Nessus output  (.nessus XML or .csv)",
            chk_var=self._use_nessus_var,
            path_var=self._nessus_var,
            command=self._browse_nessus,
            btn_label="Browse…",
            toggle_cmd=self._on_nessus_toggle,
        )

        src_frame.columnconfigure(1, weight=1)

        # Enforce initial toggle states
        self._on_nmap_toggle()
        self._on_nessus_toggle()

        # ── Map files section ─────────────────────────────────────────────────
        map_frame = tk.LabelFrame(
            self,
            text="  Mind Map Files  ",
            font=("Segoe UI", 9, "bold"),
            fg=ACCENT,
            bg=BG,
            bd=1,
            relief="groove",
            padx=16,
            pady=10,
        )
        map_frame.pack(fill="x", padx=20, pady=(8, 0))

        self._file_row(map_frame, 0, "Source mind map (.mm):", self._source_var, self._browse_source, "Browse…")
        self._file_row(map_frame, 1, "Output mind map (.mm):", self._output_var, self._browse_output, "Save as…")
        map_frame.columnconfigure(1, weight=1)

        tk.Label(
            self,
            text=(
                "The default output is a new *_enriched.mm file so your source map stays unchanged. "
                "If an existing output is replaced, a timestamped backup is created first."
            ),
            font=("Segoe UI", 9),
            fg=MUTED,
            bg=BG,
            anchor="w",
            justify="left",
            wraplength=900,
        ).pack(fill="x", padx=20, pady=(4, 0))

        # ── Options section ───────────────────────────────────────────────────
        opt_frame = tk.LabelFrame(
            self,
            text="  Options  ",
            font=("Segoe UI", 9, "bold"),
            fg=ACCENT,
            bg=BG,
            bd=1,
            relief="groove",
            padx=16,
            pady=8,
        )
        opt_frame.pack(fill="x", padx=20, pady=(8, 0))

        inner_opt = tk.Frame(opt_frame, bg=BG)
        inner_opt.pack(fill="x")

        tk.Checkbutton(
            inner_opt,
            text="Add VAPT test cases to port nodes",
            variable=self._add_tc_var,
            font=("Segoe UI", 10),
            fg=TEXT,
            bg=BG,
            activebackground=BG,
            activeforeground=TEXT,
            selectcolor=CHK_BG,
            cursor="hand2",
        ).pack(side="left")

        self._button(
            inner_opt,
            "Upload extra test cases (JSON)…",
            self._upload_test_cases,
        ).pack(side="left", padx=(20, 0))

        tc_hint = (
            "JSON format: {\"tcp\": {\"8080\": [\"TC1\", [\"Parent\", [\"child\"]]]}, "
            "\"udp\": {\"161\": [\"SNMP walk\"]}}"
        )
        tk.Label(
            opt_frame,
            text=tc_hint,
            font=("Consolas", 8),
            fg=MUTED,
            bg=BG,
            anchor="w",
            wraplength=860,
        ).pack(fill="x", pady=(4, 0))

        # ── Action buttons ────────────────────────────────────────────────────
        actions = tk.Frame(self, bg=BG, pady=8)
        actions.pack()
        self._run_button = self._button(
            actions,
            "Run Injection",
            self._on_run,
            foreground="#1e1e2e",
            background=ACCENT2,
            active_background="#94e2a1",
            bold=True,
        )
        self._run_button.pack(side="left", padx=5)
        self._clear_button = self._button(actions, "Clear Log", self._clear_log)
        self._clear_button.pack(side="left", padx=5)
        self._open_button = self._button(actions, "Open Output Folder", self._open_output_folder)
        self._open_button.config(state="disabled")
        self._open_button.pack(side="left", padx=5)

        # ── Activity log ──────────────────────────────────────────────────────
        tk.Label(
            self,
            text="Activity log",
            font=("Segoe UI", 9, "bold"),
            fg=MUTED,
            bg=BG,
            anchor="w",
        ).pack(fill="x", padx=20, pady=(6, 2))

        log_outer = tk.Frame(self, bg=ENTRY_BG, padx=2, pady=2)
        log_outer.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        self._log = tk.Text(
            log_outer,
            font=("Consolas", 10),
            bg=ENTRY_BG,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            bd=0,
            state="disabled",
            wrap="word",
        )
        scrollbar = ttk.Scrollbar(log_outer, command=self._log.yview)
        self._log.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self._log.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        for tag, color in (
            ("ok", LOG_OK),
            ("error", LOG_ERROR),
            ("warning", LOG_WARNING),
            ("info", LOG_INFO),
            ("normal", TEXT),
        ):
            self._log.tag_config(tag, foreground=color)

        # ── Status bar ────────────────────────────────────────────────────────
        self._status = tk.Label(
            self,
            text="Ready — select at least one scan file and a source mind map.",
            font=("Segoe UI", 9),
            fg=MUTED,
            bg=PANEL,
            anchor="w",
            padx=12,
            pady=5,
        )
        self._status.pack(fill="x", side="bottom")

        if not DB_LOADED:
            self._write_log(
                "[WARNING] VAPT test-case database is unavailable; ports can still be added.",
                "warning",
            )

    # ── Widget factories ──────────────────────────────────────────────────────

    def _button(
        self,
        parent: tk.Misc,
        text: str,
        command: object,
        *,
        foreground: str = TEXT,
        background: str = BUTTON_BG,
        active_background: str = BUTTON_ACTIVE,
        bold: bool = False,
    ) -> tk.Button:
        return tk.Button(
            parent,
            text="  {}  ".format(text),
            font=("Segoe UI", 10, "bold" if bold else "normal"),
            fg=foreground,
            bg=background,
            activeforeground=foreground,
            activebackground=active_background,
            relief="flat",
            cursor="hand2",
            bd=0,
            padx=11,
            pady=8,
            command=command,
        )

    def _toggle_file_row(
        self,
        parent: tk.Misc,
        row: int,
        chk_text: str,
        chk_var: tk.BooleanVar,
        path_var: tk.StringVar,
        command: object,
        btn_label: str,
        toggle_cmd: object,
    ) -> tuple[tk.Entry, tk.Button]:
        """A file-row whose entry + button are enabled/disabled by a checkbox."""
        tk.Checkbutton(
            parent,
            text=chk_text,
            variable=chk_var,
            font=("Segoe UI", 10),
            fg=TEXT,
            bg=BG,
            activebackground=BG,
            activeforeground=TEXT,
            selectcolor=CHK_BG,
            cursor="hand2",
            command=toggle_cmd,
        ).grid(row=row, column=0, sticky="w", padx=(0, 12), pady=7)

        entry = tk.Entry(
            parent,
            textvariable=path_var,
            font=("Consolas", 10),
            fg=TEXT,
            bg=ENTRY_BG,
            insertbackground=TEXT,
            disabledbackground="#252536",
            disabledforeground="#555570",
            relief="flat",
            bd=4,
        )
        entry.grid(row=row, column=1, sticky="ew", pady=7)

        btn = self._button(parent, btn_label, command)
        btn.grid(row=row, column=2, padx=(8, 0), pady=7)

        return entry, btn

    def _file_row(
        self,
        parent: tk.Misc,
        row: int,
        label: str,
        variable: tk.StringVar,
        command: object,
        button_text: str,
    ) -> None:
        tk.Label(
            parent,
            text=label,
            font=("Segoe UI", 10),
            fg=TEXT,
            bg=BG,
            anchor="w",
        ).grid(row=row, column=0, sticky="w", padx=(0, 12), pady=7)
        tk.Entry(
            parent,
            textvariable=variable,
            font=("Consolas", 10),
            fg=TEXT,
            bg=ENTRY_BG,
            insertbackground=TEXT,
            relief="flat",
            bd=4,
        ).grid(row=row, column=1, sticky="ew", pady=7)
        self._button(parent, button_text, command).grid(
            row=row, column=2, padx=(8, 0), pady=7
        )

    # ── Toggle handlers ───────────────────────────────────────────────────────

    def _on_nmap_toggle(self) -> None:
        state = "normal" if self._use_nmap_var.get() else "disabled"
        if self._nmap_entry:
            self._nmap_entry.config(state=state)
        if self._nmap_btn:
            self._nmap_btn.config(state=state)

    def _on_nessus_toggle(self) -> None:
        state = "normal" if self._use_nessus_var.get() else "disabled"
        if self._nessus_entry:
            self._nessus_entry.config(state=state)
        if self._nessus_btn:
            self._nessus_btn.config(state=state)

    # ── Browse handlers ───────────────────────────────────────────────────────

    def _browse_nmap(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Nmap Text Output",
            filetypes=[
                ("Nmap text output", "*.txt *.nmap *.log *.out"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self._nmap_var.set(path)

    def _browse_nessus(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Nessus Export",
            filetypes=[
                ("Nessus exports", "*.nessus *.csv"),
                ("Nessus XML", "*.nessus"),
                ("Nessus CSV", "*.csv"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self._nessus_var.set(path)

    def _browse_source(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Source FreeMind Mind Map",
            filetypes=[("FreeMind mind maps", "*.mm"), ("All files", "*.*")],
        )
        if path:
            self._source_var.set(path)
            source = Path(path)
            self._output_var.set(
                str(source.with_name("{}_enriched{}".format(source.stem, source.suffix)))
            )
            self._open_button.config(state="disabled")

    def _browse_output(self) -> None:
        source = Path(self._source_var.get()) if self._source_var.get() else None
        initial_directory = str(source.parent) if source else None
        initial_name = (
            "{}_enriched{}".format(source.stem, source.suffix) if source else "enriched.mm"
        )
        path = filedialog.asksaveasfilename(
            title="Choose Output Mind Map",
            defaultextension=".mm",
            initialdir=initial_directory,
            initialfile=initial_name,
            filetypes=[("FreeMind mind maps", "*.mm"), ("All files", "*.*")],
        )
        if path:
            self._output_var.set(path)
            self._open_button.config(state="disabled")

    def _upload_test_cases(self) -> None:
        """Let the user pick a JSON file and merge extra test cases into the DB."""
        path = filedialog.askopenfilename(
            title="Select Extra Test Cases JSON",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            tcp_n, udp_n = load_extra_test_cases(path)
        except MindMapInjectorError as exc:
            messagebox.showerror("Could not load test cases", str(exc))
            return
        total = tcp_n + udp_n
        self._write_log(
            "[*] Extra test-case JSON loaded: {} TCP port entr{}, {} UDP port entr{} merged.".format(
                tcp_n, "y" if tcp_n == 1 else "ies",
                udp_n, "y" if udp_n == 1 else "ies",
            ),
            "info",
        )
        if total == 0:
            self._write_log(
                "[WARNING] No new port entries were found in the JSON (check proto keys 'tcp'/'udp').",
                "warning",
            )

    # ── Run handler ───────────────────────────────────────────────────────────

    def _on_run(self) -> None:
        if self._running:
            return

        use_nmap = self._use_nmap_var.get()
        use_nessus = self._use_nessus_var.get()

        if not use_nmap and not use_nessus:
            messagebox.showwarning(
                "No input source",
                "Tick at least one of 'Include Nmap output' or 'Include Nessus output'.",
            )
            return

        nmap = self._nmap_var.get().strip() if use_nmap else None
        nessus = self._nessus_var.get().strip() if use_nessus else None
        source = self._source_var.get().strip()
        output = self._output_var.get().strip()
        add_tc = self._add_tc_var.get()

        if use_nmap and not nmap:
            messagebox.showwarning("Nmap file required", "Select a plain-text Nmap output file.")
            return
        if use_nessus and not nessus:
            messagebox.showwarning("Nessus file required", "Select a Nessus export (.nessus or .csv) file.")
            return
        if not source:
            messagebox.showwarning("Source map required", "Select a FreeMind .mm source file.")
            return
        if not output:
            messagebox.showwarning("Output file required", "Choose where to save the enriched .mm file.")
            return

        source_path = Path(source)
        output_path = Path(output)
        try:
            same_file = source_path.resolve() == output_path.resolve()
        except OSError:
            same_file = source_path == output_path

        if same_file:
            message = (
                "The source map will be updated in place. A timestamped backup will be created first.\n\n"
                "Continue?"
            )
        elif output_path.exists():
            message = (
                "The selected output file already exists and will be replaced. "
                "A timestamped backup will be created first.\n\nContinue?"
            )
        else:
            message = ""

        if message and not messagebox.askyesno("Confirm output", message, icon="warning"):
            return

        self._running = True
        self._last_output = None
        self._run_button.config(state="disabled", text="  Running…  ")
        self._clear_button.config(state="disabled")
        self._open_button.config(state="disabled")
        self._clear_log(reset_status=False)
        self._status.config(text="Processing…", fg=LOG_INFO)
        threading.Thread(
            target=self._worker,
            args=(nmap, nessus, source, output, add_tc),
            daemon=True,
            name="nmap-mindmap-worker",
        ).start()

    # ── Background worker ─────────────────────────────────────────────────────

    def _worker(
        self,
        nmap: Optional[str],
        nessus: Optional[str],
        source: str,
        output: str,
        add_tc: bool,
    ) -> None:
        try:
            summary = inject_nmap_into_mindmap(
                nmap,
                source,
                output,
                log=lambda message: self._events.put(("log", message)),
                nessus_file=nessus,
                add_test_cases=add_tc,
            )
        except MindMapInjectorError as exc:
            self._events.put(("done", False, str(exc), None))
        except Exception as exc:  # Keep a windowed portable build diagnosable.
            self._events.put(("done", False, "Unexpected error: {}".format(exc), None))
        else:
            self._events.put(("done", True, "", summary))

    # ── Event polling ─────────────────────────────────────────────────────────

    def _poll_events(self) -> None:
        try:
            while True:
                event = self._events.get_nowait()
                if event[0] == "log":
                    self._write_log(str(event[1]))
                elif event[0] == "done":
                    self._finish_run(
                        bool(event[1]), str(event[2]), event[3] if len(event) > 3 else None
                    )
        except queue.Empty:
            pass
        self.after(75, self._poll_events)

    def _finish_run(
        self, succeeded: bool, error: str, summary: Optional[InjectionSummary]
    ) -> None:
        self._running = False
        self._run_button.config(state="normal", text="  Run Injection  ")
        self._clear_button.config(state="normal")

        if not succeeded:
            self._write_log("[ERROR] {}".format(error), "error")
            self._status.config(text="Completed with an error", fg=LOG_ERROR)
            return

        assert summary is not None
        if not summary.changed:
            if summary.matched_hosts == 0:
                self._status.config(
                    text="No matching IP nodes found — source and output were not changed",
                    fg=LOG_WARNING,
                )
            else:
                self._status.config(
                    text="No changes needed — matching entries already exist",
                    fg=LOG_WARNING,
                )
            return

        self._write_log("[OK] Done!", "ok")
        if summary.nmap_hosts:
            self._write_log(
                "     Nmap hosts parsed    : {}".format(summary.nmap_hosts), "normal"
            )
        if summary.nessus_hosts:
            self._write_log(
                "     Nessus hosts parsed  : {}".format(summary.nessus_hosts), "normal"
            )
        self._write_log(
            "     Unique ports merged  : {}".format(summary.scanned_ports), "normal"
        )
        self._write_log(
            "     Matching map nodes   : {}".format(summary.matched_hosts), "normal"
        )
        self._write_log(
            "     Hosts updated        : {}".format(summary.updated_hosts), "normal"
        )
        self._write_log(
            "     Port nodes added     : {}".format(summary.ports_added), "normal"
        )
        self._write_log(
            "     Test Case groups     : {}".format(summary.test_case_groups_added), "normal"
        )
        self._write_log(
            "     Output               : {}".format(summary.output_path), "normal"
        )
        self._last_output = summary.output_path
        self._open_button.config(state="normal")
        self._status.config(text="Completed successfully", fg=LOG_OK)

    # ── Log helpers ───────────────────────────────────────────────────────────

    def _write_log(self, message: str, tag: Optional[str] = None) -> None:
        if tag is None:
            lowered = message.lower()
            if "[error]" in lowered:
                tag = "error"
            elif "[warning]" in lowered or "[!]" in lowered:
                tag = "warning"
            elif "[ok]" in lowered:
                tag = "ok"
            elif "[*]" in lowered:
                tag = "info"
            else:
                tag = "normal"
        self._log.config(state="normal")
        self._log.insert("end", message + "\n", tag)
        self._log.see("end")
        self._log.config(state="disabled")

    def _clear_log(self, reset_status: bool = True) -> None:
        self._log.config(state="normal")
        self._log.delete("1.0", "end")
        self._log.config(state="disabled")
        if reset_status:
            self._status.config(
                text="Ready — select at least one scan file and a source mind map.",
                fg=MUTED,
            )

    def _open_output_folder(self) -> None:
        if not self._last_output:
            return
        folder = self._last_output.parent
        try:
            if hasattr(os, "startfile"):
                os.startfile(str(folder))  # type: ignore[attr-defined]
            else:
                webbrowser.open(folder.as_uri())
        except OSError as exc:
            messagebox.showerror("Could not open folder", str(exc))

    def _centre_window(self) -> None:
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = max(0, (self.winfo_screenwidth() - width) // 2)
        y = max(0, (self.winfo_screenheight() - height) // 2)
        self.geometry("{}x{}+{}+{}".format(width, height, x, y))


def launch() -> None:
    app = NmapMindmapApp()
    app.mainloop()


if __name__ == "__main__":
    launch()
