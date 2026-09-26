import customtkinter as ctk
from tkinter import filedialog, messagebox
import re
import csv
import os
from collections import defaultdict
from datetime import datetime


# ──────────────────────────────────────────────
#  THEME
# ──────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BRUTE_THRESHOLD = 5          # flag IP after this many failures
COLOR_CRITICAL  = "#FF4C4C"  # red
COLOR_WARNING   = "#FFA500"  # orange
COLOR_SAFE      = "#2ECC71"  # green
COLOR_INFO      = "#5BC0F8"  # blue
COLOR_BG        = "#0D1117"  # near-black
COLOR_CARD      = "#161B22"  # card bg
COLOR_BORDER    = "#21262D"  # subtle border
COLOR_TEXT      = "#E6EDF3"  # primary text
COLOR_MUTED     = "#8B949E"  # secondary text


# ──────────────────────────────────────────────
#  LOG PARSER
# ──────────────────────────────────────────────
def parse_log(filepath):
    """Parse an auth.log file and return structured results."""
    failed   = defaultdict(list)   # ip -> [username, ...]
    accepted = []                  # list of dicts
    total_lines = 0

    # Patterns
    fail_pattern = re.compile(
        r"(\w+\s+\d+\s+[\d:]+).*Failed password for (\S+) from ([\d.]+)"
    )
    accept_pattern = re.compile(
        r"(\w+\s+\d+\s+[\d:]+).*Accepted password for (\S+) from ([\d.]+)"
    )

    with open(filepath, "r") as f:
        for line in f:
            total_lines += 1
            fm = fail_pattern.search(line)
            if fm:
                timestamp, user, ip = fm.group(1), fm.group(2), fm.group(3)
                failed[ip].append({"user": user, "time": timestamp})
                continue
            am = accept_pattern.search(line)
            if am:
                timestamp, user, ip = am.group(1), am.group(2), am.group(3)
                accepted.append({"ip": ip, "user": user, "time": timestamp})

    # Build IP summary
    ip_summary = []
    for ip, events in failed.items():
        count    = len(events)
        users    = list({e["user"] for e in events})
        last     = events[-1]["time"]
        is_brute = count >= BRUTE_THRESHOLD
        severity = "CRITICAL" if count >= BRUTE_THRESHOLD * 2 else ("HIGH" if is_brute else "MEDIUM")
        ip_summary.append({
            "ip"      : ip,
            "failures": count,
            "users"   : ", ".join(users),
            "last_seen": last,
            "brute"   : is_brute,
            "severity": severity,
        })

    ip_summary.sort(key=lambda x: x["failures"], reverse=True)

    stats = {
        "total_lines"   : total_lines,
        "failed_attempts": sum(len(v) for v in failed.values()),
        "unique_ips"    : len(failed),
        "brute_ips"     : sum(1 for r in ip_summary if r["brute"]),
        "accepted"      : len(accepted),
    }

    return ip_summary, accepted, stats


# ──────────────────────────────────────────────
#  EXPORT
# ──────────────────────────────────────────────
def export_csv(ip_summary, filepath):
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip","failures","users","last_seen","severity","brute"])
        writer.writeheader()
        writer.writerows(ip_summary)


# ──────────────────────────────────────────────
#  MAIN APP
# ──────────────────────────────────────────────
class LogAnalyzerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Log Analyzer — SOC Threat Dashboard")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.configure(fg_color=COLOR_BG)

        self._ip_summary = []
        self._accepted   = []
        self._stats      = {}

        self._build_ui()

    # ── UI LAYOUT ────────────────────────────
    def _build_ui(self):
        # Top bar
        topbar = ctk.CTkFrame(self, fg_color=COLOR_CARD, corner_radius=0, height=60)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)

        ctk.CTkLabel(
            topbar, text="🛡  Log Analyzer",
            font=ctk.CTkFont("Segoe UI", 20, "bold"),
            text_color=COLOR_INFO
        ).pack(side="left", padx=24, pady=12)

        ctk.CTkLabel(
            topbar, text="SSH Auth Log — Brute Force Detector",
            font=ctk.CTkFont("Segoe UI", 12),
            text_color=COLOR_MUTED
        ).pack(side="left", padx=0, pady=12)

        # Action buttons (top right)
        btn_frame = ctk.CTkFrame(topbar, fg_color="transparent")
        btn_frame.pack(side="right", padx=16, pady=8)

        self.export_btn = ctk.CTkButton(
            btn_frame, text="⬇  Export CSV", width=130,
            fg_color="#21262D", hover_color="#30363D",
            text_color=COLOR_TEXT, corner_radius=8,
            command=self._export
        )
        self.export_btn.pack(side="right", padx=(8, 0))

        ctk.CTkButton(
            btn_frame, text="📂  Load Log File", width=140,
            fg_color=COLOR_INFO, hover_color="#3AA0D8",
            text_color="#000000", corner_radius=8,
            font=ctk.CTkFont("Segoe UI", 13, "bold"),
            command=self._load_file
        ).pack(side="right")

        # Body
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=16)

        # Left column — stat cards + IP table
        left = ctk.CTkFrame(body, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True)

        # Stat cards row
        self.cards_frame = ctk.CTkFrame(left, fg_color="transparent")
        self.cards_frame.pack(fill="x", pady=(0, 14))
        self._build_stat_cards()

        # IP table label
        ctk.CTkLabel(
            left, text="⚠  Flagged IPs",
            font=ctk.CTkFont("Segoe UI", 14, "bold"),
            text_color=COLOR_TEXT
        ).pack(anchor="w", pady=(0, 6))

        # Table header
        header = ctk.CTkFrame(left, fg_color=COLOR_BORDER, corner_radius=6, height=34)
        header.pack(fill="x")
        header.pack_propagate(False)
        for col, w in [("IP Address", 160), ("Failures", 80), ("Severity", 100), ("Targeted Users", 180), ("Last Seen", 160)]:
            ctk.CTkLabel(
                header, text=col, width=w,
                font=ctk.CTkFont("Segoe UI", 11, "bold"),
                text_color=COLOR_MUTED, anchor="w"
            ).pack(side="left", padx=10)

        # Scrollable table
        self.table_scroll = ctk.CTkScrollableFrame(left, fg_color=COLOR_CARD, corner_radius=8)
        self.table_scroll.pack(fill="both", expand=True, pady=(4, 0))

        # Right column — log preview
        right = ctk.CTkFrame(body, fg_color=COLOR_CARD, corner_radius=10, width=300)
        right.pack(side="right", fill="y", padx=(16, 0))
        right.pack_propagate(False)

        ctk.CTkLabel(
            right, text="✅  Accepted Logins",
            font=ctk.CTkFont("Segoe UI", 13, "bold"),
            text_color=COLOR_SAFE
        ).pack(anchor="w", padx=14, pady=(14, 6))

        self.accepted_box = ctk.CTkTextbox(
            right, fg_color="transparent",
            text_color=COLOR_MUTED,
            font=ctk.CTkFont("Courier New", 11),
            wrap="word"
        )
        self.accepted_box.pack(fill="both", expand=True, padx=8, pady=(0, 14))
        self.accepted_box.insert("end", "Load a log file to see results…")
        self.accepted_box.configure(state="disabled")

        # Status bar
        self.status_var = ctk.StringVar(value="Ready — load an auth.log file to begin")
        ctk.CTkLabel(
            self, textvariable=self.status_var,
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=COLOR_MUTED
        ).pack(side="bottom", anchor="w", padx=22, pady=6)

    def _build_stat_cards(self):
        for w in self.cards_frame.winfo_children():
            w.destroy()

        cards = [
            ("Total Lines",       str(self._stats.get("total_lines", "—")),       COLOR_INFO),
            ("Failed Attempts",   str(self._stats.get("failed_attempts", "—")),   COLOR_WARNING),
            ("Unique Source IPs", str(self._stats.get("unique_ips", "—")),        COLOR_TEXT),
            ("🚨 Brute Force IPs", str(self._stats.get("brute_ips", "—")),        COLOR_CRITICAL),
            ("Accepted Logins",   str(self._stats.get("accepted", "—")),          COLOR_SAFE),
        ]

        for label, value, color in cards:
            card = ctk.CTkFrame(self.cards_frame, fg_color=COLOR_CARD, corner_radius=10)
            card.pack(side="left", expand=True, fill="both", padx=(0, 10))
            ctk.CTkLabel(card, text=value,
                         font=ctk.CTkFont("Segoe UI", 26, "bold"),
                         text_color=color).pack(padx=14, pady=(12, 2))
            ctk.CTkLabel(card, text=label,
                         font=ctk.CTkFont("Segoe UI", 10),
                         text_color=COLOR_MUTED).pack(padx=14, pady=(0, 10))

    # ── FILE LOADING ─────────────────────────
    def _load_file(self):
        path = filedialog.askopenfilename(
            title="Select auth.log file",
            filetypes=[("Log files", "*.log"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            self._ip_summary, self._accepted, self._stats = parse_log(path)
            self._refresh_ui()
            self.status_var.set(f"Loaded: {os.path.basename(path)}  |  {datetime.now().strftime('%H:%M:%S')}")
        except Exception as e:
            messagebox.showerror("Parse Error", str(e))

    # ── REFRESH UI ───────────────────────────
    def _refresh_ui(self):
        self._build_stat_cards()
        self._populate_table()
        self._populate_accepted()

    def _populate_table(self):
        for w in self.table_scroll.winfo_children():
            w.destroy()

        if not self._ip_summary:
            ctk.CTkLabel(
                self.table_scroll, text="No failed login attempts found.",
                text_color=COLOR_MUTED
            ).pack(pady=20)
            return

        for row in self._ip_summary:
            sev = row["severity"]
            color = COLOR_CRITICAL if sev == "CRITICAL" else (COLOR_WARNING if sev == "HIGH" else COLOR_INFO)

            row_frame = ctk.CTkFrame(
                self.table_scroll,
                fg_color=COLOR_BG if self._ip_summary.index(row) % 2 == 0 else COLOR_CARD,
                corner_radius=4, height=36
            )
            row_frame.pack(fill="x", pady=1)
            row_frame.pack_propagate(False)

            # IP
            ctk.CTkLabel(row_frame, text=row["ip"], width=160,
                         font=ctk.CTkFont("Courier New", 12),
                         text_color=COLOR_TEXT, anchor="w").pack(side="left", padx=10)
            # Failures
            ctk.CTkLabel(row_frame, text=str(row["failures"]), width=80,
                         font=ctk.CTkFont("Segoe UI", 12, "bold"),
                         text_color=color, anchor="w").pack(side="left")
            # Severity badge
            badge = ctk.CTkLabel(row_frame, text=f"  {sev}  ", width=100,
                                  font=ctk.CTkFont("Segoe UI", 10, "bold"),
                                  fg_color=color, text_color="#000000",
                                  corner_radius=4)
            badge.pack(side="left", padx=4, pady=6)
            # Users
            ctk.CTkLabel(row_frame, text=row["users"], width=180,
                         font=ctk.CTkFont("Segoe UI", 11),
                         text_color=COLOR_MUTED, anchor="w").pack(side="left", padx=8)
            # Last seen
            ctk.CTkLabel(row_frame, text=row["last_seen"],
                         font=ctk.CTkFont("Segoe UI", 11),
                         text_color=COLOR_MUTED, anchor="w").pack(side="left", padx=8)

    def _populate_accepted(self):
        self.accepted_box.configure(state="normal")
        self.accepted_box.delete("1.0", "end")
        if not self._accepted:
            self.accepted_box.insert("end", "No accepted logins found.")
        else:
            for entry in self._accepted:
                self.accepted_box.insert(
                    "end",
                    f"✓  {entry['user']}\n"
                    f"   {entry['ip']}\n"
                    f"   {entry['time']}\n\n"
                )
        self.accepted_box.configure(state="disabled")

    # ── EXPORT ───────────────────────────────
    def _export(self):
        if not self._ip_summary:
            messagebox.showwarning("No Data", "Load a log file first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="log_analysis_report.csv"
        )
        if path:
            export_csv(self._ip_summary, path)
            messagebox.showinfo("Exported", f"Report saved to:\n{path}")


# ──────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────
if __name__ == "__main__":
    app = LogAnalyzerApp()
    app.mainloop()
