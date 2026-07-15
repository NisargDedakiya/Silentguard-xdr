"""SilentGuard Home — desktop GUI (Tkinter, standard library).

A simple window to protect this one PC: see status, manage the blocklist, and
start/stop protection. Kept intentionally minimal so it packages into a small
.exe. Not imported by the unit tests (which target the enforcement engine).
"""
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .blocklist import KINDS, Blocklist
from .engine import ProtectionEngine
from .privileges import is_elevated

BG = "#0b1120"
FG = "#e2e8f0"
ACCENT = "#34d399"
MUTED = "#64748b"


class HomeApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.blocklist = Blocklist()
        self.engine = ProtectionEngine(self.blocklist)
        self.elevated = is_elevated()

        root.title("SilentGuard Home")
        root.configure(bg=BG)
        root.geometry("640x560")

        tk.Label(root, text="SilentGuard Home", fg=ACCENT, bg=BG,
                 font=("Segoe UI", 20, "bold")).pack(pady=(16, 2))
        tk.Label(root, text="Protect this PC", fg=MUTED, bg=BG,
                 font=("Segoe UI", 10)).pack()

        self.status = tk.Label(root, text="", fg=FG, bg=BG, font=("Segoe UI", 12, "bold"))
        self.status.pack(pady=8)

        btns = tk.Frame(root, bg=BG)
        btns.pack(pady=4)
        self.toggle_btn = tk.Button(btns, text="Turn on protection", command=self.toggle,
                                    bg=ACCENT, fg="#04121a", font=("Segoe UI", 10, "bold"),
                                    relief="flat", padx=16, pady=6)
        self.toggle_btn.pack()

        # Add-entry row
        add = tk.Frame(root, bg=BG)
        add.pack(pady=(18, 4), fill="x", padx=20)
        self.kind = ttk.Combobox(add, values=list(KINDS), width=9, state="readonly")
        self.kind.set("domain")
        self.kind.pack(side="left")
        self.value = tk.Entry(add, width=32)
        self.value.pack(side="left", padx=6)
        self.value.insert(0, "e.g. youtube.com")
        tk.Button(add, text="Block", command=self.add_entry, bg="#1e293b", fg=FG,
                  relief="flat", padx=12).pack(side="left")

        # Blocklist
        self.listbox = tk.Listbox(root, bg="#0f172a", fg=FG, height=12,
                                  selectbackground="#334155", relief="flat")
        self.listbox.pack(fill="both", expand=True, padx=20, pady=8)
        tk.Button(root, text="Remove selected", command=self.remove_entry, bg="#1e293b",
                  fg=FG, relief="flat", padx=12).pack(pady=(0, 12))

        self.refresh()
        if not self.elevated:
            messagebox.showwarning(
                "Administrator needed",
                "SilentGuard Home is not running as Administrator, so blocking "
                "cannot take effect. Close it and choose 'Run as administrator'.")

    # -- actions ----------------------------------------------------------
    def refresh(self) -> None:
        self.listbox.delete(0, tk.END)
        for e in self.blocklist.entries():
            self.listbox.insert(tk.END, f"{e['kind']:>8}   {e['value']}")
        on = self.engine._running
        state = "ON" if on else "OFF"
        color = ACCENT if on else MUTED
        priv = "" if self.elevated else "  (needs Administrator!)"
        self.status.config(text=f"Protection: {state}{priv}", fg=color)
        self.toggle_btn.config(text="Turn off protection" if on else "Turn on protection")

    def toggle(self) -> None:
        if self.engine._running:
            self.engine.stop()
        else:
            self.engine.start(interval=30.0)
            threading.Thread(target=self.engine.sync, daemon=True).start()
        self.refresh()

    def add_entry(self) -> None:
        val = self.value.get().strip()
        if not val or val.startswith("e.g."):
            return
        try:
            self.blocklist.add(self.kind.get(), val)
        except ValueError as exc:
            messagebox.showerror("Invalid entry", str(exc))
            return
        self.value.delete(0, tk.END)
        if self.engine._running:
            threading.Thread(target=self.engine.sync, daemon=True).start()
        self.refresh()

    def remove_entry(self) -> None:
        sel = self.listbox.curselection()
        if not sel:
            return
        kind, value = self.listbox.get(sel[0]).split(None, 1)
        self.blocklist.remove(kind, value.strip())
        if self.engine._running:
            threading.Thread(target=self.engine.sync, daemon=True).start()
        self.refresh()


def run() -> None:
    root = tk.Tk()
    HomeApp(root)
    root.mainloop()
