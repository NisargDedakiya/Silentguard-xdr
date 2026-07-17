"""SilentGuard Console — native desktop admin app (Tkinter).

A window that connects to a SilentGuard server and gives you the operator console
— Fleet, Threats, Blocklist, and Account/Members — instead of opening a browser.
Not imported by the unit tests (which target the API client).
"""
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .api_client import ApiClient, ApiError

BG = "#0b1120"
CARD = "#0f172a"
FG = "#e2e8f0"
ACCENT = "#34d399"
MUTED = "#64748b"


class ConsoleApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.api: ApiClient | None = None
        root.title("SilentGuard Console")
        root.configure(bg=BG)
        root.geometry("1000x680")
        self._build_login()

    # -- login ------------------------------------------------------------
    def _build_login(self):
        self.frame = tk.Frame(self.root, bg=BG)
        self.frame.pack(fill="both", expand=True)
        box = tk.Frame(self.frame, bg=CARD, padx=28, pady=24)
        box.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(box, text="SilentGuard Console", fg=ACCENT, bg=CARD,
                 font=("Segoe UI", 18, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 12))
        self.vars = {}
        for i, (key, label, default, show) in enumerate([
            ("url", "Server URL", "http://127.0.0.1:8000", ""),
            ("email", "Email (or leave blank for admin token)", "", ""),
            ("password", "Password", "", "*"),
            ("token", "Admin key or token (optional)", "", "*"),
        ], start=1):
            tk.Label(box, text=label, fg=FG, bg=CARD, anchor="w").grid(row=i, column=0, sticky="w")
            v = tk.StringVar(value=default)
            tk.Entry(box, textvariable=v, width=34, show=show).grid(row=i, column=1, pady=3)
            self.vars[key] = v
        self.login_err = tk.Label(box, text="", fg="#f87171", bg=CARD)
        self.login_err.grid(row=6, column=0, columnspan=2)
        tk.Button(box, text="Connect", command=self._connect, bg=ACCENT, fg="#04121a",
                  font=("Segoe UI", 10, "bold"), relief="flat", padx=16, pady=6
                  ).grid(row=7, column=0, columnspan=2, pady=(10, 0))

    def _connect(self):
        url = self.vars["url"].get().strip()
        if not url:
            self.login_err.config(text="Enter the server URL")
            return
        api = ApiClient(url)
        try:
            key = self.vars["token"].get().strip()
            if key.startswith("sgk_"):
                api.login_key(key)                 # org admin key from provisioning
            elif key:
                api.login_admin(key)               # legacy platform admin token
            elif self.vars["email"].get().strip():
                api.login_user(self.vars["email"].get().strip(), self.vars["password"].get())
            else:
                self.login_err.config(text="Enter an admin token or email/password")
                return
        except ApiError as exc:
            self.login_err.config(text=f"Login failed: {exc.message}")
            return
        self.api = api
        self.frame.destroy()
        self._build_main()
        self.refresh()

    # -- main console -----------------------------------------------------
    def _build_main(self):
        top = tk.Frame(self.root, bg=BG)
        top.pack(fill="x", padx=12, pady=8)
        tk.Label(top, text="SilentGuard Console", fg=ACCENT, bg=BG,
                 font=("Segoe UI", 15, "bold")).pack(side="left")
        self.plan_lbl = tk.Label(top, text="", fg=MUTED, bg=BG)
        self.plan_lbl.pack(side="left", padx=12)
        tk.Button(top, text="Refresh", command=self.refresh, bg="#1e293b", fg=FG,
                  relief="flat", padx=12).pack(side="right")

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.trees = {}
        self.trees["fleet"] = self._tab("Fleet",
                                        ("hostname", "platform", "status", "risk", "isolated"))
        self.trees["threats"] = self._tab("Threats",
                                          ("time", "severity", "rule", "device"))
        self._build_blocklist_tab()
        self._build_account_tab()

    def _tab(self, name, cols):
        f = tk.Frame(self.nb, bg=BG)
        self.nb.add(f, text=name)
        tree = ttk.Treeview(f, columns=cols, show="headings")
        for c in cols:
            tree.heading(c, text=c.title())
            tree.column(c, width=160)
        tree.pack(fill="both", expand=True)
        return tree

    def _build_blocklist_tab(self):
        f = tk.Frame(self.nb, bg=BG)
        self.nb.add(f, text="Blocklist")
        bar = tk.Frame(f, bg=BG)
        bar.pack(fill="x", pady=6)
        self.bl_kind = ttk.Combobox(bar, values=["domain", "process", "port"],
                                    width=10, state="readonly")
        self.bl_kind.set("domain")
        self.bl_kind.pack(side="left")
        self.bl_value = tk.Entry(bar, width=32)
        self.bl_value.pack(side="left", padx=6)
        tk.Button(bar, text="Block", command=self._add_block, bg=ACCENT, fg="#04121a",
                  relief="flat", padx=12).pack(side="left")
        tk.Button(bar, text="Remove selected", command=self._remove_block, bg="#1e293b",
                  fg=FG, relief="flat", padx=12).pack(side="left", padx=6)
        tree = ttk.Treeview(f, columns=("id", "kind", "value"), show="headings")
        for c in ("id", "kind", "value"):
            tree.heading(c, text=c.title())
        tree.pack(fill="both", expand=True)
        self.trees["blocklist"] = tree

    def _build_account_tab(self):
        f = tk.Frame(self.nb, bg=BG)
        self.nb.add(f, text="Account")
        self.account_lbl = tk.Label(f, text="", fg=FG, bg=BG, justify="left",
                                    font=("Consolas", 10))
        self.account_lbl.pack(anchor="w", padx=8, pady=8)
        bar = tk.Frame(f, bg=BG)
        bar.pack(fill="x")
        self.inv_email = tk.Entry(bar, width=26)
        self.inv_email.pack(side="left")
        self.inv_role = ttk.Combobox(bar, values=["read_only", "analyst", "responder",
                                                  "threat_hunter", "soc_manager", "auditor"],
                                     width=13, state="readonly")
        self.inv_role.set("read_only")
        self.inv_role.pack(side="left", padx=6)
        tk.Button(bar, text="Invite member", command=self._invite, bg=ACCENT, fg="#04121a",
                  relief="flat", padx=12).pack(side="left")
        tree = ttk.Treeview(f, columns=("email", "role", "active"), show="headings")
        for c in ("email", "role", "active"):
            tree.heading(c, text=c.title())
        tree.pack(fill="both", expand=True, pady=8)
        self.trees["members"] = tree

    # -- data -------------------------------------------------------------
    def refresh(self):
        threading.Thread(target=self._refresh_worker, daemon=True).start()

    def _refresh_worker(self):
        try:
            ent = self.api.entitlements()
            devices = self.api.devices()
            detections = self.api.detections()
            blocklist = self.api.blocklist()
            members = self._try(self.api.members) or []
        except ApiError as exc:
            self.root.after(0, lambda: messagebox.showerror("Error", exc.message))
            return
        self.root.after(0, lambda: self._render(ent, devices, detections, blocklist, members))

    def _try(self, fn):
        try:
            return fn()
        except ApiError:
            return None

    def _render(self, ent, devices, detections, blocklist, members):
        self.plan_lbl.config(text=f"Plan: {ent.get('plan', '?').title()}")
        self._fill(self.trees["fleet"], [
            (d.get("hostname"), d.get("platform"), "online" if d.get("online") else "offline",
             d.get("risk_score", d.get("risk", "")), "yes" if d.get("isolated") else "no")
            for d in devices])
        self._fill(self.trees["threats"], [
            (d.get("created_at", "")[:19], d.get("severity"), d.get("rule_id"),
             d.get("hostname") or d.get("device_id", "")[:8]) for d in detections])
        self._fill(self.trees["blocklist"], [
            (b.get("id"), b.get("kind"), b.get("value")) for b in blocklist])
        self._fill(self.trees["members"], [
            (m.get("email"), m.get("role"), "yes" if m.get("is_active") else "no")
            for m in members])
        feats = ", ".join(k for k in ("rbac", "device_groups", "integrations",
                                      "compliance_reports", "sso", "ai_assistant") if ent.get(k))
        self.account_lbl.config(
            text=f"Plan: {ent.get('plan')}   Devices: {ent.get('max_devices') or 'unlimited'}   "
                 f"Members: {ent.get('max_users') or 'unlimited'}\nUnlocked: {feats}")

    def _fill(self, tree, rows):
        tree.delete(*tree.get_children())
        for r in rows:
            tree.insert("", "end", values=r)

    # -- actions ----------------------------------------------------------
    def _add_block(self):
        val = self.bl_value.get().strip()
        if not val:
            return
        try:
            self.api.add_block(self.bl_kind.get(), val)
        except ApiError as exc:
            messagebox.showerror("Cannot block", exc.message)
            return
        self.bl_value.delete(0, tk.END)
        self.refresh()

    def _remove_block(self):
        sel = self.trees["blocklist"].selection()
        if not sel:
            return
        entry_id = self.trees["blocklist"].item(sel[0])["values"][0]
        try:
            self.api.remove_block(int(entry_id))
        except (ApiError, ValueError) as exc:
            messagebox.showerror("Cannot remove", str(exc))
            return
        self.refresh()

    def _invite(self):
        email = self.inv_email.get().strip()
        if not email:
            return
        try:
            resp = self.api.invite(email, self.inv_role.get())
        except ApiError as exc:
            messagebox.showerror("Cannot invite", exc.message)
            return
        token = resp.get("invite_token")
        msg = f"Invited {email}." + (f"\nInvite token: {token}" if token else "")
        messagebox.showinfo("Invited", msg)
        self.inv_email.delete(0, tk.END)
        self.refresh()


def run():
    root = tk.Tk()
    ConsoleApp(root)
    root.mainloop()
