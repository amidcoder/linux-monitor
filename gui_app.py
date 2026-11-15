import base64
import hashlib
import json
import logging
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import paramiko

from checker import check_server
from config import ConfigError, _parse_server, load_config
from logger_setup import setup_logger
from main import server_loop

APP_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
os.chdir(APP_DIR)
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
KNOWN_HOSTS = os.path.join(os.path.expanduser("~"), ".ssh", "known_hosts")

DEFAULT_DATA = {"ping_timeout_seconds": 3, "ssh_timeout_seconds": 10,
                "log_file": "logs/monitor.log", "servers": []}


class QueueHandler(logging.Handler):
    def __init__(self, q):
        super().__init__()
        self.q = q
        self.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s",
                                            "%Y-%m-%d %H:%M:%S"))

    def emit(self, record):
        self.q.put((record.levelname, self.format(record)))


def load_data() -> dict:
    if not os.path.isfile(CONFIG_PATH):
        return json.loads(json.dumps(DEFAULT_DATA))
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    for k, v in DEFAULT_DATA.items():
        data.setdefault(k, v)
    return data


def save_data(data: dict):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def fetch_host_key(host: str, port: int, timeout: int = 10):
    t = paramiko.Transport((host, port))
    try:
        t.banner_timeout = timeout
        t.start_client(timeout=timeout)
        return t.get_remote_server_key()
    finally:
        t.close()


def fingerprint(key) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def trust_host(host: str, port: int, parent):
    try:
        key = fetch_host_key(host, port)
    except Exception as e:
        messagebox.showerror("خطا", f"دریافت host key ممکن نشد:\n{e}", parent=parent)
        return
    fp = fingerprint(key)
    ok = messagebox.askyesno(
        "تأیید host key",
        f"سرور: {host}:{port}\nنوع: {key.get_name()}\nFingerprint:\n{fp}\n\n"
        "این مقدار را با fingerprint واقعی سرور (مثلاً از کنسول سرور با\n"
        "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub) مقایسه کنید.\n\n"
        "به known_hosts اضافه شود؟", parent=parent)
    if not ok:
        return
    os.makedirs(os.path.dirname(KNOWN_HOSTS), exist_ok=True)
    hk = paramiko.HostKeys()
    if os.path.isfile(KNOWN_HOSTS):
        hk.load(KNOWN_HOSTS)
    name = host if port == 22 else f"[{host}]:{port}"
    hk.add(name, key.get_name(), key)
    hk.save(KNOWN_HOSTS)
    messagebox.showinfo("انجام شد", "host key ذخیره شد.", parent=parent)


class ServerDialog(tk.Toplevel):
    def __init__(self, parent, initial=None):
        super().__init__(parent)
        self.title("مشخصات سرور")
        self.resizable(False, False)
        self.transient(parent)
        self.result = None
        i = initial or {}
        auth = i.get("auth", {})
        th = i.get("thresholds", {})

        self.v = {
            "name": tk.StringVar(value=i.get("name", "")),
            "host": tk.StringVar(value=i.get("host", "")),
            "port": tk.StringVar(value=str(i.get("port", 22))),
            "username": tk.StringVar(value=i.get("username", "")),
            "method": tk.StringVar(value=auth.get("method", "password")),
            "key_path": tk.StringVar(value=auth.get("key_path", "")),
            "key_env": tk.StringVar(value=auth.get("key_passphrase_env", "")),
            "pw_env": tk.StringVar(value=auth.get("password_env", "")),
            "secret": tk.StringVar(),
            "persist": tk.BooleanVar(value=False),
            "interval": tk.StringVar(value=str(i.get("interval_minutes", 5))),
            "cpu": tk.StringVar(value=str(th.get("cpu", 90))),
            "ram": tk.StringVar(value=str(th.get("ram", 90))),
            "disk": tk.StringVar(value=str(th.get("disk", 85))),
        }
        f = ttk.Frame(self, padding=12)
        f.grid()
        r = 0

        def row(label, widget):
            nonlocal r
            ttk.Label(f, text=label).grid(row=r, column=0, sticky="w", pady=3, padx=(0, 8))
            widget.grid(row=r, column=1, sticky="we", pady=3)
            r += 1
            return widget

        row("نام سرور", ttk.Entry(f, textvariable=self.v["name"], width=34))
        row("آدرس IP / هاست", ttk.Entry(f, textvariable=self.v["host"]))
        row("پورت SSH", ttk.Entry(f, textvariable=self.v["port"], width=8))
        row("نام کاربری", ttk.Entry(f, textvariable=self.v["username"]))
        row("فاصله بررسی (دقیقه)", ttk.Combobox(f, textvariable=self.v["interval"], width=8,
                                                values=["1", "5", "15", "30", "60"]))

        mf = ttk.Frame(f)
        ttk.Radiobutton(mf, text="رمز عبور", value="password", variable=self.v["method"],
                        command=self._toggle).pack(side="left")
        ttk.Radiobutton(mf, text="کلید خصوصی", value="key", variable=self.v["method"],
                        command=self._toggle).pack(side="left", padx=10)
        row("روش احراز هویت", mf)

        self.pw_frame = ttk.Frame(f)
        ttk.Entry(self.pw_frame, textvariable=self.v["pw_env"], width=34).grid(row=0, column=0)
        self.key_frame = ttk.Frame(f)
        ttk.Entry(self.key_frame, textvariable=self.v["key_path"], width=27).grid(row=0, column=0)
        ttk.Button(self.key_frame, text="...", width=3, command=self._browse).grid(row=0, column=1)
        self.pw_lbl = ttk.Label(f, text="نام متغیر محیطی رمز")
        self.key_lbl = ttk.Label(f, text="مسیر کلید خصوصی")
        self.pw_lbl.grid(row=r, column=0, sticky="w")
        self.pw_frame.grid(row=r, column=1, sticky="we", pady=3)
        self.key_lbl.grid(row=r, column=0, sticky="w")
        self.key_frame.grid(row=r, column=1, sticky="we", pady=3)
        r += 1
        self.kenv_lbl = ttk.Label(f, text="متغیر محیطی passphrase (اختیاری)")
        self.kenv_ent = ttk.Entry(f, textvariable=self.v["key_env"])
        self.kenv_lbl.grid(row=r, column=0, sticky="w")
        self.kenv_ent.grid(row=r, column=1, sticky="we", pady=3)
        r += 1

        row("مقدار رمز/passphrase (فقط حافظه)", ttk.Entry(f, textvariable=self.v["secret"], show="*"))
        ttk.Checkbutton(f, text="ذخیرهٔ دائمی در متغیر محیطی کاربر ویندوز (setx)",
                        variable=self.v["persist"]).grid(row=r, column=1, sticky="w")
        r += 1

        tf = ttk.LabelFrame(f, text="آستانه بحرانی (٪)", padding=6)
        for c, (k, lbl) in enumerate((("cpu", "CPU"), ("ram", "RAM"), ("disk", "Disk"))):
            ttk.Label(tf, text=lbl).grid(row=0, column=c * 2, padx=(6, 2))
            ttk.Entry(tf, textvariable=self.v[k], width=5).grid(row=0, column=c * 2 + 1)
        tf.grid(row=r, column=0, columnspan=2, sticky="we", pady=8)
        r += 1

        bf = ttk.Frame(f)
        ttk.Button(bf, text="ذخیره", command=self._ok).pack(side="left", padx=4)
        ttk.Button(bf, text="انصراف", command=self.destroy).pack(side="left", padx=4)
        bf.grid(row=r, column=0, columnspan=2)

        self._toggle()
        self.grab_set()
        self.wait_window(self)

    def _toggle(self):
        key = self.v["method"].get() == "key"
        for w in (self.key_lbl, self.key_frame, self.kenv_lbl, self.kenv_ent):
            w.grid() if key else w.grid_remove()
        for w in (self.pw_lbl, self.pw_frame):
            w.grid_remove() if key else w.grid()

    def _browse(self):
        p = filedialog.askopenfilename(parent=self, initialdir=os.path.expanduser("~/.ssh"))
        if p:
            self.v["key_path"].set(p)

    def _ok(self):
        v = {k: x.get().strip() if isinstance(x.get(), str) else x.get() for k, x in self.v.items()}
        try:
            raw = {"name": v["name"], "host": v["host"],
                   "port": int(v["port"] or 22), "username": v["username"],
                   "interval_minutes": float(v["interval"]),
                   "thresholds": {k: float(v[k]) for k in ("cpu", "ram", "disk")}}
            if raw["interval_minutes"].is_integer():
                raw["interval_minutes"] = int(raw["interval_minutes"])
            if v["method"] == "key":
                raw["auth"] = {"method": "key", "key_path": v["key_path"]}
                if v["key_env"]:
                    raw["auth"]["key_passphrase_env"] = v["key_env"]
                env = v["key_env"]
            else:
                raw["auth"] = {"method": "password", "password_env": v["pw_env"]}
                env = v["pw_env"]
            _parse_server(raw, 0)
        except (ConfigError, ValueError, TypeError) as e:
            messagebox.showerror("ورودی نامعتبر", str(e), parent=self)
            return
        if v["secret"]:
            if not env:
                messagebox.showerror("ورودی نامعتبر", "ابتدا نام متغیر محیطی را وارد کنید.", parent=self)
                return
            os.environ[env] = v["secret"]
            if v["persist"]:
                try:
                    subprocess.run(["setx", env, v["secret"]], check=True, capture_output=True,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                except Exception as e:
                    messagebox.showwarning("هشدار", f"setx ناموفق بود: {e}", parent=self)
        self.result = raw
        self.destroy()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("مانیتور سرورهای Linux")
        self.geometry("960x620")
        self.data = load_data()
        self.q = queue.Queue()
        self.stop_evt = None
        self.threads = []
        self.log = None

        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        cols = ("name", "host", "port", "user", "auth", "interval")
        heads = ("نام", "آدرس", "پورت", "کاربر", "احراز هویت", "فاصله (دقیقه)")
        self.tree = ttk.Treeview(top, columns=cols, show="headings", height=7, selectmode="browse")
        for c, h in zip(cols, heads):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=130 if c in ("name", "host") else 90, anchor="center")
        self.tree.pack(side="left", fill="x", expand=True)
        self.tree.bind("<Double-1>", lambda e: self.edit())

        bf = ttk.Frame(top)
        bf.pack(side="left", padx=8, anchor="n")
        for text, cmd in (("افزودن", self.add), ("ویرایش", self.edit), ("حذف", self.delete),
                          ("اعتماد به host key", self.trust), ("بررسی فوری", self.test_now)):
            ttk.Button(bf, text=text, command=cmd, width=18).pack(pady=2)

        mid = ttk.Frame(self, padding=(8, 0))
        mid.pack(fill="x")
        self.ping_t = tk.StringVar(value=str(self.data["ping_timeout_seconds"]))
        self.ssh_t = tk.StringVar(value=str(self.data["ssh_timeout_seconds"]))
        ttk.Label(mid, text="Timeout پینگ (ثانیه):").pack(side="left")
        ttk.Entry(mid, textvariable=self.ping_t, width=4).pack(side="left", padx=4)
        ttk.Label(mid, text="Timeout SSH (ثانیه):").pack(side="left", padx=(10, 0))
        ttk.Entry(mid, textvariable=self.ssh_t, width=4).pack(side="left", padx=4)
        self.status = ttk.Label(mid, text="● متوقف", foreground="gray")
        self.status.pack(side="right")
        self.toggle_btn = ttk.Button(mid, text="شروع مانیتورینگ", command=self.toggle)
        self.toggle_btn.pack(side="right", padx=8)

        lf = ttk.Frame(self, padding=8)
        lf.pack(fill="both", expand=True)
        self.text = tk.Text(lf, state="disabled", wrap="none", font=("Consolas", 10))
        sb = ttk.Scrollbar(lf, command=self.text.yview)
        self.text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.text.pack(fill="both", expand=True)
        self.text.tag_config("INFO", foreground="#1a7f37")
        self.text.tag_config("WARNING", foreground="#b35900")
        self.text.tag_config("ERROR", foreground="#c62828")

        self.refresh()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(200, self.poll)

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for s in self.data["servers"]:
            a = s.get("auth", {})
            self.tree.insert("", "end", values=(
                s.get("name"), s.get("host"), s.get("port", 22), s.get("username"),
                "کلید" if a.get("method") == "key" else "رمز", s.get("interval_minutes")))

    def selected(self):
        sel = self.tree.selection()
        return self.tree.index(sel[0]) if sel else None

    def persist(self):
        try:
            self.data["ping_timeout_seconds"] = max(1, int(self.ping_t.get()))
            self.data["ssh_timeout_seconds"] = max(1, int(self.ssh_t.get()))
        except ValueError:
            messagebox.showerror("خطا", "Timeout باید عدد صحیح باشد.")
            return False
        save_data(self.data)
        return True

    def add(self):
        d = ServerDialog(self)
        if d.result:
            self.data["servers"].append(d.result)
            self.persist()
            self.refresh()

    def edit(self):
        i = self.selected()
        if i is None:
            return
        d = ServerDialog(self, self.data["servers"][i])
        if d.result:
            self.data["servers"][i] = d.result
            self.persist()
            self.refresh()

    def delete(self):
        i = self.selected()
        if i is not None and messagebox.askyesno("حذف", "این سرور حذف شود؟"):
            del self.data["servers"][i]
            self.persist()
            self.refresh()

    def trust(self):
        i = self.selected()
        if i is not None:
            s = self.data["servers"][i]
            trust_host(s["host"], int(s.get("port", 22)), self)

    def test_now(self):
        i = self.selected()
        if i is None:
            return
        if not self.persist():
            return
        self.ensure_logger()
        try:
            srv = _parse_server(self.data["servers"][i], i)
        except (ConfigError, ValueError, TypeError) as e:
            messagebox.showerror("خطا", str(e))
            return
        threading.Thread(target=check_server, daemon=True,
                         args=(srv, self.data["ping_timeout_seconds"],
                               self.data["ssh_timeout_seconds"])).start()

    def ensure_logger(self):
        if self.log is None:
            self.log = setup_logger(self.data["log_file"])
            self.log.addHandler(QueueHandler(self.q))

    def toggle(self):
        if self.stop_evt is None:
            self.start()
        else:
            self.stop()

    def start(self):
        if any(t.is_alive() for t in self.threads):
            messagebox.showinfo("صبر کنید", "بررسی‌های قبلی هنوز در حال پایان‌اند.")
            return
        if not self.persist():
            return
        try:
            settings = load_config(CONFIG_PATH)
        except ConfigError as e:
            messagebox.showerror("خطای کانفیگ", str(e))
            return
        self.ensure_logger()
        for label, err in settings.errors:
            self.log.error("تنظیمات سرور '%s' نامعتبر است و نادیده گرفته شد: %s", label, err)
        if not settings.servers:
            messagebox.showwarning("بدون سرور", "هیچ سرور معتبری تعریف نشده است.")
            return
        self.stop_evt = threading.Event()
        self.threads = [threading.Thread(target=server_loop, name=s.name, daemon=True,
                                         args=(s, settings, self.stop_evt, self.log))
                        for s in settings.servers]
        for t in self.threads:
            t.start()
        self.log.info("مانیتورینگ %d سرور شروع شد", len(self.threads))
        self.toggle_btn.config(text="توقف مانیتورینگ")
        self.status.config(text="● در حال اجرا", foreground="#1a7f37")

    def stop(self):
        if self.stop_evt:
            self.stop_evt.set()
            self.stop_evt = None
            if self.log:
                self.log.info("مانیتورینگ متوقف شد (بررسی‌های در حال انجام تمام می‌شوند)")
        self.toggle_btn.config(text="شروع مانیتورینگ")
        self.status.config(text="● متوقف", foreground="gray")

    def poll(self):
        try:
            while True:
                level, msg = self.q.get_nowait()
                self.text.config(state="normal")
                self.text.insert("end", msg + "\n", level)
                if int(self.text.index("end-1c").split(".")[0]) > 2000:
                    self.text.delete("1.0", "500.0")
                self.text.config(state="disabled")
                self.text.see("end")
        except queue.Empty:
            pass
        self.after(200, self.poll)

    def on_close(self):
        self.stop()
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
