"""通用图形界面骨架：设备选择 + 连接配置 + 单 IP 操作 + 批量导入 + 日志。

各厂商差异由 DriverSpec 描述，协议交互由传入的客户端类负责；传入设备清单后
窗口顶部出现选择条，切换设备只重建界面，不新开窗口（一套 GUI 服务所有设备）。
客户端需要提供：

- `authenticated`（属性）：是否已登录
- `login()` / `logout()` / `test_connection()`
- `entries(ip)`：查单 IP 的匹配条目（列表，空表示未封禁）
- `block(ip, desc="")` / `unblock(ip)`：返回可读结果文本，已存在/不存在时含「跳过」
- `list_entries()`：仅当 `support_list=True` 时调用，返回可直接填表的行
"""

from __future__ import annotations

import os
import queue
import threading
import time
from dataclasses import dataclass, field

from . import secret_store
from .common import LOG_DIR_NAME, UI_LINE_LIMIT, ToolError, extract_ips

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk

    TK_AVAILABLE = True
except Exception:  # 无图形环境仍可导入本模块做脚本化调用
    TK_AVAILABLE = False


DEFAULT_TIMEOUT = 10.0
DEFAULT_DESC = "SenseMind联动封禁"


@dataclass
class DriverSpec:
    """厂商差异描述，GUI 按此渲染。"""

    key: str
    title: str
    default_url: str
    log_file: str
    hint: str = ""
    # (name, label, default) —— 额外配置字段，如深信服的命名空间
    extra_fields: tuple = field(default_factory=tuple)
    support_list: bool = False
    support_desc: bool = True
    list_title: str = "黑名单条目（设备侧）"
    list_columns: tuple = (
        ("ip", "IP", 160),
        ("type", "类型", 90),
        ("enable", "启用", 70),
        ("urltype", "urlType", 90),
        ("desc", "描述", 380),
    )


class LogSink:
    """日志出口：界面队列（超长截断）+ 脚本同目录文件（首次真实操作时才创建）。"""

    def __init__(self, path: str, ui_limit: int = UI_LINE_LIMIT):
        self.path = path
        self.ui_limit = ui_limit
        self.queue: queue.Queue[str] = queue.Queue()
        self.quiet = False

    def __call__(self, message: str, quiet: bool | None = None) -> None:
        """客户端与批量流程共用的日志入口。"""
        self.write(message, self.quiet if quiet is None else quiet)

    def banner(self, message: str) -> None:
        """只显示在界面，不写日志文件。

        启动与切换这类没有操作内容的提示走这里，避免一开程序就在磁盘上留一个空日志。
        日志文件在第一次真实操作（或报错）时才由 write() 创建（追加写入）。
        """
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        for line in str(message).splitlines() or [""]:
            if len(line) > self.ui_limit:
                line = f"{line[: self.ui_limit]} …（共 {len(line)} 字符）"
            self.queue.put(f"{stamp[11:]}  {line}")


    def write(self, message: str, quiet: bool = False) -> None:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        lines = str(message).splitlines() or [""]
        try:
            folder = os.path.dirname(self.path)
            if folder:
                os.makedirs(folder, exist_ok=True)   # 目录同样在首次真实操作时才创建
            with open(self.path, "a", encoding="utf-8") as fh:
                for line in lines:
                    fh.write(f"{stamp}  {line}\n")
        except OSError:
            pass
        if quiet and not any(token in str(message) for token in ("✗", "失败", "异常")):
            return
        for line in lines:
            if len(line) > self.ui_limit:
                line = f"{line[: self.ui_limit]} …（共 {len(line)} 字符，全文见日志文件）"
            self.queue.put(f"{stamp[11:]}  {line}")


class DeviceToolApp:
    """按 DriverSpec 渲染的通用界面。

    `devices` 传入设备清单（`kit.registry` 的 `DeviceEntry` 序列）时，窗口顶部显示
    设备选择条，切换设备复用同一窗口与同一套控件代码。
    """

    def __init__(self, root, spec: DriverSpec, client_factory, devices=None):
        self.root = root
        self.devices: tuple = tuple(devices or ())
        self.busy = False
        self.client = None
        self.client_key: tuple | None = None
        self.action_buttons: list = []
        self.batch_ips: list[str] = []
        self.stop_event = threading.Event()
        self.vars: dict = {}
        self.tree = None
        self.stop_btn = None
        self.picker = None
        self._load(spec, client_factory)
        self._build()
        self.root.after(120, self._drain_log)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._log_start()
        self._apply_saved()

    # ---------- 设备 ----------

    def _load(self, spec: DriverSpec, client_factory) -> None:
        """绑定一个设备：换 spec、客户端类与日志文件。"""
        self.spec = spec
        self.client_factory = client_factory
        entry = self._entry_of(spec.key)
        self.precheck = entry.precheck if entry is not None else None
        self.log = LogSink(os.path.join(entry_dir(), LOG_DIR_NAME, spec.log_file))
        self.secret_path = os.path.join(secret_store.config_dir(), f"{spec.key}.secrets")

    def _entry_of(self, key: str):
        for entry in self.devices:
            if entry.spec.key == key:
                return entry
        return None

    def _label_of(self, key: str) -> str:
        entry = self._entry_of(key)
        return entry.label if entry is not None else self.spec.title

    def _log_start(self) -> None:
        # 启动提示只上面板、不落文件：文件在首次真实操作或报错时才创建
        self.log.banner("=" * 62)
        self.log.banner(f"{self.spec.title}启动")
        self.log.banner(f"日志文件：{self.log.path}（追加写入，关掉界面也不丢）")
        if self.precheck is not None:
            try:
                ok = bool(self.precheck())
            except Exception:  # 自检本身出错不拦启动
                ok = True
            if not ok:
                self.log.write("[警告] 内置 AES 自检未通过，登录口令加密可能不可用")

    def on_switch_device(self, _event=None) -> None:
        label = self.picker.get()
        entry = next((e for e in self.devices if e.label == label), None)
        if entry is None or entry.spec.key == self.spec.key:
            return
        if self.busy:
            self.picker.set(self._label_of(self.spec.key))
            messagebox.showinfo("请稍候", "上一个操作尚未结束，完成后再切换设备")
            return
        # 等选择框的事件回调退出后再重建界面，避免销毁正在处理事件的控件
        self.root.after(10, lambda: self._switch_to(entry))

    def _switch_to(self, entry) -> None:
        if self.busy or entry.spec.key == self.spec.key:
            return
        self._drop_client()
        self._load(entry.spec, entry.client_factory)
        self.vars = {}
        self.action_buttons = []
        self.batch_ips = []
        self.tree = None
        self.stop_btn = None
        for child in self.root.winfo_children():
            child.destroy()
        self._build()
        self._log_start()
        self._apply_saved()

    def _drop_client(self) -> None:
        """丢弃当前会话：后台登出，留下连接配置值由界面重建。"""
        client, self.client, self.client_key = self.client, None, None
        if client is not None and getattr(client, "authenticated", False):
            threading.Thread(target=client.logout, daemon=True).start()

    # ---------- 界面 ----------

    def _var(self, name: str, value: str = "") -> tk.StringVar:
        var = tk.StringVar(value=value)
        self.vars[name] = var
        return var

    def _build_picker(self) -> None:
        """设备选择条：只有登记了多个设备时才出现。"""
        if len(self.devices) < 2:
            return
        bar = ttk.Frame(self.root)
        bar.pack(fill="x", padx=6, pady=(6, 0))
        ttk.Label(bar, text="设备类型").pack(side="left")
        self.picker = ttk.Combobox(
            bar, state="readonly", width=26, values=[entry.label for entry in self.devices]
        )
        self.picker.set(self._label_of(self.spec.key))
        self.picker.pack(side="left", padx=8)
        self.picker.bind("<<ComboboxSelected>>", self.on_switch_device)
        ttk.Label(bar, text="切换后按新设备重新登录，日志换新文件", foreground="#666666").pack(
            side="left", padx=8
        )

    def _build(self) -> None:
        spec = self.spec
        self.root.title(spec.title)
        height = 900 if spec.support_list else 860
        self.root.geometry(f"1000x{height}")
        self.root.minsize(900, 700)
        pad = {"padx": 6, "pady": 4}
        self._build_picker()
        parent = ttk.Frame(self.root)
        parent.pack(fill="both", expand=True)

        cfg = ttk.LabelFrame(parent, text="设备连接")
        cfg.pack(fill="x", **pad)
        row = 0
        ttk.Label(cfg, text="管理地址").grid(row=row, column=0, sticky="e", padx=6, pady=6)
        ttk.Entry(cfg, textvariable=self._var("base_url", spec.default_url), width=34).grid(
            row=row, column=1, columnspan=3, sticky="we", padx=6, pady=6
        )
        row += 1
        ttk.Label(cfg, text="用户名").grid(row=row, column=0, sticky="e", padx=6, pady=6)
        ttk.Entry(cfg, textvariable=self._var("username"), width=18).grid(
            row=row, column=1, sticky="we", padx=6, pady=6
        )
        ttk.Label(cfg, text="密码").grid(row=row, column=2, sticky="e", padx=6, pady=6)
        ttk.Entry(cfg, textvariable=self._var("password"), width=18, show="*").grid(
            row=row, column=3, sticky="we", padx=6, pady=6
        )
        row += 1
        ttk.Label(cfg, text="超时(秒)").grid(row=row, column=0, sticky="e", padx=6, pady=6)
        ttk.Entry(cfg, textvariable=self._var("timeout", str(int(DEFAULT_TIMEOUT))), width=8).grid(
            row=row, column=1, sticky="w", padx=6, pady=6
        )
        self.vars["verify_tls"] = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            cfg, text="校验 TLS 证书（自签证书请勿勾选）", variable=self.vars["verify_tls"]
        ).grid(row=row, column=2, columnspan=2, sticky="w", padx=6, pady=4)
        row += 1
        self.vars["save_secret"] = tk.BooleanVar(value=False)
        self.save_check = ttk.Checkbutton(
            cfg,
            text="保存密码（DPAPI 加密，仅本机本用户可解密）",
            variable=self.vars["save_secret"],
            command=self.on_toggle_save,
        )
        self.save_check.grid(row=row, column=0, columnspan=2, sticky="w", padx=6, pady=(0, 6))
        if not secret_store.available():
            self.save_check.configure(state="disabled")
            ttk.Label(cfg, text="当前系统没有 DPAPI（仅 Windows 可用）", foreground="#999999").grid(
                row=row, column=2, columnspan=2, sticky="w", padx=6, pady=(0, 6)
            )
        else:
            ttk.Label(cfg, text="勾选后立即加密保存，取消勾选即删除", foreground="#666666").grid(
                row=row, column=2, columnspan=2, sticky="w", padx=6, pady=(0, 6)
            )
        row += 1
        for name, label, default in spec.extra_fields:
            ttk.Label(cfg, text=label).grid(row=row, column=0, sticky="e", padx=6, pady=6)
            ttk.Entry(cfg, textvariable=self._var(name, default), width=22).grid(
                row=row, column=1, sticky="w", padx=6, pady=6
            )
            row += 1
        if spec.hint:
            ttk.Label(cfg, text=spec.hint, foreground="#666666").grid(
                row=row, column=0, columnspan=4, sticky="w", padx=6, pady=(0, 6)
            )
            row += 1
        cfg.columnconfigure(1, weight=1)
        cfg.columnconfigure(3, weight=1)

        btns = ttk.Frame(parent)
        btns.pack(fill="x", **pad)
        self._button(btns, "测试连接", self.on_test).pack(side="left", padx=(0, 6))
        if spec.support_list:
            self._button(btns, "刷新黑名单", self.on_refresh).pack(side="left", padx=6)
        self._button(btns, "清空日志", self.on_clear_log).pack(side="left", padx=6)
        self._button(btns, "打开日志文件", self.on_open_log).pack(side="left", padx=6)

        op = ttk.LabelFrame(parent, text="单 IP 操作")
        op.pack(fill="x", **pad)
        ttk.Label(op, text="IP 地址").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        ttk.Entry(op, textvariable=self._var("ip"), width=22).grid(row=0, column=1, sticky="w", padx=6, pady=6)
        column = 2
        if spec.support_desc:
            ttk.Label(op, text="描述").grid(row=0, column=column, sticky="e", padx=6, pady=6)
            ttk.Entry(op, textvariable=self._var("desc", DEFAULT_DESC), width=24).grid(
                row=0, column=column + 1, sticky="we", padx=6, pady=6
            )
            op.columnconfigure(column + 1, weight=1)
            column += 2
        for text, handler in (("查询状态", self.on_query), ("封 禁", self.on_block), ("解 封", self.on_unblock)):
            self._button(op, text, handler).grid(row=0, column=column, padx=6, pady=6)
            column += 1

        if spec.support_list:
            table_box = ttk.LabelFrame(parent, text=spec.list_title)
            table_box.pack(fill="both", expand=True, **pad)
            keys = tuple(col[0] for col in spec.list_columns)
            self.tree = ttk.Treeview(table_box, columns=keys, show="headings", height=6)
            for key, title, width in spec.list_columns:
                self.tree.heading(key, text=title)
                self.tree.column(key, width=width, anchor="w")
            yscroll = ttk.Scrollbar(table_box, orient="vertical", command=self.tree.yview)
            self.tree.configure(yscrollcommand=yscroll.set)
            self.tree.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=6)
            yscroll.pack(side="right", fill="y", padx=(0, 6), pady=6)
            self.tree.bind("<Double-1>", self.on_row_pick)

        batch = ttk.LabelFrame(parent, text="批量导入（Excel / CSV / TXT）")
        batch.pack(fill="x", **pad)
        self._var("batch_file")
        self._var("batch_info", "未导入文件")
        self._var("interval", "0.1")
        ttk.Label(batch, text="表格文件").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        ttk.Entry(batch, textvariable=self.vars["batch_file"]).grid(
            row=0, column=1, columnspan=3, sticky="we", padx=6, pady=6
        )
        ttk.Button(batch, text="选择文件…", command=self.on_pick_file).grid(row=0, column=4, padx=6, pady=6)
        ttk.Button(batch, text="提取 IP", command=self.on_extract).grid(row=0, column=5, padx=6, pady=6)
        ttk.Label(batch, text="间隔(秒)").grid(row=1, column=0, sticky="e", padx=6, pady=6)
        ttk.Entry(batch, textvariable=self.vars["interval"], width=8).grid(
            row=1, column=1, sticky="w", padx=6, pady=6
        )
        if spec.support_desc:
            self._var("batch_desc", DEFAULT_DESC)
            ttk.Label(batch, text="描述").grid(row=1, column=2, sticky="e", padx=6, pady=6)
            ttk.Entry(batch, textvariable=self.vars["batch_desc"], width=22).grid(
                row=1, column=3, sticky="we", padx=6, pady=6
            )
        self._button(batch, "批量封禁", self.on_batch_block).grid(row=1, column=4, padx=6, pady=6)
        self._button(batch, "批量解封", self.on_batch_unblock).grid(row=1, column=5, padx=6, pady=6)
        self.stop_btn = ttk.Button(batch, text="停止", command=self.on_stop, state="disabled")
        self.stop_btn.grid(row=1, column=6, padx=6, pady=6)
        ttk.Label(batch, textvariable=self.vars["batch_info"], foreground="#666666").grid(
            row=2, column=0, columnspan=7, sticky="w", padx=6, pady=(0, 6)
        )
        batch.columnconfigure(1, weight=1)
        batch.columnconfigure(3, weight=1)

        log_box = ttk.LabelFrame(parent, text="日志")
        log_box.pack(fill="both", expand=True, **pad)
        self.log_text = scrolledtext.ScrolledText(
            log_box, height=10 if spec.support_list else 16, state="disabled", wrap="word"
        )
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)

    def _button(self, parent, text, handler):
        btn = ttk.Button(parent, text=text, command=handler)
        self.action_buttons.append(btn)
        return btn

    # ---------- 日志 ----------

    def _drain_log(self) -> None:
        while True:
            try:
                line = self.log.queue.get_nowait()
            except queue.Empty:
                break
            self.log_text.configure(state="normal")
            self.log_text.insert("end", line + "\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        self.root.after(120, self._drain_log)

    def on_clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def on_open_log(self) -> None:
        try:
            if not os.path.exists(self.log.path):
                open(self.log.path, "a", encoding="utf-8").close()
            if hasattr(os, "startfile"):
                os.startfile(self.log.path)
            else:
                messagebox.showinfo("日志文件", self.log.path)
        except OSError as exc:
            messagebox.showwarning("无法打开日志", f"{exc}\n路径：{self.log.path}")

    # ---------- 会话 ----------

    def _config(self) -> dict:
        try:
            timeout = float(str(self.vars["timeout"].get()).strip() or DEFAULT_TIMEOUT)
        except ValueError:
            raise ToolError("超时时间必须是数字") from None
        cfg = {
            "base_url": self.vars["base_url"].get().strip(),
            "username": self.vars["username"].get().strip(),
            "password": self.vars["password"].get(),
            "verify_tls": bool(self.vars["verify_tls"].get()),
            "timeout": timeout,
        }
        for name, _label, _default in self.spec.extra_fields:
            cfg[name] = str(self.vars[name].get()).strip()
        return cfg

    def _client(self):
        cfg = self._config()
        key = tuple(cfg.items())
        if self.client is not None and self.client_key == key:
            if not getattr(self.client, "authenticated", False):
                self.client.login()
            return self.client
        if self.client is not None:
            self.client.logout()
        client = self.client_factory(log=self.log, **cfg)
        client.login()
        self.client = client
        self.client_key = key
        return client

    # ---------- 本机凭据（DPAPI） ----------

    def _apply_saved(self) -> None:
        """启动或切换设备时用本机保存的配置回填；解密失败只提示，不拦启动。"""
        if not secret_store.available():
            return
        try:
            payload = secret_store.load(self.secret_path)
        except OSError as exc:
            self.log.write(f"[警告] 本机保存的连接配置无法读取或解密（{exc}），请重新填写")
            return
        if not payload:
            return
        self.vars["save_secret"].set(True)
        for name in ("base_url", "username", "password", "timeout"):
            if name in payload and name in self.vars:
                self.vars[name].set(str(payload[name]))
        if "verify_tls" in payload:
            self.vars["verify_tls"].set(bool(payload["verify_tls"]))
        for name, _label, _default in self.spec.extra_fields:
            if name in payload and name in self.vars:
                self.vars[name].set(str(payload[name]))
        self.log.banner(f"已载入本机保存的连接配置：{self.secret_path}")

    def on_toggle_save(self) -> None:
        """勾选即保存当前配置，取消勾选即删除本机凭据文件。"""
        if not secret_store.available():
            return
        if self.vars["save_secret"].get():
            self._save_secret(notify=True)
            return
        try:
            secret_store.clear(self.secret_path)
        except OSError as exc:
            messagebox.showwarning("删除失败", f"{exc}\n路径：{self.secret_path}")
            return
        self.log.write(f"已删除本机保存的连接配置：{self.secret_path}")

    def _save_secret(self, notify: bool = False) -> None:
        """加密写盘当前配置；字段没填全时静默跳过，不打断正在进行的操作。"""
        if not secret_store.available() or not self.vars["save_secret"].get():
            return
        try:
            cfg = self._config()
        except ToolError:
            return
        missing = [name for name in ("base_url", "username", "password") if not str(cfg.get(name) or "").strip()]
        if missing:
            if notify:
                self.log.write(f"连接信息不完整（{'、'.join(missing)} 为空），未保存；已保存的配置保持不变")
            return
        payload = {
            "base_url": cfg["base_url"],
            "username": cfg["username"],
            "password": cfg["password"],
            "timeout": cfg["timeout"],
            "verify_tls": cfg["verify_tls"],
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for name, _label, _default in self.spec.extra_fields:
            payload[name] = cfg.get(name, "")
        try:
            secret_store.save(self.secret_path, payload)
        except OSError as exc:
            self.log.write(f"[警告] 保存连接配置失败：{exc}")
            return
        if notify:
            self.log.write(f"已保存连接配置（地址、用户名、密码，DPAPI 加密）：{self.secret_path}")

    # ---------- 线程封装 ----------

    def _run(self, label: str, func, on_done=None, refresh: bool = False) -> None:
        if self.busy:
            messagebox.showinfo("请稍候", "上一个操作尚未结束")
            return
        self.busy = True
        self._set_buttons("disabled")
        self.log.write(f"===== {label} =====")
        started = time.monotonic()

        def worker():
            try:
                result = func()
            except ToolError as exc:
                self.log(f"[失败] {exc}")
            except Exception as exc:  # 兜底，界面不能因未预期异常卡住
                self.log(f"[异常] {type(exc).__name__}: {exc}")
            else:
                if on_done is not None:
                    self.root.after(0, lambda: on_done(result))
            finally:
                elapsed = time.monotonic() - started
                self.root.after(0, lambda: self._finish(refresh, elapsed))

        threading.Thread(target=worker, daemon=True).start()

    def _finish(self, refresh: bool = False, elapsed: float = 0.0) -> None:
        self.busy = False
        self.log.quiet = False
        self._set_buttons("normal")
        self.stop_btn.configure(state="disabled")
        self.log.write(f"----- {elapsed:.2f}s -----")
        self._save_secret()  # 勾选了「保存密码」时，把最近一次用的配置同步到磁盘
        if refresh and self.spec.support_list:
            self.on_refresh()

    def _set_buttons(self, state: str) -> None:
        for btn in self.action_buttons:
            btn.configure(state=state)

    # ---------- 单 IP 动作 ----------

    def on_test(self) -> None:
        def job():
            return self.client_factory(log=self.log, **self._config()).test_connection()

        def done(message):
            self.log.write(message)
            messagebox.showinfo("测试连接", message)

        self._run("测试连接", job, done)

    def _require_ip(self, ip: str) -> bool:
        if not ip:
            messagebox.showwarning("缺少 IP", "请先填写 IP 地址")
            return False
        return True

    def on_query(self) -> None:
        ip = self.vars["ip"].get().strip()
        if not self._require_ip(ip):
            return

        def job():
            hits = self._client().entries(ip)
            if not hits:
                return f"{ip}：不在黑名单"
            first = hits[0]
            detail = ""
            if isinstance(first, dict):
                detail = "，".join(f"{k}={v}" for k, v in first.items() if k in ("name", "type", "enable", "urlType", "desc"))
            return f"{ip}：已封禁（匹配 {len(hits)} 条{f'，{detail}' if detail else ''}）"

        def done(message):
            self.log.write(message)
            messagebox.showinfo("查询状态", message)

        self._run("查询 IP 状态", job, done)

    def on_block(self) -> None:
        ip = self.vars["ip"].get().strip()
        if not self._require_ip(ip):
            return
        desc = self.vars["desc"].get().strip() if self.spec.support_desc else ""

        def job():
            return self._client().block(ip, desc)

        def done(message):
            self.log.write(message)

        self._run("封禁 IP", job, done, refresh=True)

    def on_unblock(self) -> None:
        ip = self.vars["ip"].get().strip()
        if not self._require_ip(ip):
            return

        def job():
            return self._client().unblock(ip)

        def done(message):
            self.log.write(message)

        self._run("解封 IP", job, done, refresh=True)

    def on_refresh(self) -> None:
        if not self.spec.support_list:
            return

        def job():
            return self._client().list_entries()

        def done(rows):
            for item in self.tree.get_children():
                self.tree.delete(item)
            for row in rows:
                self.tree.insert("", "end", values=row)
            self.log.write(f"共 {len(rows)} 条条目")

        self._run("刷新黑名单", job, done)

    def on_row_pick(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        values = self.tree.item(selected[0], "values")
        if values:
            self.vars["ip"].set(str(values[0]))

    # ---------- 批量 ----------

    def on_pick_file(self) -> None:
        path = filedialog.askopenfilename(
            title="选择包含 IP 的表格",
            filetypes=[("表格文件", "*.xlsx *.csv *.txt"), ("所有文件", "*.*")],
        )
        if path:
            self.vars["batch_file"].set(path)
            self.on_extract()

    def on_extract(self) -> None:
        path = self.vars["batch_file"].get().strip()
        if not path:
            messagebox.showwarning("缺少文件", "请先选择包含 IP 的表格文件")
            return

        def job():
            return extract_ips(path)

        def done(ips):
            self.batch_ips = list(ips)
            self.vars["batch_info"].set(f"已提取 {len(ips)} 个 IP（去重后）")
            self.log.write(f"从 {os.path.basename(path)} 提取到 {len(ips)} 个唯一 IPv4")
            if ips:
                self.log.write("预览（前 20 个）：" + "、".join(ips[:20]))
            else:
                messagebox.showwarning("没有 IP", "文件里没找到合法 IPv4 地址")

        self._run("提取表格 IP", job, done)

    def on_batch_block(self) -> None:
        self._batch("block")

    def on_batch_unblock(self) -> None:
        self._batch("unblock")

    def on_stop(self) -> None:
        if self.busy:
            self.stop_event.set()
            self.log.write("收到停止请求：当前这条处理完就停")

    def _batch(self, action: str) -> None:
        ips = list(self.batch_ips)
        if not ips:
            messagebox.showwarning("没有 IP", "请先选择表格并提取 IP")
            return
        verb = "封禁" if action == "block" else "解封"
        if not messagebox.askyesno("批量确认", f"将对 {len(ips)} 个 IP 执行{verb}，是否继续？"):
            return
        desc = self.vars["batch_desc"].get().strip() if self.spec.support_desc else ""
        try:
            interval = max(0.0, float(str(self.vars["interval"].get()).strip() or 0))
        except ValueError:
            messagebox.showwarning("参数错误", "间隔必须是数字（秒）")
            return

        self.stop_event.clear()
        self.stop_btn.configure(state="normal")
        total = len(ips)

        def job():
            self.log.quiet = True  # 逐条请求明细只落文件，界面留结果行
            try:
                client = self._client()
                ok = skipped = failed = 0
                for index, ip in enumerate(ips, 1):
                    if self.stop_event.is_set():
                        self.log.write(f"已停止：剩余 {total - index + 1} 个未处理")
                        break
                    try:
                        message = client.block(ip, desc) if action == "block" else client.unblock(ip)
                    except ToolError as exc:
                        failed += 1
                        self.log.write(f"[{index}/{total}] {ip} 失败：{exc}")
                    except Exception as exc:
                        failed += 1
                        self.log.write(f"[{index}/{total}] {ip} 异常：{type(exc).__name__}: {exc}")
                    else:
                        if "跳过" in message:
                            skipped += 1
                        else:
                            ok += 1
                        self.log.write(f"[{index}/{total}] {message}")
                    self.root.after(
                        0,
                        lambda i=index, o=ok, s=skipped, f=failed: self._update_batch_info(i, total, o, s, f),
                    )
                    if interval and index < total:
                        time.sleep(interval)
                return {"ok": ok, "skipped": skipped, "failed": failed}
            finally:
                self.log.quiet = False

        def done(result):
            summary = (
                f"批量{verb}结束：成功 {result['ok']}，跳过 {result['skipped']}，"
                f"失败 {result['failed']}（共 {total} 个）"
            )
            self.log.write(summary)
            self.vars["batch_info"].set(summary)

        self._run(f"批量{verb}", job, done, refresh=True)

    def _update_batch_info(self, index: int, total: int, ok: int, skipped: int, failed: int) -> None:
        self.vars["batch_info"].set(f"进行中 {index}/{total}：成功 {ok}，跳过 {skipped}，失败 {failed}")

    def on_close(self) -> None:
        # 关窗前同步一次：改了密码但没点任何按钮直接退出，也不会丢
        self._save_secret()
        self._drop_client()
        self.root.destroy()


def entry_dir() -> str:
    """工具根目录（`kit/` 的上一级）：日志统一写这里，与从哪个入口启动无关。"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_tool(spec: DriverSpec, client_factory, devices=None) -> None:
    """入口脚本调用：创建窗口并进入事件循环。

    `devices` 传设备清单时窗口顶部出现设备选择条，`spec` 为初始选中的设备。
    """
    if not TK_AVAILABLE:
        print("当前 Python 缺少 tkinter，请使用官方安装包（Windows 默认包含 tkinter）。")
        return
    try:  # Windows 高 DPI 下文字不糊
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    DeviceToolApp(root, spec, client_factory, devices)
    root.mainloop()
