"""设备联调统一入口：窗口顶部选择设备，所有设备共用同一套界面。

运行：python device_tool.py（或双击 run.cmd，默认不弹控制台窗口）。
启动失败时会弹窗提示，并把堆栈写到 logs/startup_error.log。
"""

import os
import sys
import traceback

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)


def _report_startup_error(detail: str) -> None:
    """没有控制台窗口时，错误必须能被看到：先落盘，再弹窗。"""
    try:
        folder = os.path.join(BASE_DIR, "logs")
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "startup_error.log"), "a", encoding="utf-8") as fh:
            fh.write(detail + "\n")
    except OSError:
        pass
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("设备联调工具启动失败", detail.strip().splitlines()[-1] + "\n\n详细堆栈：logs/startup_error.log")
        root.destroy()
    except Exception:
        pass


if __name__ == "__main__":
    try:
        from kit.registry import DEVICES
        from kit.ui import run_tool

        first = DEVICES[0]
        run_tool(first.spec, first.client_factory, DEVICES)
    except Exception:
        _report_startup_error(traceback.format_exc())
        raise SystemExit(1)
