"""本机连接配置保存：用 Windows DPAPI 加密后落盘，只有本机的当前用户能解开。

通过 ctypes 直接调 crypt32（不引入 pywin32 等第三方库）。加密作用域是当前用户，
拷到别的机器或换用户登录都解不开；文件被删掉即视为未保存。

落盘格式：魔数 + DPAPI blob，blob 里是 UTF-8 JSON（管理地址、用户名、密码、超时、
TLS 开关与厂商额外字段）。非 Windows 平台不可用，调用方应按 `available()` 置灰入口。
"""

from __future__ import annotations

import ctypes
import json
import os

MAGIC = b"SMDPAPI1\n"
DESCRIPTION = "fw_block_tools connection"
CRYPTPROTECT_UI_FORBIDDEN = 0x1
APP_FOLDER = "fw_block_tools"


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def available() -> bool:
    """DPAPI 只在 Windows 上存在。"""
    return os.name == "nt"


def config_dir() -> str:
    """凭据落用户目录，不跟工具目录走：Windows 用 %LOCALAPPDATA%，其它平台退回 ~/.fw_block_tools。

    DPAPI 的作用域本来就是本机本用户，放用户目录才能和它对齐；把 fw_block_tools
    整个目录拷给别人时也不会把密文一起带走。
    """
    for name in ("LOCALAPPDATA", "APPDATA", "USERPROFILE"):
        base = os.environ.get(name)
        if base:
            return os.path.join(base, APP_FOLDER)
    return os.path.join(os.path.expanduser("~"), f".{APP_FOLDER}")


def _blob(data: bytes):
    buffer = ctypes.create_string_buffer(data, len(data))
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer


def _apis():
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    blob = ctypes.POINTER(_DataBlob)
    # szDataDescr 是 LPCWSTR，必须显式声明参数类型，否则 ctypes 按 ANSI 传字符串
    crypt32.CryptProtectData.argtypes = [
        blob, ctypes.c_wchar_p, blob, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, blob
    ]
    crypt32.CryptProtectData.restype = ctypes.c_bool
    crypt32.CryptUnprotectData.argtypes = [
        blob, ctypes.POINTER(ctypes.c_wchar_p), blob, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, blob
    ]
    crypt32.CryptUnprotectData.restype = ctypes.c_bool
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    return crypt32, kernel32


def protect(data: bytes) -> bytes:
    if not available():
        raise OSError("DPAPI 仅在 Windows 上可用")
    crypt32, kernel32 = _apis()
    source, _keep = _blob(data)
    target = _DataBlob()
    ok = crypt32.CryptProtectData(
        ctypes.byref(source),
        DESCRIPTION,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(target),
    )
    if not ok:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        kernel32.LocalFree(target.pbData)


def unprotect(blob: bytes) -> bytes:
    if not available():
        raise OSError("DPAPI 仅在 Windows 上可用")
    crypt32, kernel32 = _apis()
    source, _keep = _blob(blob)
    target = _DataBlob()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(source), None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(target)
    )
    if not ok:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        kernel32.LocalFree(target.pbData)


def save(path: str, payload: dict) -> None:
    """加密并原子写入：先写 .tmp 再替换，避免中途失败留下半个文件。"""
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "wb") as fh:
        fh.write(MAGIC + protect(data))
    os.replace(tmp, path)


def load(path: str) -> dict | None:
    """返回保存的配置；文件不存在返回 None，解不开时抛 OSError。"""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise OSError(f"读取失败：{exc}") from None
    if not raw.startswith(MAGIC):
        raise OSError("文件格式不对，可能不是本工具保存的配置")
    try:
        payload = json.loads(unprotect(raw[len(MAGIC):]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise OSError(f"解密结果不是有效配置：{exc}") from None
    return payload if isinstance(payload, dict) else None


def clear(path: str) -> None:
    """删除保存的配置；不存在时静默返回。"""
    try:
        os.remove(path)
    except FileNotFoundError:
        return
