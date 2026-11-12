"""深信服 AF 协议客户端：登录换 token → token 放 cookie → whiteblacklist 增删查。"""

from __future__ import annotations

import json
import socket
import ssl
import time
from urllib import error as urlerror
from urllib import parse, request

from ..common import ToolError, check_ip, json_text, mask_secret

DEFAULT_NAMESPACE = "@namespace"
BLACK_DESCRIPTION = "SenseMind联动封禁"
NOT_FOUND_CODE = 1004  # 设备的「资源不存在」语义码，比中文文案稳定


def entry_kind(entry: dict) -> str:
    """条目的实际形态，用于「同名条目冲突」的提示。"""
    whitelist = entry.get("type") == "WHITE"
    enabled = bool(entry.get("enable"))
    if whitelist:
        return "白名单条目" if enabled else "已停用的白名单条目"
    if not enabled:
        return "已停用的黑名单条目"
    return "非 IP 类型的名单条目"


def conflict_message(ip: str, entry: dict) -> str:
    """给运维看的冲突说明：说清「已经在白名单里」这类事实，不描述接口内部实现。"""
    if entry.get("type") == "WHITE":
        return f"{ip} 已经在设备白名单里，与封禁冲突，请先在设备上移除这条白名单（或改成黑名单）再下发封禁"
    if not entry.get("enable"):
        return f"{ip} 在设备黑名单里但处于停用状态，请先在设备上启用或删除该条目再下发封禁"
    return f"{ip} 在设备上已有同名条目（{entry_kind(entry)}），请先在设备上处理该条目再下发封禁"


class SangforAF:
    """深信服 AF 白名单/黑名单客户端。"""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        namespace: str = DEFAULT_NAMESPACE,
        verify_tls: bool = False,
        timeout: float = 10.0,
        log=None,
    ):
        base = (base_url or "").strip().rstrip("/")
        if not base:
            raise ToolError("缺少管理地址")
        if not base.lower().startswith(("http://", "https://")):
            base = "https://" + base
        self.base_url = base
        self.username = (username or "").strip()
        self.password = password or ""
        self.namespace = (namespace or "").strip() or DEFAULT_NAMESPACE
        self.verify_tls = bool(verify_tls)
        self.timeout = float(timeout or 10.0)
        self.token = ""
        self._log = log or (lambda _msg: None)

    @property
    def authenticated(self) -> bool:
        return bool(self.token)

    @property
    def base_path(self) -> str:
        return f"/api/v1/namespaces/{self.namespace}"

    # ---------- HTTP ----------

    def _ssl_context(self):
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            # 设备多为自签证书：先关主机名校验再改校验模式，顺序反了会 ValueError
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _request(self, method: str, path: str, *, body=None, params=None) -> tuple[int, str]:
        url = self.base_url + path
        if params:
            url += "?" + parse.urlencode(params)
        data = None
        headers = {
            "Content-Type": "application/json; charset=UTF-8",
            "Accept": "application/json",
        }
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        if self.token:
            headers["Cookie"] = f"token={self.token}"

        self._log(f"→ {method} {url}")
        if body is not None:
            self._log(f"   请求体 {json_text(body)}")
        if self.token:
            self._log(f"   Cookie token={mask_secret(self.token)}")

        req = request.Request(url, data=data, headers=headers, method=method)
        started = time.monotonic()
        try:
            with request.urlopen(req, timeout=self.timeout, context=self._ssl_context()) as resp:
                status = getattr(resp, "status", 200)
                text = resp.read().decode("utf-8", "replace")
                self._log_response(status, text, started)
                return status, text
        except urlerror.HTTPError as exc:
            text = exc.read().decode("utf-8", "replace")
            self._log_response(exc.code, text, started)
            return exc.code, text
        except TimeoutError:
            self._log(f"✗ 请求超时（{self.timeout:g}s）：{url}")
            raise ToolError(f"请求超时（{self.timeout:g}s）：{url}") from None
        except urlerror.URLError as exc:
            raise self._network_error(exc, url) from None

    def _log_response(self, status: int, text: str, started: float) -> None:
        elapsed = (time.monotonic() - started) * 1000
        self._log(f"← HTTP {status}（{elapsed:.0f} ms，响应 {len(text)} 字符）")
        if not text:
            return
        try:
            payload = json.loads(text)
        except ValueError:
            self._log(f"   响应体（非 JSON）{text.strip()}")
            return
        self._log(f"   响应体 {json_text(payload)}")

    def _network_error(self, exc, url: str) -> ToolError:
        reason = getattr(exc, "reason", exc)
        hint = ""
        if isinstance(reason, socket.gaierror):
            hint = "；域名解析失败，检查管理地址是否写错"
        elif isinstance(reason, ssl.SSLError):
            hint = "；TLS/证书问题，自签证书请取消勾选「校验 TLS 证书」"
        elif isinstance(reason, ConnectionRefusedError):
            hint = "；连接被拒绝，端口未开放或被设备安全策略拦截"
        elif isinstance(reason, ConnectionResetError):
            hint = "；连接被对端重置"
        self._log(f"✗ 网络错误：{reason}{hint}（{url}）")
        return ToolError(f"网络错误：{reason}{hint}（{url}）")

    @staticmethod
    def _json(text: str, action: str) -> dict:
        try:
            payload = json.loads(text)
        except ValueError:
            raise ToolError(f"{action}失败：响应不是有效 JSON（{text[:160]}）") from None
        if not isinstance(payload, dict):
            raise ToolError(f"{action}失败：响应不是 JSON 对象")
        return payload

    @staticmethod
    def _ensure_ok(payload: dict, action: str, status: int | None = None) -> None:
        """设备成功可能只体现在 message=="成功"，也可能带 code==0，两者皆无即失败。"""
        if payload.get("code") in (0, "0") or payload.get("message") == "成功":
            return
        reason = payload.get("message") or f"HTTP {status}"
        raise ToolError(f"{action}失败：{reason}")

    @staticmethod
    def _is_blocked(entry: dict) -> bool:
        if not entry.get("enable") or entry.get("type") != "BLACK":
            return False
        url_type = entry.get("urlType")
        if url_type is not None:
            return url_type == "ip"
        # 部分固件不回 urlType，改用 domain 标记：0 表示非域名（即 IP 对象）
        return entry.get("domain") in (None, 0, "0", False)

    @staticmethod
    def _is_not_found(payload: dict) -> bool:
        try:
            return int(payload.get("code")) == NOT_FOUND_CODE
        except (TypeError, ValueError):
            return False

    # ---------- 会话 ----------

    def login(self) -> str:
        if not self.username or not self.password:
            raise ToolError("请填写用户名和密码")
        self.token = ""
        self._log(
            f"登录 {self.base_url}（用户 {self.username}，命名空间 {self.namespace}，"
            f"校验证书={self.verify_tls}，超时={self.timeout:g}s）"
        )
        status, text = self._request(
            "POST", f"{self.base_path}/login", body={"name": self.username, "password": self.password}
        )
        if status >= 400:
            raise ToolError(f"登录请求被拒绝（HTTP {status}）：{text[:200]}")
        payload = self._json(text, "登录")
        self._ensure_ok(payload, "登录", status)
        token = ((payload.get("data") or {}).get("loginResult") or {}).get("token")
        if not token:
            raise ToolError("登录成功但未返回 token")
        self.token = token
        self._log(f"登录成功，token={mask_secret(token)}")
        return token

    def logout(self) -> None:
        if not self.token:
            return
        self._log("退出登录")
        try:
            self._request("POST", f"{self.base_path}/logout", body={"loginResult": {"token": self.token}})
        except ToolError as exc:
            self._log(f"退出登录失败（忽略）：{exc}")
        finally:
            self.token = ""

    def test_connection(self) -> str:
        self.login()
        self.logout()
        return f"连接成功：{self.base_url}（命名空间 {self.namespace}）"

    # ---------- 黑名单 ----------

    def _query_entry(self, target: str) -> dict | None:
        """查单 IP 条目：不存在（404 / code=1004 / 文案含「不存在」）时返回 None。

        存在就原样返回——白名单条目、停用条目也返回，由调用方判断能否封禁。
        """
        status, text = self._request("GET", f"{self.base_path}/whiteblacklist/{target}")
        if status == 404:
            self._log(f"   判定：HTTP 404 → {target} 不在黑名单")
            return None
        if status >= 400:
            raise ToolError(f"查询黑名单失败（HTTP {status}）：{text[:200]}")
        payload = self._json(text, "查询黑名单")
        if self._is_not_found(payload):
            self._log(f"   判定：code={NOT_FOUND_CODE} → {target} 不在黑名单")
            return None
        if "不存在" in text:
            self._log(f"   判定：响应含「不存在」→ {target} 不在黑名单")
            return None
        data = payload.get("data")
        if not isinstance(data, dict):
            self._log(f"   判定：data 是 {type(data).__name__}（期望对象）→ 视为不在黑名单")
            return None
        return data

    def entries(self, ip: str) -> list[dict]:
        """查单 IP：只有「启用的黑名单 IP 条目」才算已封禁，其余形态返回空列表。"""
        target = check_ip(ip)
        self._log(f"查询 {target} 在设备侧的黑名单条目")
        data = self._query_entry(target)
        if data is None:
            return []
        blocked = self._is_blocked(data)
        self._log(
            f"   条目字段：type={data.get('type')} enable={data.get('enable')} "
            f"urlType={data.get('urlType')} domain={data.get('domain')} description={data.get('description')}"
        )
        if blocked:
            self._log("   判定：已封禁")
            return [data]
        self._log(f"   判定：设备上是{entry_kind(data)}，不算封禁")
        return []

    def block(self, ip: str, desc: str = BLACK_DESCRIPTION) -> str:
        target = check_ip(ip)
        final_desc = (desc or "").strip() or BLACK_DESCRIPTION
        self._log(f"封禁 {target}（描述：{final_desc}）")
        entry = self._query_entry(target)
        if entry is not None:
            if self._is_blocked(entry):
                self._log(f"   跳过：{target} 已满足封禁条件")
                return f"{target} 已在黑名单，跳过"
            # 不替用户改配置，直接报冲突（设备也会以「已存在」拒绝新增）
            self._log(f"   中止：设备上已有同名条目（{entry_kind(entry)}）")
            raise ToolError(conflict_message(target, entry))
        status, text = self._request(
            "POST",
            f"{self.base_path}/whiteblacklist",
            body={"type": "BLACK", "url": target, "enable": True, "description": final_desc},
        )
        if status >= 400:
            raise ToolError(f"添加黑名单失败（HTTP {status}）：{text[:200]}")
        self._ensure_ok(self._json(text, "添加黑名单"), "添加黑名单", status)
        self._log(f"   成功：{target} 已写入黑名单")
        return f"{target} 已加入黑名单"

    def unblock(self, ip: str) -> str:
        target = check_ip(ip)
        self._log(f"解封 {target}")
        entry = self._query_entry(target)
        if entry is None:
            self._log(f"   跳过：{target} 不在黑名单")
            return f"{target} 不在黑名单，跳过"
        if not self._is_blocked(entry):
            # 白名单/停用条目不是我们下发的，删掉等于改人工配置，只提示不动它
            self._log(f"   跳过：设备上是{entry_kind(entry)}，不动它")
            return f"{target} 在设备上是{entry_kind(entry)}，未删除"
        status, text = self._request("DELETE", f"{self.base_path}/whiteblacklist/{target}")
        if status >= 400:
            raise ToolError(f"删除黑名单失败（HTTP {status}）：{text[:200]}")
        self._ensure_ok(self._json(text, "删除黑名单"), "删除黑名单", status)
        self._log(f"   成功：{target} 已从黑名单删除")
        return f"{target} 已从黑名单删除"


