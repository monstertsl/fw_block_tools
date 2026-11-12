"""绿盟 NF 防火墙客户端：静态 API Token 认证，封堵落点 = 策略配置-全局黑白名单-黑名单。

- 查：GET  /north/nf/strategy/globalWb/blist/info/?size=&page=&search=
- 加：POST /north/nf/strategy/globalWb/blist/configuration/（action=create）
- 删：POST /north/nf/strategy/globalWb/blist/delete/（{"id": [...]}）

响应 `{"status":2000,...}`，status 可能是 int 也可能是字符串，统一按字符串比较。
"""

from __future__ import annotations

import json
import socket
import ssl
import time
from urllib import error as urlerror
from urllib import parse, request

from ..common import ToolError, check_ip, json_text, mask_secret

API_PREFIX = "/north/nf/strategy/globalWb/blist"
INFO_PATH = f"{API_PREFIX}/info/"
CONFIG_PATH = f"{API_PREFIX}/configuration/"
DELETE_PATH = f"{API_PREFIX}/delete/"
SUCCESS_STATUS = "2000"
BLACK_TYPE = "sourceIp"
PROTOCOL = "any"
PAGE_SIZE = 100


class NsfocusNF:
    """绿盟 NF 黑名单客户端（Token 认证，无登录会话）。"""

    def __init__(
        self,
        base_url: str,
        api_token: str = "",
        verify_tls: bool = False,
        timeout: float = 10.0,
        log=None,
        **_ignored,  # 界面固定渲染的用户名/密码，本设备用不到
    ):
        base = (base_url or "").strip().rstrip("/")
        if not base:
            raise ToolError("缺少管理地址")
        if not base.lower().startswith(("http://", "https://")):
            base = "https://" + base
        self.base_url = base
        self.api_token = (api_token or "").strip()
        self.verify_tls = bool(verify_tls)
        self.timeout = float(timeout or 10.0)
        self.ready = False
        self._log = log or (lambda _msg: None)

    @property
    def authenticated(self) -> bool:
        return self.ready

    # ---------- HTTP ----------

    def _ssl_context(self):
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _request(self, method: str, path: str, *, payload=None, params=None) -> tuple[int, str]:
        url = self.base_url + path
        if params:
            url += "?" + parse.urlencode(params)
        data = None
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": self.api_token,
        }
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        self._log(f"→ {method} {url}")
        self._log(f"   Authorization {mask_secret(self.api_token)}")
        if payload is not None:
            self._log(f"   请求体 {json_text(payload)}")

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
        self._log(f"← HTTP {status}（{elapsed:.0f} ms，{len(text)} 字符）")
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
            hint = "；连接被拒绝，确认 API 端口（默认 8081）已开放"
        self._log(f"✗ 网络错误：{reason}{hint}（{url}）")
        return ToolError(f"网络错误：{reason}{hint}（{url}）")

    def _call(self, method: str, path: str, *, payload=None, params=None, action: str) -> dict:
        status, text = self._request(method, path, payload=payload, params=params)
        if status >= 400:
            raise ToolError(f"{action}被拒绝（HTTP {status}）：{text[:200]}")
        try:
            body = json.loads(text)
        except ValueError:
            raise ToolError(f"{action}失败：响应不是有效 JSON（{text[:160]}）") from None
        if not isinstance(body, dict):
            raise ToolError(f"{action}失败：响应不是 JSON 对象")
        if str(body.get("status")) != SUCCESS_STATUS:
            reason = body.get("message") or body.get("status") or "设备未返回原因"
            raise ToolError(f"{action}失败：{reason}")
        return body

    # ---------- 会话 ----------

    def login(self) -> str:
        if not self.api_token:
            raise ToolError("请填写 API Token（设备 Web 界面「系统管理 → API 管理」生成）")
        self._log(f"校验 Token {self.base_url}（校验证书={self.verify_tls}，超时={self.timeout:g}s）")
        self.ready = True  # Token 无会话，能查到数据即视为可用
        body = self._call("GET", INFO_PATH, params={"size": 1, "page": 1}, action="Token 校验")
        total = (body.get("result") or {}).get("total") or 0
        self._log(f"Token 可用，黑名单当前 {total} 条")
        return "Token 校验通过"

    def logout(self) -> None:
        self.ready = False
        self._log("Token 认证无会话，无需退登")

    def test_connection(self) -> str:
        self.login()
        return "Token 校验通过（可读写黑名单）"

    # ---------- 黑名单 ----------

    def _rows(self, *, search: str = "", page_all: bool = False) -> tuple[list, int]:
        params = {"size": -1 if page_all else PAGE_SIZE, "page": 1}
        if search:
            params["search"] = search
        body = self._call("GET", INFO_PATH, params=params, action="查询黑名单")
        result = body.get("result") or {}
        return result.get("list") or [], result.get("total") or 0

    def entries(self, ip: str) -> list:
        """按 IP 精确取条目；search 只回部分结果时退化为全量比对。"""
        target = check_ip(ip)
        rows, total = self._rows(search=target)
        hits = [row for row in rows if str(row.get("ip") or "") == target]
        if hits or not total:
            return hits
        rows, _ = self._rows(page_all=True)
        return [row for row in rows if str(row.get("ip") or "") == target]

    def block(self, ip: str, desc: str = "") -> str:
        target = check_ip(ip)
        if self.entries(target):
            return f"{target} 已在黑名单，跳过"
        self._call(
            "POST",
            CONFIG_PATH,
            payload={
                "type": BLACK_TYPE,
                "ip": target,
                "protocol": PROTOCOL,
                "objectType": "ip",
                "port": "any",
                "is_time": "f",
                "status": True,
                "action": "create",
            },
            action="添加黑名单",
        )
        if not self.entries(target):
            raise ToolError(f"添加 {target} 返回成功，但复查黑名单未见该条目")
        return f"{target} 已加入黑名单（sourceIp / any 协议）"

    def unblock(self, ip: str) -> str:
        target = check_ip(ip)
        entries = self.entries(target)
        if not entries:
            return f"{target} 不在黑名单，跳过"
        ids = [row.get("id") for row in entries if row.get("id") is not None]
        if not ids:
            raise ToolError(f"黑名单条目缺少 id，无法删除：{target}")
        self._call("POST", DELETE_PATH, payload={"id": ids}, action="删除黑名单")
        if self.entries(target):
            raise ToolError(f"删除 {target} 返回成功，但复查黑名单仍有该条目")
        return f"{target} 已移出黑名单（删除 {len(ids)} 条）"

    def list_entries(self) -> list:
        rows, _ = self._rows(page_all=True)
        return [
            (
                str(row.get("ip") or ""),
                str(row.get("type") or ""),
                str(row.get("protocol") or ""),
                str(row.get("port") or ""),
                "是" if row.get("status") else "否",
            )
            for row in rows
        ]
