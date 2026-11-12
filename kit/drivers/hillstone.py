"""山石网科防火墙客户端：登录换会话（X-Auth-* 头 + 同名 Cookie），封禁落点 = 地址簿组。

认证契约（按 MCP 客户端实现，兼容老固件）：

- Token：`{"api_token": "..."}`
- 用户名密码：`{"lang":"en","userName":"<base64>","password":"<base64>"}`
- 老固件退回明文：`{"userName":"明文","password":"明文","encodeUserName":"0","encodePassword":"0"}`
- 会话头 `X-Auth-*` + 同名 Cookie，另带 `X-API-Language`
- `401` 或 `error_code` 为 `loginError_1001/1002/1003` 时重登一次再重试

地址簿接口：

- 查组：GET  /rest/api/addrbook?query={"conditions":[{"field":"name","value":"<组>"}],...}
- 建组：POST /rest/api/addrbook  body=[{"name":组,"ip":[{"ip_addr":ip,"netmask":"32","flag":0}]}]
- 覆盖：PUT  /rest/api/addrbook  同上结构（整体覆盖组成员）

地址簿只是对象容器，**组必须被安全策略引用才会真正阻断**；写入后一律回读，以组内是否真的
出现/消失该 IP 判定成败。
"""

from __future__ import annotations

import base64
import json
import socket
import ssl
import time
from urllib import error as urlerror
from urllib import parse, request

from ..common import ToolError, check_ip, json_text, mask_secret

LOGIN_PATH = "/rest/api/login"
ADDRBOOK_PATH = "/rest/api/addrbook"
DEFAULT_LOCALE = "en"
DEFAULT_GROUP = "SenseMind-Block"
QUERY_LIMIT = 200
MAX_ATTEMPTS = 2
SESSION_ERROR_CODES = {"loginError_1001", "loginError_1002", "loginError_1003"}
# 与设备 WebUI 客户端一致的 Accept；个别固件只认 text/plain 承载的 JSON
ACCEPT_HEADER = "text/plain;charset=UTF-8, application/json;q=0.9, */*;q=0.8"
PLAIN_CONTENT_TYPE = "text/plain;charset=UTF-8"


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


class HillstoneFW:
    """山石网科地址簿封禁客户端。"""

    def __init__(
        self,
        base_url: str,
        username: str = "",
        password: str = "",
        group_name: str = DEFAULT_GROUP,
        api_token: str = "",
        verify_tls: bool = False,
        timeout: float = 10.0,
        log=None,
        **_ignored,
    ):
        base = (base_url or "").strip().rstrip("/")
        if not base:
            raise ToolError("缺少管理地址")
        if not base.lower().startswith(("http://", "https://")):
            base = "https://" + base
        self.base_url = base
        self.username = (username or "").strip()
        self.password = password or ""
        self.api_token = (api_token or "").strip()
        self.group_name = (group_name or DEFAULT_GROUP).strip() or DEFAULT_GROUP
        self.verify_tls = bool(verify_tls)
        self.timeout = float(timeout or 10.0)
        self.session: dict | None = None
        self.cookies: dict[str, str] = {}
        self._log = log or (lambda _msg: None)

    @property
    def authenticated(self) -> bool:
        return bool(self.session and self.session.get("token"))

    # ---------- HTTP ----------

    def _ssl_context(self):
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _headers(self) -> dict:
        headers = {
            "Accept": ACCEPT_HEADER,
            "Content-Type": "application/json",
            "X-API-Language": DEFAULT_LOCALE,
        }
        if self.authenticated:
            session = self.session or {}
            headers.update(
                {
                    "X-Auth-Token": str(session.get("token", "")),
                    "X-Auth-Role": str(session.get("role", "")),
                    "X-Auth-VsysId": str(session.get("vsysId", "")),
                    "X-Auth-Fromrootvsys": str(session.get("fromrootvsys", "")),
                    "X-Auth-Username": str(session.get("username", "")),
                }
            )
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        return headers

    def _request(
        self, method: str, path: str, *, payload=None, params=None, content_type: str | None = None
    ) -> tuple[int, str]:
        url = self.base_url + path
        if params:
            url += "?" + parse.urlencode(params)
        data = None
        headers = self._headers()
        if content_type:
            headers["Content-Type"] = content_type
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        self._log(f"→ {method} {url}")
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
            hint = "；连接被拒绝，确认 WebUI 端口（443/8443）是否开放"
        self._log(f"✗ 网络错误：{reason}{hint}（{url}）")
        return ToolError(f"网络错误：{reason}{hint}（{url}）")

    @staticmethod
    def _session_expired(status: int, body) -> bool:
        # 401/403 都按会话失效处理（设备侧行为：401、403 清会话）
        if status in (401, 403):
            return True
        if isinstance(body, dict):
            if body.get("error_code") in SESSION_ERROR_CODES:
                return True
            exception = body.get("exception")
            if isinstance(exception, dict) and exception.get("code") in SESSION_ERROR_CODES:
                return True
        return False

    def _call(self, method: str, path: str, *, payload=None, params=None, action: str, retry: bool = True):
        status, text = self._request(method, path, payload=payload, params=params)
        if payload is not None and status in (400, 415):
            self._log(f"   {action} 返回 HTTP {status}，改用 text/plain 重试一次")
            status, text = self._request(
                method, path, payload=payload, params=params, content_type=PLAIN_CONTENT_TYPE
            )
        try:
            body = json.loads(text)
        except ValueError:
            body = None
        if retry and self._session_expired(status, body):
            self._log("   会话已失效，重新登录后重试")
            self.login()
            return self._call(method, path, payload=payload, params=params, action=action, retry=False)
        if status >= 400:
            raise ToolError(f"{action}被拒绝（HTTP {status}）：{text[:200]}")
        if body is None:
            raise ToolError(f"{action}失败：响应不是有效 JSON（{text[:160]}）")
        if isinstance(body, dict):
            if body.get("success") is False:
                raise ToolError(f"{action}失败：{body.get('message') or '设备拒绝'}")
            error_code = body.get("error_code")
            if error_code not in (None, "", 0, "0"):
                raise ToolError(f"{action}失败：{body.get('message') or error_code}")
        return body

    # ---------- 会话 ----------

    def _login_bodies(self) -> list:
        if self.api_token:
            return [("token", {"api_token": self.api_token})]
        if not self.username or not self.password:
            raise ToolError("请填写 API Token，或填写用户名 + 密码")
        return [
            (
                "base64",
                {
                    "lang": DEFAULT_LOCALE,
                    "userName": _b64(self.username),
                    "password": _b64(self.password),
                },
            ),
            (
                "plain",
                {
                    "lang": DEFAULT_LOCALE,
                    "userName": self.username,
                    "password": self.password,
                    "encodeUserName": "0",
                    "encodePassword": "0",
                },
            ),
        ]

    def login(self) -> str:
        self.session = None
        self.cookies = {}
        self._log(f"登录 {self.base_url}（校验证书={self.verify_tls}，超时={self.timeout:g}s）")
        reasons = []
        for mode, body in self._login_bodies():
            self._log(f"   尝试方式：{mode}")
            try:
                payload = self._call("POST", LOGIN_PATH, payload=body, action="登录", retry=False)
            except ToolError as exc:
                reasons.append(f"{mode}: {exc}")
                continue
            items = self._items(payload)
            first = items[0] if items and isinstance(items[0], dict) else {}
            token = str(first.get("token") or "").strip()
            if not token:
                reasons.append(f"{mode}: 未返回 token")
                continue
            self.session = {
                "token": token,
                "role": str(first.get("role") or "admin"),
                "vsysId": str(first.get("vsysId") or "0"),
                "fromrootvsys": str(first.get("fromrootvsys") or "true"),
                "username": str(first.get("username") or self.username),
                "lang": DEFAULT_LOCALE,
            }
            self.cookies = {
                "fromrootvsys": self.session["fromrootvsys"],
                "role": self.session["role"],
                "vsysId": self.session["vsysId"],
                "token": token,
                "username": self.session["username"],
                "lang": DEFAULT_LOCALE,
            }
            self._log(
                f"登录成功（{mode}）：user={self.session['username']}，vsysId={self.session['vsysId']}，"
                f"role={self.session['role']}，token={mask_secret(token)}"
            )
            return token
        raise ToolError("登录失败：" + "；".join(reasons))

    def logout(self) -> None:
        self.session = None
        self.cookies = {}
        self._log("已清理本地会话（不等价于设备侧注销）")

    def test_connection(self) -> str:
        self.login()
        group = self._read_group()
        if group is None:
            return f"登录成功；地址簿组 {self.group_name} 尚不存在，首次封禁会创建"
        return f"登录成功；地址簿组 {self.group_name} 现有 {len(self._group_ips(group))} 个 IP"

    # ---------- 地址簿 ----------

    @staticmethod
    def _items(body) -> list:
        if isinstance(body, list):
            return body
        if isinstance(body, dict):
            result = body.get("result")
            if isinstance(result, list):
                return result
            if isinstance(result, dict):
                for key in ("data", "items", "list"):
                    value = result.get(key)
                    if isinstance(value, list):
                        return value
                return [result]
            if isinstance(body.get("data"), list):
                return body["data"]
        return []

    @classmethod
    def _group_ips(cls, group) -> list:
        found = []

        def walk(node):
            if isinstance(node, dict):
                value = node.get("ip_addr")
                if isinstance(value, str) and value.strip():
                    found.append(value.strip())
                for item in node.values():
                    walk(item)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(group.get("ip") if isinstance(group, dict) else group)
        seen, ordered = set(), []
        for ip in found:
            if ip not in seen:
                seen.add(ip)
                ordered.append(ip)
        return ordered

    def _read_group(self):
        query = {
            "conditions": [{"field": "name", "value": self.group_name}],
            "start": 0,
            "limit": QUERY_LIMIT,
            "page": 1,
        }
        body = self._call(
            "GET",
            ADDRBOOK_PATH,
            params={"query": json.dumps(query, ensure_ascii=False)},
            action="查询地址簿",
        )
        for item in self._items(body):
            if isinstance(item, dict) and str(item.get("name") or "") == self.group_name:
                return item
        return None

    def _write_group(self, ips: list, *, create: bool) -> None:
        payload = [
            {
                "name": self.group_name,
                "ip": [{"ip_addr": ip, "netmask": "32", "flag": 0} for ip in ips],
            }
        ]
        self._call(
            "POST" if create else "PUT",
            ADDRBOOK_PATH,
            payload=payload,
            action="新建地址簿组" if create else "覆盖地址簿组",
        )

    # ---------- 黑名单语义 ----------

    def entries(self, ip: str) -> list:
        target = check_ip(ip)
        group = self._read_group()
        if group is None:
            self._log(f"   地址簿组 {self.group_name} 不存在，判定：未封禁")
            return []
        ips = self._group_ips(group)
        self._log(f"   组内 {len(ips)} 个 IP，判定：{'已封禁' if target in ips else '未封禁'}")
        return [{"ip": target, "group": self.group_name}] if target in ips else []

    def block(self, ip: str, desc: str = "") -> str:
        target = check_ip(ip)
        for attempt in range(1, MAX_ATTEMPTS + 1):
            group = self._read_group()
            ips = self._group_ips(group) if group is not None else []
            if target in ips:
                return f"{target} 已在地址簿组 {self.group_name}，跳过"
            self._write_group(ips + [target], create=group is None)
            current = self._read_group()
            if current is not None and target in self._group_ips(current):
                return f"{target} 已加入地址簿组 {self.group_name}（第 {attempt} 次写入确认生效）"
            self._log(f"   写入后回读未见 {target}（第 {attempt} 次），重试")
        raise ToolError(f"添加 {target} 返回成功，但地址簿组 {self.group_name} 内复查未见该 IP")

    def unblock(self, ip: str) -> str:
        target = check_ip(ip)
        for attempt in range(1, MAX_ATTEMPTS + 1):
            group = self._read_group()
            ips = self._group_ips(group) if group is not None else []
            if target not in ips:
                return f"{target} 不在地址簿组 {self.group_name}，跳过"
            self._write_group([item for item in ips if item != target], create=False)
            current = self._read_group()
            if current is None or target not in self._group_ips(current):
                return f"{target} 已移出地址簿组 {self.group_name}（第 {attempt} 次写入确认生效）"
            self._log(f"   删除后回读仍有 {target}（第 {attempt} 次），重试")
        raise ToolError(f"删除 {target} 返回成功，但地址簿组 {self.group_name} 内复查仍有该 IP")

    def list_entries(self) -> list:
        group = self._read_group()
        ips = self._group_ips(group) if group is not None else []
        return [(ip, self.group_name) for ip in ips]
