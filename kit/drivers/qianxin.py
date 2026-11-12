"""奇安信防火墙协议客户端：/v1.0/login/ 取 token + sessionid，业务走 /v1.0/rest/。

封禁落点是「人工处置 → 网络连接」（module=threat_disposal）：地址黑名单只对源地址生效，
故每个 IP 下发两条处置项——sip 为该 IP 与 dip 为该 IP 各一条。
"""

from __future__ import annotations

import json
import socket
import ssl
import time
from http.cookies import SimpleCookie
from urllib import error as urlerror
from urllib import parse, request

from ..common import ToolError, check_ip, json_text, mask_secret

MODULE = "threat_disposal"
SOURCE = "manual"
DATATYPE = "connection"
# 处置时效取「永久」，解封由删除处置项完成
BLOCK_TIMEOUT = "forever"
# 处置项状态：封禁幂等只看「处置中」，解封要连「待响应」一起清（两者都可直接删除）
BLOCK_STATUSES = ("block",)
PENDING_STATUSES = ("block", "undisposed")
# 查询条件里的空值/0 都表示 any，比对时必须当作「不限」处理
ANY_TOKENS = ("", "0", "any")
PAGE_SIZE = 100
MAX_PAGES = 10


def _is_any(value) -> bool:
    return str(value or "").strip().lower() in ANY_TOKENS


def _direction(row: dict, statuses=BLOCK_STATUSES) -> str:
    """处置项方向：sip 有值且 dip 为空 → 源；dip 有值且 sip 为空 → 目的。"""
    if str(row.get("datatype") or "") != DATATYPE:
        return ""
    if str(row.get("status") or "") not in statuses:
        return ""
    if str(row.get("ipv4") or "yes") != "yes":
        return ""
    sip = str(row.get("sip") or "").strip()
    dip = str(row.get("dip") or "").strip()
    if sip and _is_any(dip):
        return "src"
    if dip and _is_any(sip):
        return "dst"
    return ""


def _direction_name(row: dict) -> str:
    return {"src": "源地址", "dst": "目的地址"}.get(_direction(row, PENDING_STATUSES), "?")


def _matches(row: dict, ip: str, statuses=BLOCK_STATUSES) -> bool:
    direction = _direction(row, statuses)
    if not direction:
        return False
    value = row.get("sip") if direction == "src" else row.get("dip")
    return str(value or "").strip() == ip


def _block_rule(ip: str, direction: str) -> dict:
    """单条处置项：只填一个方向，另一方向留空即 any。"""
    rule = {"ipv4": "yes", "timeout": BLOCK_TIMEOUT, "action": "block", "source": SOURCE, "datatype": DATATYPE}
    rule["sip" if direction == "src" else "dip"] = ip
    return rule


def _record_rule(row: dict, raw: bool = False) -> dict:
    """按五元组定位一条处置记录（撤销与删除共用）。

    默认与添加时同构（只带方向地址），部分固件要求把端口、协议等原值一并回传，
    此时用 raw=True 走「查询结果原样回传」的形态。
    """
    rule = {
        "ipv4": str(row.get("ipv4") or "yes"),
        "source": str(row.get("source") or SOURCE),
        "datatype": str(row.get("datatype") or DATATYPE),
    }
    if raw:
        for key in ("sip", "sport", "dip", "dport", "proto"):
            rule[key] = str(row.get(key) or "").strip()
        if row.get("dispose_id"):
            rule["dispose_id"] = str(row["dispose_id"])
        rule["action"] = str(row.get("action") or "block")
        rule["timeout"] = str(row.get("timeout") or BLOCK_TIMEOUT)
        return rule
    direction = _direction(row, PENDING_STATUSES) or ("src" if str(row.get("sip") or "").strip() else "dst")
    value = row.get("sip") if direction == "src" else row.get("dip")
    rule["sip" if direction == "src" else "dip"] = str(value or "").strip()
    return rule


class QianxinFW:
    """奇安信 rest 接口客户端。"""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
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
        self.verify_tls = bool(verify_tls)
        self.timeout = float(timeout or 10.0)
        self.cookies: dict[str, str] = {}
        self._log = log or (lambda _msg: None)

    @property
    def authenticated(self) -> bool:
        return bool(self.cookies.get("token"))

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
        headers = {"Accept": "application/json", "Content-Type": "application/json; charset=UTF-8"}
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())

        self._log(f"→ {method} {url}")
        if payload is not None:
            self._log(f"   请求体 {json_text(payload)}")
        if self.cookies:
            self._log(f"   Cookie {', '.join(sorted(self.cookies))}")

        req = request.Request(url, data=data, headers=headers, method=method)
        started = time.monotonic()
        try:
            with request.urlopen(req, timeout=self.timeout, context=self._ssl_context()) as resp:
                self._absorb_cookies(resp.headers)
                status = getattr(resp, "status", 200)
                text = resp.read().decode("utf-8", "replace")
                self._log_response(status, text, started)
                return status, text
        except urlerror.HTTPError as exc:
            self._absorb_cookies(exc.headers)
            text = exc.read().decode("utf-8", "replace")
            self._log_response(exc.code, text, started)
            return exc.code, text
        except TimeoutError:
            self._log(f"✗ 请求超时（{self.timeout:g}s）：{url}")
            raise ToolError(f"请求超时（{self.timeout:g}s）：{url}") from None
        except urlerror.URLError as exc:
            raise self._network_error(exc, url) from None

    def _absorb_cookies(self, headers) -> None:
        try:
            raw = headers.get_all("Set-Cookie") or []
        except AttributeError:
            raw = []
        for item in raw:
            jar = SimpleCookie()
            try:
                jar.load(item)
            except Exception:
                continue
            for name, morsel in jar.items():
                self.cookies[name] = morsel.value

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
            hint = "；连接被拒绝，端口未开放或被设备安全策略拦截"
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
    def _first(payload):
        """rest 请求体是列表，响应可能也是列表。"""
        if isinstance(payload, list):
            if not payload:
                raise ToolError("设备返回空结果")
            return payload[0]
        return payload

    # ---------- 会话 ----------

    def login(self) -> str:
        if not self.username or not self.password:
            raise ToolError("请填写用户名和密码")
        self._log(f"登录 {self.base_url}（用户 {self.username}，校验证书={self.verify_tls}，超时={self.timeout:g}s）")
        status, text = self._request(
            "POST", "/v1.0/login/", payload={"username": self.username, "password": self.password}
        )
        if status >= 400:
            raise ToolError(f"登录请求被拒绝（HTTP {status}）：{text[:200]}")
        payload = self._json(text, "登录")
        head = payload.get("head") or {}
        token = (payload.get("result") or {}).get("token")
        if not token:
            raise ToolError(f"登录失败：{head.get('error_message') or '设备未返回 token'}")
        self.cookies["token"] = token
        self._log(f"登录成功，token={mask_secret(token)}，cookie={sorted(self.cookies)}")
        return token

    def logout(self) -> None:
        if not self.cookies:
            return
        self._log("退出登录")
        try:
            self._request("POST", "/v1.0/out/", payload={"username": self.username})
        except ToolError as exc:
            self._log(f"退出登录失败（忽略）：{exc}")
        finally:
            self.cookies.clear()

    def test_connection(self) -> str:
        self.login()
        self.logout()
        return f"连接成功：{self.base_url}"

    # ---------- rest ----------

    def _rest(self, function: str, body: dict, action: str, page: int = 0):
        head = {"module": MODULE, "function": function}
        if page:
            head["page_index"] = page
            head["page_size"] = PAGE_SIZE
        payload = [{"head": head, "body": body}]
        status, text = self._request("POST", "/v1.0/rest/", payload=payload)
        if status >= 400:
            raise ToolError(f"{action}请求被拒绝（HTTP {status}）：{text[:200]}")
        result = self._first(self._json(text, action))
        head = (result or {}).get("head") or {}
        code = head.get("error_code")
        if code not in (0, "0", None):
            reason = head.get("error_string") or head.get("error_message") or code
            raise ToolError(f"{action}失败（error_code={code}）：{reason}")
        return result

    def _rows(self, searchkey: str) -> list[dict]:
        rows: list[dict] = []
        page = 1
        while page <= MAX_PAGES:
            result = self._rest(
                "get_threat_disposal",
                {
                    "threat_disposal_cfg_ext": {
                        "operation": "",
                        "is_later": "no",
                        "disposal_filter": {
                            "status": "",
                            "searchkey": searchkey,
                            "expired": "0",
                            "datatype": "",
                            "source": "",
                        },
                    }
                },
                "查询人工处置",
                page=page,
            )
            batch = [row for row in ((result or {}).get("data") or []) if isinstance(row, dict)]
            rows.extend(batch)
            total = str(((result or {}).get("head") or {}).get("total") or "-1").strip()
            if len(batch) < PAGE_SIZE or (total.lstrip("-").isdigit() and int(total) >= 0 and len(rows) >= int(total)):
                break
            page += 1
        return rows

    def entries(self, ip: str, statuses=BLOCK_STATUSES) -> list[dict]:
        """searchkey 是模糊查询、未必覆盖目的地址方向，未命中时退化为全量比对。"""
        target = check_ip(ip)
        self._log(f"查询 {target} 的人工处置记录")
        hits = [row for row in self._rows(target) if _matches(row, target, statuses)]
        if not hits:
            self._log("   searchkey 未命中，退化为全量比对")
            hits = [row for row in self._rows("") if _matches(row, target, statuses)]
        self._log(f"   匹配 {len(hits)} 条")
        for row in hits:
            self._log(
                f"   处置项：{_direction_name(row)} ip={row.get('sip') or row.get('dip')} "
                f"proto={row.get('proto') or 'any'} 失效={row.get('outoftime')}"
            )
        return hits

    def block(self, ip: str, desc: str = "") -> str:
        target = check_ip(ip)
        self._log(f"封禁 {target}（人工处置：源地址、目的地址各一条）")
        existing = {_direction(row) for row in self.entries(target)}
        missing = [direction for direction in ("src", "dst") if direction not in existing]
        if not missing:
            self._log(f"   跳过：{target} 已有源地址与目的地址处置")
            return f"{target} 已有源/目的两条处置，跳过"
        self._rest(
            "add_threat_disposal",
            {
                "threat_disposal_cfg_ext": {
                    "is_later": "no",
                    "threat_disposal_cfg": [_block_rule(target, d) for d in missing],
                }
            },
            "添加人工处置",
        )
        names = "、".join({"src": "源地址", "dst": "目的地址"}[d] for d in missing)
        self._log(f"   成功：{target} 已下发{names}（{len(missing)} 条）")
        return f"{target} 已加入人工处置（{names}）"

    def _submit(self, rows: list, function: str, action: str, operation: str = "") -> None:
        """先按添加同构、再按查询原值下发同一个操作；两次都被拒时抛最后一次错误。"""
        for raw in (False, True):
            ext = {"is_later": "no", "threat_disposal_cfg": [_record_rule(row, raw=raw) for row in rows]}
            if operation:
                ext["operation"] = operation
            try:
                self._rest(function, {"threat_disposal_cfg_ext": ext}, action)
                return
            except ToolError as exc:
                if raw:
                    raise
                self._log(f"   {action}被拒（{exc}），按设备原值重试")

    def unblock(self, ip: str) -> str:
        target = check_ip(ip)
        self._log(f"解封 {target}（删除人工处置记录）")
        entries = self.entries(target, PENDING_STATUSES)
        if not entries:
            self._log(f"   跳过：{target} 无人工处置记录")
            return f"{target} 无处置记录，跳过"
        active = [row for row in entries if _direction(row, BLOCK_STATUSES)]
        pending = [row for row in entries if not _direction(row, BLOCK_STATUSES)]
        parts = []
        # 处置中的记录直接删除即解除阻断；删除被拒才退回撤销（撤销会留下待响应记录）
        if active:
            try:
                self._submit(active, "del_threat_disposal", "删除人工处置记录")
            except ToolError as exc:
                self._log(f"   删除被拒（{exc}），改走撤销")
                self._submit(active, "set_threat_disposal", "撤销人工处置", operation="revoke")
                self._log(f"   已撤销 {len(active)} 条处置，记录以待响应状态留在列表")
                parts.append(f"撤销 {len(active)} 条处置，列表残留待响应条目")
            else:
                self._log(f"   成功：{target} 已删除 {len(active)} 条处置记录")
                parts.append(f"删除 {len(active)} 条处置")
        # 已是「待响应」的历史记录同样直接删，不做「恢复处置再删」那种反复改状态的绕路
        if pending:
            try:
                self._submit(pending, "del_threat_disposal", "删除待响应处置记录")
                self._log(f"   已删除待响应记录 {len(pending)} 条")
                parts.append(f"清理待响应记录 {len(pending)} 条")
            except ToolError as exc:
                self._log(f"   待响应记录删除被拒（{exc}），需在设备 WebUI 手工处理")
                parts.append(f"待响应记录 {len(pending)} 条删除被拒，需设备侧手工清理")
        return f"{target} 已解封（{'；'.join(parts)}）"
