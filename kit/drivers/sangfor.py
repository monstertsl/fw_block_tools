"""深信服 AF 协议客户端：登录换 token → token 放 cookie → whiteblacklist 增删查。

另支持「添加到地址对象」封禁方式（勾选后走 网络对象-地址）：
- 查询：GET    /ipgroups/{name}
- 新建：POST   /ipgroups          body={name, businessType:"IP", addressType:"IPV4", ipRanges:[...]}
- 增删成员：PATCH /ipgroups/{name}?_arrayop=add|remove  body 同上（只带变化的 ipRanges 元素）

地址对象有行数上限（AF 官方：单个网络对象最多 200 行 IP 地址或 IP 范围，各版本可能不同），
接口本身不返回上限值，因此添加前先回读现有行数做软校验，并解析设备报错文案兜底。
"""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import time
from urllib import error as urlerror
from urllib import parse, request

from ..common import ToolError, check_ip, json_text, mask_secret

DEFAULT_NAMESPACE = "@namespace"
BLACK_DESCRIPTION = "SenseMind联动封禁"
ADDRESS_DESCRIPTION = "SenseMind联动封禁"
ADDRESS_DEFAULT_NAME = "SenseMind-Block"
NOT_FOUND_CODE = 1004  # 设备的「资源不存在」语义码，比中文文案稳定
# 设备拒绝写入地址时的文案特征：命中即按「达到上限」给出可操作提示
LIMIT_ERROR_TOKENS = ("超过", "上限", "最多", "达到", "条数", "超限", "exceed", "maximum", "full")
# 响应体日志截断长度（地址对象全量 ipRanges 有几千字符，不整段打印）
RESPONSE_LOG_LIMIT = 240


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
        use_address: bool = False,
        address_name: str = ADDRESS_DEFAULT_NAME,
        confirm_create=None,
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
        # 地址对象封禁方式：True 时 block/unblock/entries 走 网络对象-地址
        self.use_address = bool(use_address)
        self.address_name = (address_name or "").strip() or ADDRESS_DEFAULT_NAME
        # 地址对象不存在时的确认回调（界面从后台线程弹确认框），返回 True 才新建
        self.confirm_create = confirm_create
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
            self._log(f"   响应体（非 JSON）{text.strip()[:RESPONSE_LOG_LIMIT]}")
            return
        body = json_text(payload)
        if len(body) > RESPONSE_LOG_LIMIT:
            # 大响应（如地址对象全量 ipRanges）只截取开头，避免刷屏
            body = f"{body[:RESPONSE_LOG_LIMIT]}…（{len(body)} 字符，略）"
        self._log(f"   响应体 {body}")

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

    # ---------- 地址对象（网络对象-地址） ----------

    def get_address(self, name: str | None = None) -> dict | None:
        """查地址对象：不存在（404 / code=1004 / code=22+空data / 文案含「不存在」）返回 None，存在返回 data。

        官方文档失败样例是 HTTP 200 + {"code":22,"data":"","message":"无效参数"}，
        即按名字查不到对象时 code 非 0 且 data 为空串，与黑白名单的 1004 语义码不同。
        """
        target = (name or self.address_name).strip()
        if not target:
            raise ToolError("请填写地址对象名")
        self._log(f"查询地址对象 {target}")
        status, text = self._request("GET", f"{self.base_path}/ipgroups/{parse.quote(target)}")
        if status == 404:
            self._log(f"   判定：HTTP 404 → 地址对象 {target} 不存在")
            return None
        if status >= 400:
            raise ToolError(f"查询地址对象失败（HTTP {status}）：{text[:200]}")
        payload = self._json(text, "查询地址对象")
        if self._is_not_found(payload):
            self._log(f"   判定：code={NOT_FOUND_CODE} → 地址对象 {target} 不存在")
            return None
        if "不存在" in text or "未找到" in text:
            self._log("   判定：响应含「不存在/未找到」→ 地址对象不存在")
            return None
        code = payload.get("code")
        data = payload.get("data")
        if code not in (0, "0") and (data == "" or data is None):
            # 名字查不到时的文档样例形态：code=22、data 为空串
            self._log(f"   判定：code={code} 且 data 为空 → 地址对象 {target} 不存在")
            return None
        if not isinstance(data, dict):
            self._log(f"   判定：data 是 {type(data).__name__}（期望对象）→ 视为地址对象不存在")
            return None
        ranges = data.get("ipRanges") or []
        self._log(f"   地址对象 {target} 现有 {len(ranges)} 行 IP/范围")
        return data

    @staticmethod
    def _address_lines(data: dict) -> list[dict]:
        """地址对象的 ipRanges 行列表（每行一个 IP 或 IP 范围）。"""
        ranges = data.get("ipRanges")
        if not isinstance(ranges, list):
            return []
        return [item for item in ranges if isinstance(item, dict)]

    @staticmethod
    def _ip_in_ranges(target: str, ranges: list[dict]) -> bool:
        """单 IP 是否已作为独立行存在（范围/CIDR 行不算命中，避免误判在范围内）。"""
        for item in ranges:
            start = str(item.get("start") or "").strip()
            end = str(item.get("end") or "").strip()
            if start == target and (not end or end == start) and not item.get("bits"):
                return True
        return False

    @staticmethod
    def _located_entry(target: str, ranges: list[dict]) -> dict | None:
        """IP 实际落在哪一行：独立行精确命中，或位于范围行/CIDR 行内。

        设备没有「查 IP 是否在对象内」的专用接口，只能拉全量 ipRanges 后本地判断。
        查询/展示用它如实反映「是否会被拦」，增删仍只针对独立行。
        """
        try:
            target_ip = ipaddress.ip_address(target)
        except ValueError:
            return None
        for item in ranges:
            start = str(item.get("start") or "").strip()
            end = str(item.get("end") or "").strip()
            bits = item.get("bits")
            if start == target and (not end or end == start) and not bits:
                return item
            try:
                lo = ipaddress.ip_address(start)
            except ValueError:
                continue
            if bits not in (None, "", 0, "0"):
                try:
                    net = ipaddress.ip_network(f"{start}/{bits}", strict=False)
                except ValueError:
                    continue
                if target_ip in net:
                    return item
                continue
            if end:
                try:
                    hi = ipaddress.ip_address(end)
                except ValueError:
                    continue
                if lo <= target_ip <= hi:
                    return item
        return None

    @staticmethod
    def _range_label(item: dict) -> str:
        """范围/CIDR 行的可读描述，用于日志与提示。"""
        start = str(item.get("start") or "?").strip()
        end = str(item.get("end") or "").strip()
        bits = item.get("bits")
        if bits not in (None, "", 0, "0"):
            return f"{start}/{bits}"
        if end and end != start:
            return f"{start}-{end}"
        return start

    def _create_address(self, name: str, ips: list[str], desc: str = "") -> None:
        """新建 IP 类型地址对象，初始成员为 ips。

        文档 Body 参数写 `netobj` 但没给请求样例，无法确定是否要 {"netobj": {...}} 包裹：
        先发扁平 body（与黑白名单一致），设备回 code=22/无效参数或 HTTP 4xx 时改包裹重试一次。
        """
        body = {
            "name": name,
            "businessType": "IP",
            "addressType": "IPV4",
            "description": (desc or "").strip() or ADDRESS_DESCRIPTION,
            "ipRanges": [{"start": ip} for ip in ips],
        }
        self._log(f"新建地址对象 {name}（初始 {len(ips)} 行）")
        status, text = self._request("POST", f"{self.base_path}/ipgroups", body=body)
        if self._invalid_body(status, text):
            self._log("   设备判定无效参数，改用 {\"netobj\": …} 包裹重试")
            status, text = self._request("POST", f"{self.base_path}/ipgroups", body={"netobj": body})
        if status >= 400:
            raise ToolError(f"新建地址对象失败（HTTP {status}）：{text[:200]}")
        self._ensure_ok(self._json(text, "新建地址对象"), "新建地址对象", status)

    def _patch_address(self, name: str, ip: str, op: str) -> None:
        """增量增删地址对象成员：_arrayop=add|remove，只带这一行 ipRanges。

        body 包裹方式与新建同理：先扁平，无效参数时再 {"netobj": …} 包裹重试。
        """
        body = {"name": name, "businessType": "IP", "ipRanges": [{"start": ip}]}
        verb = "添加" if op == "add" else "删除"
        status, text = self._request(
            "PATCH", f"{self.base_path}/ipgroups/{parse.quote(name)}", body=body, params={"_arrayop": op}
        )
        if self._invalid_body(status, text):
            self._log("   设备判定无效参数，改用 {\"netobj\": …} 包裹重试")
            status, text = self._request(
                "PATCH",
                f"{self.base_path}/ipgroups/{parse.quote(name)}",
                body={"netobj": body},
                params={"_arrayop": op},
            )
        if status >= 400 or self._is_limit_rejection(status, text):
            message = self._limit_message(text) or f"HTTP {status}：{text[:200]}"
            hint = ""
            if self._looks_like_limit_error(message):
                hint = "地址对象可能已达该版本的行数上限，请更换其他地址对象或新建一个再试"
            raise ToolError(f"{verb}地址对象成员失败：{message}。{hint}".strip())
        try:
            payload = self._json(text, "修改地址对象")
        except ToolError:
            self._log(f"   {verb}响应非 JSON（{text.strip()[:120]}），按成功处理")
            return
        self._ensure_ok(payload, "修改地址对象", status)

    @staticmethod
    def _invalid_body(status: int, text: str) -> bool:
        """文档失败样例：HTTP 200 + code=22「无效参数」；HTTP 4xx 同样视为被拒。"""
        if status >= 400:
            return True
        try:
            payload = json.loads(text)
        except ValueError:
            return False
        if not isinstance(payload, dict):
            return False
        if payload.get("code") in (0, "0") or payload.get("message") == "成功":
            return False
        message = str(payload.get("message") or "")
        return payload.get("code") in (22, "22") or "无效参数" in message or "无效" in message


    def _is_limit_rejection(self, status: int, text: str) -> bool:
        """HTTP 200 但业务失败且文案像「超上限」时也按上限处理。"""
        if status >= 400:
            return False
        try:
            payload = json.loads(text)
        except ValueError:
            return False
        if not isinstance(payload, dict):
            return False
        if payload.get("code") in (0, "0") or payload.get("message") == "成功":
            return False
        return self._looks_like_limit_error(payload.get("message") or "")

    @staticmethod
    def _limit_message(text: str) -> str:
        try:
            payload = json.loads(text)
        except ValueError:
            return ""
        if isinstance(payload, dict):
            return str(payload.get("message") or "")
        return ""

    @staticmethod
    def _looks_like_limit_error(message: str) -> bool:
        text = str(message or "").lower()
        return any(token in text for token in LIMIT_ERROR_TOKENS)

    def _confirm_create_address(self, name: str) -> bool:
        """地址对象不存在时询问是否新建；没有确认回调（纯脚本调用）时拒绝新建。"""
        if self.confirm_create is None:
            self._log(f"   地址对象 {name} 不存在，且无确认回调，不自动新建")
            return False
        return bool(self.confirm_create(name))

    def _address_add(self, target: str, desc: str = "") -> str:
        name = self.address_name
        data = self.get_address(name)
        if data is None:
            if not self._confirm_create_address(name):
                return f"{target} 跳过（地址对象 {name} 不存在，未确认新建）"
            self._create_address(name, [target], desc)
            self._log(f"   成功：新建地址对象 {name} 并写入 {target}")
            return f"{target} 已加入地址对象 {name}（新建完成）"
        ranges = self._address_lines(data)
        if self._ip_in_ranges(target, ranges):
            self._log(f"   跳过：{target} 已是地址对象 {name} 的独立行")
            return f"{target} 已在地址对象 {name}，跳过"
        # 行数上限不做本地预判（各版本不同），以设备返回的报错为准，见 _patch_address 的转译
        self._patch_address(name, target, "add")
        self._log(f"   成功：{target} 已写入地址对象 {name}")
        return f"{target} 已加入地址对象 {name}（现有 {len(ranges) + 1} 行）"

    def _address_remove(self, target: str) -> str:
        name = self.address_name
        data = self.get_address(name)
        if data is None:
            self._log(f"   跳过：地址对象 {name} 不存在")
            return f"{target} 不在地址对象 {name}（对象不存在），跳过"
        ranges = self._address_lines(data)
        if not self._ip_in_ranges(target, ranges):
            located = self._located_entry(target, ranges)
            if located is not None:
                self._log(f"   跳过：{target} 位于范围行 {self._range_label(located)} 内，工具不做范围拆分")
                return f"{target} 位于地址对象 {name} 的范围行 {self._range_label(located)} 内，无法单独删除，跳过"
            self._log(f"   跳过：{target} 不在地址对象 {name} 里")
            return f"{target} 不在地址对象 {name} 里，跳过"
        self._patch_address(name, target, "remove")
        self._log(f"   成功：{target} 已从地址对象 {name} 删除")
        return f"{target} 已从地址对象 {name} 删除"

    # ---------- 网络对象反查（IP 在哪些网络对象中） ----------

    def fetch_ipgroups(self) -> list[dict]:
        """分页拉取全部 IP 类型网络对象（列表项自带 ipRanges，无需逐个查详情）。

        excludeAll=TRUE 过滤掉默认的「全部」（0.0.0.0-255.255.255.255），
        否则任何 IP 都会命中它，反查结果没有意义。
        """
        items: list[dict] = []
        page_size = 200  # 文档 _length 上限 200
        start = 0
        while True:
            params = {
                "addressType": "IPV4",
                "businessType": "IP",
                "excludeAll": "TRUE",
                # 反查只需要名字和成员，用 _select 让设备少返回字段，减小响应体
                "_select": "name,ipRanges",
                "_start": start,
                "_length": page_size,
            }
            status, text = self._request("GET", f"{self.base_path}/ipgroups", params=params)
            if status >= 400:
                raise ToolError(f"查询网络对象列表失败（HTTP {status}）：{text[:200]}")
            payload = self._json(text, "查询网络对象列表")
            self._ensure_ok(payload, "查询网络对象列表", status)
            data = payload.get("data") or {}
            batch = data.get("items") if isinstance(data, dict) else None
            if not isinstance(batch, list):
                self._log("   列表响应没有 items 字段，按无对象处理")
                break
            items.extend(item for item in batch if isinstance(item, dict))
            if len(batch) < page_size:
                break
            start += len(batch)
            if start > 100000:  # 防御：对象数异常时不再翻页
                self._log("   网络对象数量异常，停止分页")
                break
        self._log(f"共取到 {len(items)} 个 IP 类型网络对象")
        return items

    def locate_ip(self, ip: str, groups: list[dict] | None = None) -> list[dict]:
        """反查 IP 出现在哪些网络对象里，返回 [{name, exact, label}]。

        exact=True 表示是独立行（可以单独删除）；False 表示位于范围行/CIDR 行内。
        groups 传入已拉取的对象列表可避免批量场景重复分页。
        """
        target = check_ip(ip)
        if groups is None:
            groups = self.fetch_ipgroups()
        hits: list[dict] = []
        for item in groups:
            ranges = self._address_lines(item)
            located = self._located_entry(target, ranges)
            if located is None:
                continue
            hits.append(
                {
                    "name": str(item.get("name") or ""),
                    "exact": self._ip_in_ranges(target, ranges),
                    "label": self._range_label(located),
                }
            )
        return hits

    def _block_hint(self, target: str) -> str:
        """封禁前的反查提示：IP 已在网络对象中时返回对象名（顿号连接），否则空串。"""
        try:
            hits = self.locate_ip(target)
        except ToolError as exc:
            self._log(f"   网络对象反查失败（忽略，继续封禁）：{exc}")
            return ""
        names = [h["name"] for h in hits if h["name"]]
        if not names:
            return ""
        self._log(f"   提示：{target} 已在网络对象「{'、'.join(names)}」中")
        return "、".join(names)

    def remove_from_object(self, name: str, ip: str) -> str:
        """把 IP 从指定网络对象中提出；不是独立行（范围/CIDR 行内）时跳过。"""
        target = check_ip(ip)
        data = self.get_address(name)
        if data is None:
            self._log(f"   跳过：网络对象 {name} 不存在")
            return f"{ip} 所在网络对象「{name}」不存在，跳过"
        ranges = self._address_lines(data)
        if not self._ip_in_ranges(target, ranges):
            located = self._located_entry(target, ranges)
            if located is not None:
                label = self._range_label(located)
                self._log(f"   跳过：{target} 位于「{name}」的范围行 {label} 内")
                return f"{ip} 位于「{name}」的范围行 {label} 内，无法单独删除，跳过"
            self._log(f"   跳过：{target} 已不在「{name}」中")
            return f"{ip} 已不在网络对象「{name}」中，跳过"
        self._patch_address(name, target, "remove")
        self._log(f"   成功：{target} 已从网络对象 {name} 删除")
        return f"{ip} 已从网络对象「{name}」删除"

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
        """查单 IP：网络对象归属（反查全部对象）+ 黑名单条目，两部分都返回。"""
        target = check_ip(ip)
        results: list[dict] = []
        try:
            for hit in self.locate_ip(target):
                desc = "独立行成员" if hit["exact"] else f"位于范围行 {hit['label']} 内"
                self._log(f"   判定：{target} 在网络对象「{hit['name']}」中（{desc}）")
                results.append({"name": hit["name"], "type": "网络对象", "enable": True, "desc": desc})
        except ToolError as exc:
            self._log(f"   网络对象反查失败（忽略）：{exc}")
        self._log(f"查询 {target} 在设备侧的黑名单条目")
        data = self._query_entry(target)
        if data is not None:
            blocked = self._is_blocked(data)
            self._log(
                f"   条目字段：type={data.get('type')} enable={data.get('enable')} "
                f"urlType={data.get('urlType')} domain={data.get('domain')} description={data.get('description')}"
            )
            if blocked:
                self._log("   判定：已在黑名单")
                results.append(data)
            else:
                self._log(f"   判定：设备上是{entry_kind(data)}，不算封禁")
        return results

    def block(self, ip: str, desc: str = BLACK_DESCRIPTION) -> str:
        target = check_ip(ip)
        # 封禁前先反查：IP 已在某个网络对象中就提示（不阻断，继续封禁）
        hint = self._block_hint(target)
        if self.use_address:
            self._log(f"封禁 {target}（地址对象 {self.address_name}）")
            result = self._address_add(target, desc)
        else:
            result = self._blacklist_block(target, desc)
        if hint:
            result = f"{result}（提示：该 IP 已在网络对象「{hint}」中）"
        return result

    def _blacklist_block(self, target: str, desc: str) -> str:
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
        """黑名单解封：原逻辑，不需要确认。

        网络对象侧的解封（发现式、需人工确认）由界面编排：
        locate_ip() 找出对象 → 弹窗确认 → remove_from_object() 逐个提出。
        """
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


