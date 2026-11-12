"""天融信 WebUI 表单接口客户端：AES 加密码令登录，token 每次响应轮转，codeRun 校验。"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import socket
import ssl
import time
from http.cookies import SimpleCookie
from urllib import error as urlerror
from urllib import parse, request

from ..common import ToolError, check_ip, json_text, mask_secret

LOGIN_PATH = "/home/login/addNoCode/"
LOGOUT_PATH = "/home/index/logout/"
RESTLOGOUT_PATH = "/home/restLogout/"
# 落点：安全策略 → 黑白名单 → 静态黑名单。能操作这份名单的接口有两套，按设备能力二选一（详见 _use_static）：
#   static = blackWhite，新固件，条目 mark=ip、带 ipaddr + direction
#   spread = blackListSpread，老固件，条目 mark=tuple、是五元组 sip/dip
STATIC_SEARCH = "/home/default/blackWhite/addrStaticBlackSearch/"
STATIC_ADD = "/home/default/blackWhite/whiteIpAdd/"
STATIC_POLICY_GROUP = "/home/default/blackWhite/showPolicyGroup/"
SPREAD_ADD = "/home/default/blackListSpread/add/"
SPREAD_SHOW_ALL = "/home/default/blackListSpread/showAll/"
# 两套落点共用同一个删除入口，靠命令名区分：静态黑名单 blacklist_cfg_delete_ip、五元组 pf_blacklist_delete
BLACKLIST_DELETE = "/home/default/blackListSpread/deleteLots/"
# 源方向必须封住（只有它拦得住攻击源主动发来的流量）；目的方向尽力下发，被拒只记日志
BLOCK_DIRECTIONS = ("src", "dst")
# 五元组里方向对应的维度
DIRECTION_FIELDS = {"src": "sip", "dst": "dip"}
# 五元组删除要原样带回的维度，空数组表示该维度不限，下发空串
TUPLE_FIELDS = ("sip", "sport", "dip", "dport", "l4_protocol")
# 静态黑名单的策略组：只能用设备列表里实际存在的名字，查不到就不传
DEFAULT_GROUP = "default_group"
BLOCK_COMMENT = "SenseMind联动封禁"

LOGIN_AES_KEY = "ngfwrestapilogin"
LOGIN_AES_IV = "ngfwrestapilogin"
RESTLOGIN_PATH = "/home/restLogin/"
# restLogin 的口令与长度加密固定用 16 个 1（官方示例注释）
REST_LOGIN_AES_KEY = "1111111111111111"
REST_LOGIN_AES_IV = "1111111111111111"


# ---------- AES-128-CBC（零填充）纯 Python 实现 ----------

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)


def _xtime(value: int) -> int:
    value <<= 1
    if value & 0x100:
        value ^= 0x11B
    return value & 0xFF


def _gmul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        b >>= 1
        a = _xtime(a)
    return result


def _expand_key(key: bytes) -> list[bytes]:
    """AES-128 密钥扩展：44 个字，按 4 字拼成 11 组轮密钥（每组 16 字节）。"""
    words = [bytearray(key[i * 4 : i * 4 + 4]) for i in range(4)]
    rcon = 1
    for index in range(4, 44):
        temp = bytearray(words[index - 1])
        if index % 4 == 0:
            temp = bytearray(_SBOX[b] for b in (temp[1:] + temp[:1]))
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        words.append(bytearray(a ^ b for a, b in zip(words[index - 4], temp)))
    return [b"".join(bytes(word) for word in words[index * 4 : index * 4 + 4]) for index in range(11)]


def _shift_rows(state: bytearray) -> bytearray:
    out = bytearray(16)
    for row in range(4):
        for col in range(4):
            out[col * 4 + row] = state[((col + row) % 4) * 4 + row]
    return out


def _mix_columns(state: bytearray) -> bytearray:
    out = bytearray(16)
    for col in range(4):
        a = state[col * 4 : col * 4 + 4]
        out[col * 4 + 0] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
        out[col * 4 + 1] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
        out[col * 4 + 2] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
        out[col * 4 + 3] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
    return out


def aes_encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    state = bytearray(a ^ b for a, b in zip(block, round_keys[0]))
    for round_index in range(1, 11):
        state = bytearray(_SBOX[b] for b in state)
        state = _shift_rows(state)
        if round_index != 10:
            state = _mix_columns(state)
        state = bytearray(a ^ b for a, b in zip(state, round_keys[round_index]))
    return bytes(state)


def aes_cbc_zero_base64(text: str, key: str, iv: str) -> str:
    """AES-CBC + 零填充 + 标准 base64，与设备登录要求一致。"""
    key_bytes = key.encode("utf-8")
    iv_bytes = iv.encode("utf-8")
    if len(key_bytes) not in (16, 24, 32):
        raise ToolError("AES 密钥长度必须是 16/24/32 字节")
    if len(iv_bytes) != 16:
        raise ToolError("AES IV 长度必须是 16 字节")
    raw = text.encode("utf-8")
    padded = raw + b"\x00" * ((-len(raw)) % 16)
    if not padded:
        padded = b"\x00" * 16
    round_keys = _expand_key(key_bytes)
    previous = bytearray(iv_bytes)
    out = bytearray()
    for offset in range(0, len(padded), 16):
        block = bytearray(a ^ b for a, b in zip(padded[offset : offset + 16], previous))
        encrypted = aes_encrypt_block(bytes(block), round_keys)
        out += encrypted
        previous = bytearray(encrypted)
    return base64.b64encode(bytes(out)).decode("ascii")


def aes_selfcheck() -> bool:
    """FIPS-197 附录 C.1 向量自检，确认内置 AES 实现正确。"""
    round_keys = _expand_key(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    cipher = aes_encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff"), round_keys)
    return cipher.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


# ---------- 表单与校验 ----------


def split_token_prefix(text: str) -> tuple[str, str]:
    """响应形如 `?[TOKEN}?<body>`；无前缀时 token 为空、body 为原文。"""
    if "?[" not in text:
        return "", text
    tail = text.split("?[", 1)[1]
    if "}?" not in tail:
        return "", text
    token, body = tail.split("}?", 1)
    return token.strip(), body.strip()


def flatten(name: str, value, out: dict) -> None:
    """嵌套命令字典 → `commands[0][pf_blacklist_add][sip]=1.1.1.1` 表单字段。"""
    if isinstance(value, dict):
        for key, item in value.items():
            flatten(f"{name}[{key}]", item, out)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            flatten(f"{name}[{index}]", item, out)
        return
    if value is None:
        out[name] = ""
    elif isinstance(value, bool):
        out[name] = "true" if value else "false"
    else:
        out[name] = str(value)


def build_query(params: dict) -> str:
    """拼 query 串。

    键必须保持原样：设备按 `commands[0][pf_blacklist_add][sip]` 字面解析参数，
    键里的 `[` `]` 一旦被百分号编码就解析不出 commands，返回「无效输入，分析错误」。
    """
    return "&".join(f"{key}={parse.quote_plus(str(value))}" for key, value in params.items())


def _sign_value(value):
    """数字键字典还原成 JSON 数组。

    设备把 `commands[0][x][0]=v` 还原成 `[{"x":["v"]}]`，codeRun 也按数组算；
    命令里用 `{"0": ...}` 只是为了让 flatten 能拼出带下标的字段名。
    """
    if isinstance(value, dict):
        if value and all(str(key).isdigit() for key in value):
            ordered = sorted(value, key=lambda key: int(str(key)))
            return [_sign_value(value[key]) for key in ordered]
        return {key: _sign_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sign_value(item) for item in value]
    return value


def code_run(secret: str, token: str, url: str, commands: dict) -> str:
    serialized = json.dumps(_sign_value(commands), ensure_ascii=False, separators=(",", ":"))
    return hashlib.md5((secret + token + url + serialized).encode("utf-8")).hexdigest()


def decode_login_body(body: str) -> dict:
    text = (body or "").strip()
    try:
        decoded = base64.b64decode(text).decode("utf-8")
    except Exception:
        decoded = text
    try:
        payload = json.loads(decoded)
    except ValueError:
        raise ToolError("登录响应不是有效 JSON") from None
    return payload if isinstance(payload, dict) else {}


class TopsecFW:
    """天融信 WebUI 表单接口客户端。"""

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
        self.token = ""
        self.user_mark = ""
        self.secret = ""
        self._rest_login = False  # True 表示走 /home/restLogin/，登出必须用 /home/restLogout/
        self._mode = ""  # ""=还没探测；"static"=静态黑名单；"spread"=黑名单传播五元组
        self._group = ""  # 静态黑名单的策略组，空串表示不传
        self._log = log or (lambda _msg: None)

    @property
    def authenticated(self) -> bool:
        return bool(self.user_mark)

    # ---------- HTTP ----------

    def _ssl_context(self):
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

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

    def _request(self, method: str, path: str, *, params=None, data=None, referer: bool = True):
        url = self.base_url + path
        if params:
            url += "?" + build_query(params)
        body = None
        headers = {"Accept": "application/json, text/plain, */*"}
        if data is not None:
            # 表单键同样是 commands[0][...] 字面量，编码后设备解析不出命令
            body = build_query(data).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if referer and self.user_mark:
            headers["Referer"] = f"{self.base_url}/html/webui/home.html/?userMark={self.user_mark}"
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())

        self._log(f"→ {method} {url}")
        if data is not None:
            self._log(f"   表单 {json_text(data)}")

        req = request.Request(url, data=body, headers=headers, method=method)
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

    def _log_response(self, status: int, text: str, started: float) -> None:
        elapsed = (time.monotonic() - started) * 1000
        self._log(f"← HTTP {status}（{elapsed:.0f} ms，{len(text)} 字符）")
        token, body = split_token_prefix(text)
        if token:
            self._log(f"   响应 token={mask_secret(token)}")
        self._log(f"   响应体 {body.strip()[:1500]}")

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

    def _finish(self, status: int, text: str) -> str:
        if status >= 400:
            raise ToolError(f"设备返回 HTTP {status}：{text[:200]}")
        token, body = split_token_prefix(text)
        if token and token != self.token:
            self.token = token
            self._log(f"   token 轮转 → {mask_secret(token)}")
        return body

    def post(self, path: str, commands: dict) -> str:
        # token / codeRun 放 query、commands 放表单，与设备 WebUI 的请求形态一致
        fields: dict = {}
        flatten("commands", commands, fields)
        params: dict = {"userMark": self.user_mark}
        if self.token:
            params["token"] = self.token
        if self.secret:
            params["codeRun"] = code_run(self.secret, self.token, path, commands)
        status, text = self._request("POST", path, params=params, data=fields)
        return self._finish(status, text)

    def get(self, path: str, commands: dict | None = None) -> str:
        params: dict = {"userMark": self.user_mark}
        if commands:
            flatten("commands", commands, params)
        if self.token:
            params["token"] = self.token
        # 登出这类命令为空（`{}`）的请求同样要带 codeRun，故判 None 而不是真假
        if commands is not None and self.secret:
            params["codeRun"] = code_run(self.secret, self.token, path, commands)
        status, text = self._request("GET", path, params=params)
        return self._finish(status, text)

    # ---------- 会话 ----------

    def login(self) -> str:
        if not self.username or not self.password:
            raise ToolError("请填写用户名和密码")
        self._log(f"登录 {self.base_url}（用户 {self.username}，校验证书={self.verify_tls}，超时={self.timeout:g}s）")
        try:
            return self._login_restlogin()
        except ToolError as exc:
            # 3.7 起只有 restLogin；更老的固件没有它时（返回 404）改试 addNoCode
            if "HTTP 404" not in str(exc):
                raise
            self._log("   该固件不支持 /home/restLogin/（HTTP 404），改试 /home/login/addNoCode/")
        return self._login_addnocode()

    def _login_addnocode(self) -> str:
        self._rest_login = False
        cipher = aes_cbc_zero_base64(self.password, LOGIN_AES_KEY, LOGIN_AES_IV)
        self._log(f"   口令 AES-CBC 加密后 {mask_secret(cipher)}，pwdlen={len(self.password)}")
        status, text = self._request(
            "POST",
            LOGIN_PATH,
            data={"name": self.username, "password": cipher, "pwdlen": len(self.password)},
            referer=False,
        )
        if status >= 400:
            raise ToolError(f"登录请求被拒绝（HTTP {status}）：{text[:200]}")
        token, body = split_token_prefix(text)
        return self._absorb_login(decode_login_body(body), token)

    def _login_restlogin(self) -> str:
        self._rest_login = True
        cipher = aes_cbc_zero_base64(self.password, REST_LOGIN_AES_KEY, REST_LOGIN_AES_IV)
        length = aes_cbc_zero_base64(str(len(self.password)), REST_LOGIN_AES_KEY, REST_LOGIN_AES_IV)
        self._log(
            f"   口令 AES-CBC(restLogin) 加密后 {mask_secret(cipher)}，"
            f"pwdlen={len(self.password)} 加密后 {mask_secret(length)}"
        )
        status, text = self._request(
            "POST",
            RESTLOGIN_PATH,
            data={"name": self.username, "password": cipher, "ngtosAuth": length},
            referer=False,
        )
        if status >= 400:
            raise ToolError(f"restLogin 请求被拒绝（HTTP {status}）：{text[:200]}")
        token, body = split_token_prefix(text)
        try:
            payload = json.loads(body)
        except ValueError:
            raise ToolError("restLogin 响应不是有效 JSON") from None
        payload = payload if isinstance(payload, dict) else {}
        tokens = payload.get("tokens") or []
        if not token:
            # 登录响应不带 token 前缀时，token 由 tokens 数组给出（示例取第 2 个）
            token = str(tokens[1]) if len(tokens) > 1 else (str(tokens[0]) if tokens else "")
        return self._absorb_login(payload, token)

    def _absorb_login(self, payload: dict, token: str) -> str:
        data = payload.get("data")
        if payload.get("result") is not True:
            reason = data if isinstance(data, str) else "设备拒绝登录"
            raise ToolError(f"登录失败：{reason}")
        data = data if isinstance(data, dict) else {}
        self.user_mark = str(data.get("authid") or "").strip()
        if not self.user_mark:
            raise ToolError("登录响应未返回 authid")
        # addNoCode 把 secret 放在 data 里，restLogin 放在顶层
        self.secret = str(payload.get("secret") or data.get("secret") or "").strip()
        self.token = token
        self._log(
            f"登录成功：userMark={mask_secret(self.user_mark)}，"
            f"secret={mask_secret(self.secret)}，token={mask_secret(self.token)}"
        )
        return self.token

    def logout(self) -> None:
        if not self.user_mark:
            return
        self._log("退出登录")
        try:
            # 两条登录线路的退登接口不同；命令为空（{}）也要带 codeRun，否则设备报 Parameter tampered
            self.get(RESTLOGOUT_PATH if self._rest_login else LOGOUT_PATH, {})
        except ToolError as exc:
            self._log(f"退出登录失败（忽略）：{exc}")
        finally:
            self.token = ""
            self.user_mark = ""
            self.secret = ""
            self._mode = ""
            self._group = ""
            self.cookies.clear()

    def test_connection(self) -> str:
        self.login()
        self.logout()
        return f"连接成功：{self.base_url}"

    # ---------- 黑名单 ----------

    @staticmethod
    def _value(row: dict, key: str) -> str:
        """取条目里某个维度的值：单值字段是字符串，多值字段是数组（空数组表示该维度不限）。"""
        value = row.get(key)
        if isinstance(value, list):
            return str(value[0]).strip() if value else ""
        return "" if value is None else str(value).strip()

    @staticmethod
    def _holds(row: dict, key: str, ip: str) -> bool:
        """条目的某个维度里是否包含这个 IP（多值字段逐个比）。"""
        value = row.get(key)
        items = value if isinstance(value, list) else [value]
        return any(item and str(item).strip() == ip for item in items)

    def _range_covers(self, row: dict, ip: str) -> bool:
        start = self._value(row, "ip_start")
        end = self._value(row, "ip_end")
        if not start or not end:
            return False
        try:
            target = ipaddress.ip_address(ip)
            return ipaddress.ip_address(start) <= target <= ipaddress.ip_address(end)
        except ValueError:
            return False

    def _matches(self, row: dict, ip: str) -> bool:
        """条目是否命中该 IP：静态黑名单看 ipaddr，五元组看 sip/dip，地址段看 ip_start/ip_end。"""
        return (
            self._holds(row, "ipaddr", ip)
            or self._holds(row, "sip", ip)
            or self._holds(row, "dip", ip)
            or self._range_covers(row, ip)
        )

    def _query(self, path: str, commands: dict, action: str) -> dict:
        body = self.get(path, commands)
        try:
            payload = json.loads(body)
        except ValueError:
            raise ToolError(f"{action}失败：响应不是有效 JSON（{body[:160]}）") from None
        if not isinstance(payload, dict):
            raise ToolError(f"{action}失败：响应不是 JSON 对象")
        if payload.get("result") is False:
            reason = payload.get("data")
            reason = reason if isinstance(reason, str) and reason else "设备未返回原因"
            raise ToolError(f"{action}被设备拒绝：{reason}")
        return payload

    def _use_static(self) -> bool:
        """探测该设备能用的落点，True = 静态黑名单，False = 黑名单传播五元组。

        探针用「查策略组」而不是「添加」：3.7 的静态黑名单同一 IP 只允许一条记录，添加被拒
        不等于模块不可用；而策略组接口报「cfg文件不存在」说明这套配置在设备上根本不存在，
        此时 whiteIpAdd 无论带不带 group_name 都加不进去（真机实测）。
        """
        if self._mode:
            return self._mode == "static"
        try:
            payload = self._query(
                STATIC_POLICY_GROUP, [{"blacklist_profile_group_show": {"from": "1", "num": "20"}}], "查询策略组"
            )
        except ToolError as exc:
            self._log(f"   静态黑名单接口 blackWhite 不可用（{exc}），改用黑名单传播接口 blackListSpread")
            self._mode = "spread"
            return False
        names = [
            str(row.get("name") or "").strip()
            for row in (payload.get("rows") or [])
            if isinstance(row, dict) and str(row.get("name") or "").strip()
        ]
        if DEFAULT_GROUP in names:
            self._group = DEFAULT_GROUP
        else:
            self._group = names[0] if names else ""
        self._mode = "static"
        self._log(f"   使用静态黑名单接口 blackWhite（策略组：{self._group or '不传'}）")
        return True

    def entries(self, ip: str) -> list[dict]:
        """该 IP 命中的全部条目。

        静态黑名单先按 IP 精确搜（`detail`），搜不了就退 `showAll` 全量本地比对；
        五元组没有可按 IP 搜的可用接口，直接 `showAll`。
        """
        target = check_ip(ip)
        self._log(f"查询 {target} 是否在黑名单")
        if self._use_static():
            try:
                payload = self._query(
                    STATIC_SEARCH,
                    [{"pf_blacklist_static_search": {"detail": target, "from": "1", "num": "20"}}],
                    "查询黑名单",
                )
                rows = [row for row in (payload.get("rows") or []) if isinstance(row, dict)]
                hits = [row for row in rows if self._matches(row, target)]
                self._log(f"   静态黑名单返回 {len(rows)} 条，命中 {len(hits)} 条")
                self._log(f"   判定：{'已封禁' if hits else '不在黑名单'}")
                return hits
            except ToolError as exc:
                self._log(f"   {exc}，改为拉取全部记录比对")
        payload = self._query(SPREAD_SHOW_ALL, {"0": {"pf_blacklist_show_all": ""}}, "查询全部黑名单")
        rows = [row for row in (payload.get("rows") or []) if isinstance(row, dict)]
        hits = [row for row in rows if self._matches(row, target)]
        self._log(f"   黑名单共 {len(rows)} 条（total={payload.get('total')}），命中 {len(hits)} 条")
        for row in hits:
            self._log(
                f"   条目：mark={row.get('mark')} ipaddr={row.get('ipaddr')} sip={row.get('sip')} dip={row.get('dip')}"
            )
        self._log(f"   判定：{'已封禁' if hits else '不在黑名单'}")
        return hits

    @staticmethod
    def _expect_result(body: str, action: str) -> None:
        try:
            payload = json.loads(body)
        except ValueError:
            raise ToolError(f"{action}失败：响应不是有效 JSON（{body[:160]}）") from None
        if not isinstance(payload, dict):
            raise ToolError(f"{action}失败：响应不是 JSON 对象")
        if payload.get("result") is not True:
            reason = payload.get("data")
            reason = reason if isinstance(reason, str) and reason else "设备未返回原因"
            raise ToolError(f"{action}失败：{reason}")

    def _covered(self, entries: list[dict], ip: str) -> set[str]:
        """已封住的方向。

        静态黑名单条目自带 direction；五元组条目 `sip=<ip>` 即源方向、`dip=<ip>` 即目的方向。
        """
        have: set[str] = set()
        for row in entries:
            if self._range_covers(row, ip):
                have.update(BLOCK_DIRECTIONS)
                continue
            direction = str(row.get("direction") or "").strip()
            if direction in BLOCK_DIRECTIONS:
                have.add(direction)
                continue
            if self._holds(row, "sip", ip):
                have.add("src")
            if self._holds(row, "dip", ip):
                have.add("dst")
        return have

    def _add_static(self, ip: str, direction: str) -> None:
        rule = {
            "ipaddr": ip,
            "enable": "yes",
            "direction": direction,
            "except_priv_ip": "off",
            "comment": BLOCK_COMMENT,
        }
        if self._group:
            rule["group_name"] = self._group
        self._expect_result(self.post(STATIC_ADD, [{"blacklist_cfg_add_ip": rule}]), "添加黑名单")

    def _add_tuple(self, ip: str, direction: str) -> None:
        self._expect_result(
            self.post(SPREAD_ADD, [{"pf_blacklist_add": {DIRECTION_FIELDS[direction]: ip}}]), "添加黑名单"
        )

    def _delete_entry(self, row: dict) -> None:
        """按条目形态选删除命令：静态黑名单按 ipaddr 删，五元组按条目原值删。"""
        if self._value(row, "ip_start"):
            self._log("   地址段条目不支持按 IP 删除，需在设备上处理")
            return
        ipaddr = self._value(row, "ipaddr")
        if ipaddr:
            self._log(f"   删除静态黑名单条目：ipaddr={ipaddr}")
            self._expect_result(
                self.post(BLACKLIST_DELETE, [{"blacklist_cfg_delete_ip": [{"ipaddr": ipaddr}]}]), "删除黑名单"
            )
            return
        tuple_ = {field: self._value(row, field) for field in TUPLE_FIELDS}
        self._log("   删除五元组条目：" + " ".join(f"{key}={value or '不限'}" for key, value in tuple_.items()))
        self._expect_result(self.post(BLACKLIST_DELETE, [{"pf_blacklist_delete": [tuple_]}]), "删除黑名单")

    def _block_static(self, target: str, entries: list[dict], have: set[str]) -> None:
        if "src" not in have:
            try:
                self._add_static(target, "src")
            except ToolError as exc:
                if not have:
                    raise
                # 3.7 同一 IP 只允许一条记录，旧条目占着位置，删掉才有位置放源方向
                self._log(f"   源方向被拒（{exc}），已有方向 {'、'.join(sorted(have))}，删除后重建")
                for row in entries:
                    self._delete_entry(row)
                have.clear()
                self._add_static(target, "src")
            self._log(f"   成功：{target} 已写入静态黑名单（direction=src）")
        if "dst" not in have:
            try:
                self._add_static(target, "dst")
                self._log(f"   成功：{target} 已写入静态黑名单（direction=dst）")
            except ToolError as exc:
                self._log(f"   目的方向未下发（设备只允许一个方向时属正常）：{exc}")

    def _block_tuple(self, target: str, have: set[str]) -> None:
        for direction in BLOCK_DIRECTIONS:
            if direction in have:
                self._log(f"   {direction} 方向已封禁，跳过")
                continue
            try:
                self._add_tuple(target, direction)
                have.add(direction)
                self._log(f"   成功：{target} 已写入（{DIRECTION_FIELDS[direction]}={target}）")
            except ToolError as exc:
                # 源方向封不住等于没封，抛给界面记失败；目的方向只匹配「发往该 IP」的报文，尽力即可
                if direction == BLOCK_DIRECTIONS[0]:
                    raise
                self._log(f"   目的方向未下发（设备不允许该五元组时属正常）：{exc}")

    def block(self, ip: str, desc: str = "") -> str:
        """desc 参数仅为与其它驱动签名一致；天融信黑名单条目不带描述字段。"""
        target = check_ip(ip)
        self._log(f"封禁 {target}（源方向必封，目的方向尽力）")
        entries = self.entries(target)
        have = self._covered(entries, target)
        if all(direction in have for direction in BLOCK_DIRECTIONS):
            self._log(f"   跳过：{target} 已按源、目的封禁")
            return f"{target} 已在黑名单，跳过"
        if self._use_static():
            self._block_static(target, entries, have)
        else:
            self._block_tuple(target, have)
        added = "、".join(direction for direction in BLOCK_DIRECTIONS if direction in have)
        return f"{target} 已加入黑名单（{added}）"

    def unblock(self, ip: str) -> str:
        target = check_ip(ip)
        self._log(f"解封 {target}")
        entries = self.entries(target)
        if not entries:
            self._log(f"   跳过：{target} 不在黑名单")
            return f"{target} 不在黑名单，跳过"
        for row in entries:
            self._delete_entry(row)
        self._log(f"   成功：{target} 已从黑名单删除")
        return f"{target} 已从黑名单删除"
