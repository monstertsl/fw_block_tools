"""设备清单：统一入口与各设备独立入口共用的唯一来源。

新增设备时在此登记一条 `DeviceEntry`，窗口顶部的设备选择条会自动出现该项，
界面、日志、批量流程仍由 `kit.ui.DeviceToolApp` 一套代码处理。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .drivers.hillstone import HillstoneFW
from .drivers.nsfocus import NsfocusNF
from .drivers.qianxin import QianxinFW
from .drivers.sangfor import DEFAULT_NAMESPACE, SangforAF
from .drivers.topsec import TopsecFW, aes_selfcheck
from .ui import DriverSpec


@dataclass(frozen=True)
class DeviceEntry:
    """一个可选设备：选择条上的显示名 + 界面描述 + 协议客户端类。"""

    label: str
    spec: DriverSpec
    client_factory: type
    # 选中该设备时的自检（返回 False 则日志里提示），可选
    precheck: Callable[[], bool] | None = None


SANGFOR = DeviceEntry(
    label="深信服 AF",
    spec=DriverSpec(
        key="sangfor_af",
        title="深信服 AF 黑名单联动测试工具",
        default_url="https://10.0.0.1:443",
        log_file="sangfor_af_tool.log",
        hint="命名空间默认 @namespace（根系统），多虚拟系统时填实际值",
        extra_fields=(("namespace", "命名空间", DEFAULT_NAMESPACE),),
        # 「添加到地址」封禁方式：勾选后封禁写入 网络对象-地址（ipgroups），解封即从地址删除成员
        address_block=True,
        # 不提供设备侧列表：该设备黑名单动辄上万条（真机 10803 条/55 页），翻页全量拉取会把界面和日志拖死；
        # 是否已封禁按单 IP 查 `GET /whiteblacklist/<ip>` 就够，与奇安信、天融信等保持一致
        support_list=False,
        support_desc=True,
    ),
    client_factory=SangforAF,
)

QIANXIN = DeviceEntry(
    label="奇安信防火墙",
    spec=DriverSpec(
        key="qianxin_firewall",
        title="奇安信防火墙黑名单联动测试工具",
        default_url="https://10.0.0.1:8443",
        log_file="qianxin_fw_tool.log",
        hint="需先在设备启用 RESTful API 并使用「RESTful API管理员」角色的账号；封禁写入人工处置（源、目的地址各一条）",
        support_list=False,
        support_desc=False,  # 人工处置项没有描述字段
    ),
    client_factory=QianxinFW,
)

TOPSEC = DeviceEntry(
    label="天融信防火墙",
    spec=DriverSpec(
        key="topsec_firewall",
        title="天融信防火墙黑名单联动测试工具",
        default_url="https://10.0.0.1:443",
        log_file="topsec_fw_tool.log",
        hint="密码填明文（工具按设备要求 AES-CBC 加密）；登录优先 restLogin、404 回落到 addNoCode，建议关掉登录验证码",
        support_list=False,
        support_desc=False,  # 静态黑名单条目不带描述字段
    ),
    client_factory=TopsecFW,
    precheck=aes_selfcheck,
)


NSFOCUS = DeviceEntry(
    label="绿盟 NF 防火墙",
    spec=DriverSpec(
        key="nsfocus_nf",
        title="绿盟 NF 防火墙黑名单联动测试工具",
        default_url="https://10.0.0.1:8081",
        log_file="nsfocus_nf_tool.log",
        hint="Token 认证：不用填用户名/密码，「API Token」填设备 Web 界面「系统管理 → API 管理」生成的值",
        extra_fields=(("api_token", "API Token", ""),),
        support_list=True,
        support_desc=False,  # 黑名单条目只有 IP/协议/端口与时间，无描述字段
        list_columns=(
            ("ip", "IP", 180),
            ("type", "类型", 110),
            ("protocol", "协议", 90),
            ("port", "端口", 90),
            ("status", "启用", 80),
        ),
    ),
    client_factory=NsfocusNF,
)


HILLSTONE = DeviceEntry(
    label="山石网科防火墙",
    spec=DriverSpec(
        key="hillstone_fw",
        title="山石网科防火墙黑名单联动测试工具",
        default_url="https://10.0.0.1:8443",
        log_file="hillstone_fw_tool.log",
        hint="登录填「API Token」，或用户名+密码二选一；封禁写入地址簿组（组需被安全策略引用才会阻断）",
        extra_fields=(
            ("api_token", "API Token", ""),
            ("group_name", "地址簿组名", "SenseMind-Block"),
        ),
        support_list=True,
        support_desc=False,  # 地址簿主机对象没有描述字段
        list_columns=(("ip", "IP", 220), ("group", "地址簿组", 220)),
    ),
    client_factory=HillstoneFW,
)


DEVICES = (SANGFOR, QIANXIN, TOPSEC, NSFOCUS, HILLSTONE)
