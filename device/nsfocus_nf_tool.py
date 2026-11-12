"""绿盟 NF 防火墙黑名单联动工具（单独入口，默认选中绿盟，窗口内可切换设备）。

运行：python device/nsfocus_nf_tool.py（或双击），依赖上一级目录的 kit/ 包。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kit.registry import DEVICES, NSFOCUS  # noqa: E402
from kit.ui import run_tool  # noqa: E402


if __name__ == "__main__":
    run_tool(NSFOCUS.spec, NSFOCUS.client_factory, DEVICES)
