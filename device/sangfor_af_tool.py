"""深信服 AF 黑名单联动工具（单独入口，默认选中深信服，窗口内可切换设备）。

运行：python device/sangfor_af_tool.py（或双击），依赖上一级目录的 kit/ 包。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kit.registry import DEVICES, SANGFOR  # noqa: E402
from kit.ui import run_tool  # noqa: E402


if __name__ == "__main__":
    run_tool(SANGFOR.spec, SANGFOR.client_factory, DEVICES)
