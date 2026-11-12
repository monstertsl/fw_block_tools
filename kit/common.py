"""通用工具：错误类型、IP 校验与提取、表格解析（xlsx/csv/txt）、日志脱敏。

表格解析只用标准库（zipfile + ElementTree / csv），不引入 openpyxl 等第三方库。
"""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
import xml.etree.ElementTree as ET
import zipfile

IPV4_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
MAX_CELL_VALUES = 200_000  # 单文件最多扫描的单元格数，防止误选超大文件把界面拖死
UI_LINE_LIMIT = 1500  # 界面单行最多显示字符数，完整内容始终写日志文件
LOG_DIR_NAME = "logs"  # 日志统一落 fw_block_tools/logs/，根目录只留代码
SECRET_KEYS = ("password", "passwd", "token", "secret", "authid", "sessionid", "coderun", "code_run")


class ToolError(Exception):
    """带可读原因的失败，界面直接展示 message。"""


def check_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        raise ToolError(f"非法 IP：{value}") from None


def mask_secret(value: str) -> str:
    """token/密码不原样落日志，只保留可核对的头尾。"""
    text = str(value or "")
    if len(text) <= 8:
        return "***"
    return f"{text[:4]}***{text[-2:]}"


def mask_payload(payload):
    """递归给敏感键打码，用于请求体/响应体日志。"""
    if isinstance(payload, dict):
        masked = {}
        for key, val in payload.items():
            if isinstance(val, str) and str(key).lower() in SECRET_KEYS:
                masked[key] = mask_secret(val)
            else:
                masked[key] = mask_payload(val)
        return masked
    if isinstance(payload, list):
        return [mask_payload(item) for item in payload]
    return payload


def json_text(payload) -> str:
    try:
        return json.dumps(mask_payload(payload), ensure_ascii=False)
    except (TypeError, ValueError):
        return str(payload)


def ips_from_values(values) -> list[str]:
    """从任意文本里捞合法 IPv4，去重并按出现顺序保留。"""
    seen: dict[str, None] = {}
    for text in values:
        for raw in IPV4_RE.findall(str(text or "")):
            try:
                seen.setdefault(str(ipaddress.IPv4Address(raw)), None)
            except ValueError:
                continue  # 999.1.1.1 这类伪 IP 直接丢
    return list(seen)


def xlsx_values(path: str) -> list[str]:
    """直接解 xlsx（zip + xml），不引入第三方库。"""
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
            shared: list[str] = []
            if "xl/sharedStrings.xml" in names:
                root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
                for item in root:
                    shared.append("".join(n.text or "" for n in item.iter() if n.tag.endswith("}t")))
            sheets = sorted(n for n in names if re.match(r"xl/worksheets/sheet\d+\.xml$", n))
            if not sheets:
                raise ToolError("这个 xlsx 里没有工作表内容")
            values: list[str] = []
            for sheet in sheets:
                root = ET.fromstring(zf.read(sheet))
                for cell in root.iter():
                    if not cell.tag.endswith("}c"):  # 只看 <c> 单元格
                        continue
                    kind = cell.get("t")
                    texts = [n.text for n in cell.iter() if n.tag.endswith("}v")]
                    if kind == "s" and texts and texts[0] is not None:
                        try:
                            values.append(shared[int(texts[0])])
                        except (ValueError, IndexError):
                            continue
                    elif kind == "inlineStr":
                        values.append("".join(n.text or "" for n in cell.iter() if n.tag.endswith("}t")))
                    else:
                        values.extend(text or "" for text in texts)
                    if len(values) > MAX_CELL_VALUES:
                        raise ToolError("表格内容过多（超过 20 万单元格），请拆分后再导入")
            return values
    except zipfile.BadZipFile:
        raise ToolError("不是有效的 xlsx（.xls 请先用 Excel 另存为 .xlsx 或 .csv）") from None
    except ET.ParseError:
        raise ToolError("xlsx 内容解析失败，文件可能已损坏") from None
    except OSError as exc:
        raise ToolError(f"读取文件失败：{exc}") from None


def csv_values(path: str) -> list[str]:
    """Excel 导出的 CSV 可能是 UTF-8 BOM 或 GBK，逐个试。"""
    for encoding in ("utf-8-sig", "gbk", "utf-16"):
        try:
            with open(path, newline="", encoding=encoding) as fh:
                return [cell for row in csv.reader(fh) for cell in row]
        except UnicodeDecodeError:
            continue
        except OSError as exc:
            raise ToolError(f"读取文件失败：{exc}") from None
    raise ToolError("CSV 编码无法识别，请另存为 UTF-8 或改用 xlsx")


def extract_ips(path: str) -> list[str]:
    """按扩展名分派：xlsx / csv / txt 都能取；返回去重后的合法 IPv4。"""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".xlsx":
        return ips_from_values(xlsx_values(path))
    if ext == ".csv":
        return ips_from_values(csv_values(path))
    if ext in (".txt", ".log"):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                return ips_from_values(fh)
        except OSError as exc:
            raise ToolError(f"读取文件失败：{exc}") from None
    if ext == ".xls":
        raise ToolError("不支持老格式 .xls，请用 Excel 另存为 .xlsx 或 .csv")
    raise ToolError(f"不支持的文件类型：{ext or '未知'}（支持 .xlsx / .csv / .txt）")
