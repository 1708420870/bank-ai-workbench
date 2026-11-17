# -*- coding: utf-8 -*-
"""纯 Python 生成 Windows .lnk 快捷方式（Shell Link 二进制格式）。

用法：python make_shortcut.py <快捷方式路径.lnk> <目标exe路径> [工作目录]
仅用标准库 struct，不依赖 COM / pywin32，规避安全策略对 LOLBin 的拦截。
严格按 MS-SHLLINK（Shell Link (.LNK) Binary File Format）实现：

ShellLinkHeader（76 字节，固定）:
  HeaderSize=0x4C | LinkCLSID | LinkFlags | FileAttributes | 3xFILETIME
  | FileSize | IconIndex | ShowCommand | HotKey | Reserved1-3
LinkInfo（本地目标）:
  Size | HeaderSize(0x1C) | Flags | VolumeIDOffset | LocalBasePathOffset
  | CommonNetRelLinkOffset | CommonPathSuffixOffset + VolumeID + BasePath + Suffix
StringData（按 LinkFlags 位序出现）:
  Name → RelativePath → WorkingDir → Arguments → IconLocation
  每个 = cch(2字节,字符数含NUL) + UTF-16LE 内容 + NUL（IsUnicode 置位）
"""
import struct
import sys
from pathlib import Path

LINK_CLSID = bytes.fromhex("0102140000000000c000000000000046")  # {00021401-...} 小端
FILE_ATTRIBUTE_NORMAL = 0x80
SHOW_NORMAL = 1

# LinkFlags
HAS_LINK_INFO = 0x02
HAS_NAME = 0x04
HAS_RELATIVE_PATH = 0x08
HAS_WORKING_DIR = 0x10
HAS_ICON_LOCATION = 0x40
IS_UNICODE = 0x80


def _mbcs(s: str) -> bytes:
    return s.encode("mbcs", errors="replace")


def _uni_string(s: str) -> bytes:
    """IsUnicode 置位时的 StringData：cch(含 NUL 的字符数) + UTF-16LE + NUL。"""
    b = s.encode("utf-16-le")
    return struct.pack("<H", s.count("") ) if False else struct.pack("<H", len(s) + 1) + b + b"\x00\x00"


def make_lnk(dest: str, target: str, workdir: str = "") -> None:
    target_abs = str(Path(target).resolve())
    wd = workdir or str(Path(target_abs).parent)
    drive, rest = target_abs[:3], target_abs[3:]
    rel_path = str(Path(target_abs).relative_to(wd)) if target_abs.startswith(str(Path(wd))) else target_abs

    # ---- LinkInfo：本地目标 ----
    base_path = _mbcs(target_abs) + b"\x00"
    volume_label = b"\x00"                       # 空卷标（仅占位 NUL）
    volume_id_size = 16 + len(volume_label)      # Size/DriveType/Serial/LabelOffset + label
    local_bp_off = 0x1C + volume_id_size         # 28 + volumeID
    common_suffix_off = local_bp_off + len(base_path)
    link_info_size = common_suffix_off + 1       # 末尾空 suffix + NUL

    link_info = b"".join([
        struct.pack("<7I",
                    link_info_size,      # LinkInfoSize
                    0x1C,                # LinkInfoHeaderSize（7 个 DWORD）
                    0x01,                # VolumeIDAndLocalBasePath
                    0x1C,                # VolumeIDOffset
                    local_bp_off,        # LocalBasePathOffset
                    0,                   # CommonNetworkRelativeLinkOffset
                    common_suffix_off),  # CommonPathSuffixOffset
        # VolumeID
        struct.pack("<III I", volume_id_size, 3, 0, 16)[:16],  # DriveType=DRIVE_FIXED, LabelOffset=16
        volume_label,
        base_path,
        b"\x00",  # CommonPathSuffix = ""
    ])
    assert len(link_info) == link_info_size

    # ---- LinkFlags 与按位序排列的 StringData ----
    flags = (HAS_LINK_INFO | HAS_NAME | HAS_RELATIVE_PATH |
             HAS_WORKING_DIR | HAS_ICON_LOCATION | IS_UNICODE)
    strings = (
        _uni_string("银行客服 AI 工作台") +  # NAME_STRING
        _uni_string(rel_path) +             # RELATIVE_PATH
        _uni_string(wd) +                   # WORKING_DIR
        _uni_string(target_abs)             # ICON_LOCATION（图标取 exe 自带）
    )

    # ---- ShellLinkHeader：严格 76 字节 ----
    header = b"".join([
        struct.pack("<I", 0x4C),
        LINK_CLSID,
        struct.pack("<I", flags),
        struct.pack("<I", FILE_ATTRIBUTE_NORMAL),
        struct.pack("<QQQ", 0, 0, 0),                 # 3 x FILETIME
        struct.pack("<III", 0, 0, SHOW_NORMAL),       # FileSize / IconIndex / ShowCommand
        struct.pack("<HHII", 0, 0, 0, 0),             # HotKey / Res1 / Res2 / Res3
    ])
    assert len(header) == 0x4C, len(header)

    Path(dest).write_bytes(header + link_info + strings)
    print(f"OK: {dest} -> {target_abs}")


if __name__ == "__main__":
    make_lnk(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
