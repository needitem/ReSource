"""
binary_info.py — DLL/EXE 파일 기본 정보 파악.

is_dotnet(path)  → .NET CLR 어셈블리 여부
is_64bit(path)   → 64비트 여부
"""
from __future__ import annotations

import struct
from pathlib import Path


def is_dotnet(path: Path) -> bool:
    """
    PE 헤더의 CLR metadata DataDirectory(#14)가 비어있지 않으면 .NET.
    실패 시 False 반환.
    """
    try:
        with open(path, "rb") as f:
            # DOS header
            sig = f.read(2)
            if sig != b"MZ":
                return False
            f.seek(0x3C)
            pe_offset = struct.unpack("<I", f.read(4))[0]

            # PE signature
            f.seek(pe_offset)
            if f.read(4) != b"PE\x00\x00":
                return False

            # COFF header
            machine = struct.unpack("<H", f.read(2))[0]
            f.read(18)  # skip to Optional header magic

            magic = struct.unpack("<H", f.read(2))[0]
            is_pe32plus = magic == 0x20B  # PE32+ = 64bit

            # Optional header sizes differ for PE32 vs PE32+
            if is_pe32plus:
                # skip to DataDirectory (offset 112 from magic in PE32+)
                f.read(106)
            else:
                # skip to DataDirectory (offset 96 from magic in PE32)
                f.read(90)

            # DataDirectory[14] = CLR Runtime Header
            # Each entry = 8 bytes (VirtualAddress + Size)
            # Skip entries 0–13 (14 * 8 = 112 bytes)
            f.read(14 * 8)
            clr_va, clr_size = struct.unpack("<II", f.read(8))
            return clr_size > 0

    except Exception:
        return False


def is_64bit(path: Path) -> bool:
    """Machine == 0x8664 (AMD64) or 0xAA64 (ARM64)."""
    try:
        with open(path, "rb") as f:
            if f.read(2) != b"MZ":
                return False
            f.seek(0x3C)
            pe_offset = struct.unpack("<I", f.read(4))[0]
            f.seek(pe_offset + 4)
            machine = struct.unpack("<H", f.read(2))[0]
            return machine in (0x8664, 0xAA64)
    except Exception:
        return False
