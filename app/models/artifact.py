"""Raw per-function artifact collected from IDA via MCP."""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"     # decompile ok + type ok + callgraph consistent
    MEDIUM = "MEDIUM" # partial success
    LOW = "LOW"       # mostly guessed


class FunctionArtifact(BaseModel):
    address: int
    name: str                        # raw IDA name (may be sub_XXXXX)
    demangled_name: Optional[str] = None
    size: int = 0
    decompiled_code: Optional[str] = None
    disasm: Optional[str] = None
    prototype: Optional[str] = None
    callers: list[int] = []
    callees: list[int] = []
    xrefs_to: list[int] = []
    stack_vars: list[dict] = []
    is_exported: bool = False
    module: Optional[str] = None     # assigned by module_classifier

    # confidence scoring (0-100)
    confidence_score: int = 0
    confidence_level: ConfidenceLevel = ConfidenceLevel.LOW
    confidence_reasons: list[str] = []

    # Phase B status
    decompile_ok: bool = False
    type_ok: bool = False
    decompile_error: Optional[str] = None

    def add_confidence(self, points: int, reason: str) -> None:
        self.confidence_score = min(100, self.confidence_score + points)
        self.confidence_reasons.append(reason)
        if self.confidence_score >= 70:
            self.confidence_level = ConfidenceLevel.HIGH
        elif self.confidence_score >= 40:
            self.confidence_level = ConfidenceLevel.MEDIUM
        else:
            self.confidence_level = ConfidenceLevel.LOW

    @property
    def display_name(self) -> str:
        return self.demangled_name or self.name


class GlobalArtifact(BaseModel):
    imports: list[dict] = []
    exports: list[dict] = []
    strings: list[dict] = []
    structs: list[dict] = []
    enums: list[dict] = []
