"""Raw per-function artifact collected from IDA via MCP."""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


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
    callers: list[int] = Field(default_factory=list)
    callees: list[int] = Field(default_factory=list)
    xrefs_to: list[int] = Field(default_factory=list)
    stack_vars: list[dict] = Field(default_factory=list)
    is_exported: bool = False
    module: Optional[str] = None     # assigned by module_classifier
    module_reason: Optional[str] = None

    # no-PDB heuristics
    string_refs: list[str] = Field(default_factory=list)
    source_candidates: list[str] = Field(default_factory=list)
    class_hint: Optional[str] = None
    guessed_name: Optional[str] = None

    # confidence scoring (0-100)
    confidence_score: int = 0
    confidence_level: ConfidenceLevel = ConfidenceLevel.LOW
    confidence_reasons: list[str] = Field(default_factory=list)

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
        return self.demangled_name or self.guessed_name or self.name

    @property
    def source_hint(self) -> Optional[str]:
        return self.source_candidates[0] if self.source_candidates else None

    @property
    def c_identifier(self) -> str:
        candidate = self.guessed_name or self.name or f"sub_{self.address:X}"
        sanitized = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in candidate)
        sanitized = sanitized.strip("_") or f"sub_{self.address:X}"
        if sanitized[0].isdigit():
            sanitized = f"fn_{sanitized}"
        return sanitized

    @property
    def stub_name(self) -> str:
        return f"fn_{self.address:X}"


class GlobalArtifact(BaseModel):
    imports: list[dict] = Field(default_factory=list)
    exports: list[dict] = Field(default_factory=list)
    strings: list[dict] = Field(default_factory=list)
    structs: list[dict] = Field(default_factory=list)
    enums: list[dict] = Field(default_factory=list)
