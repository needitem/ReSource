"""Final recovered project structure — the output of the whole pipeline."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


class RecoveredFile(BaseModel):
    relative_path: str        # e.g. "src/net_module.c"
    content: str
    function_addresses: list[int] = Field(default_factory=list)


class RecoveredProject(BaseModel):
    job_id: str
    dll_name: str
    output_dir: Path

    header_file: Optional[RecoveredFile] = None       # include/recovered_types.h
    source_files: list[RecoveredFile] = Field(default_factory=list)
    support_files: list[RecoveredFile] = Field(default_factory=list)
    readme: Optional[str] = None

    total_functions: int = 0
    placed_functions: int = 0
    failed_functions: int = 0

    @property
    def placement_pct(self) -> float:
        if self.total_functions == 0:
            return 0.0
        return round(self.placed_functions / self.total_functions * 100, 1)

    def write_to_disk(self) -> None:
        base = self.output_dir / self.job_id
        base.mkdir(parents=True, exist_ok=True)

        if self.header_file:
            p = base / self.header_file.relative_path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(self.header_file.content, encoding="utf-8")

        for sf in self.source_files:
            p = base / sf.relative_path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(sf.content, encoding="utf-8")

        for sf in self.support_files:
            p = base / sf.relative_path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(sf.content, encoding="utf-8")

        if self.readme:
            (base / "README_recovered.md").write_text(self.readme, encoding="utf-8")
