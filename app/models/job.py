"""Job state machine for a single DLL analysis run."""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    PENDING = "pending"
    LOADING = "loading"       # IDA opening the binary
    EXTRACTING = "extracting" # Phase B: collecting artifacts
    ANALYZING = "analyzing"   # Phase C: type refinement / module classify
    EXPORTING = "exporting"   # Phase C-4 / D: writing output files
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobStats(BaseModel):
    total_functions: int = 0
    decompiled: int = 0
    failed: int = 0
    skipped: int = 0

    @property
    def progress_pct(self) -> float:
        if self.total_functions == 0:
            return 0.0
        done = self.decompiled + self.failed + self.skipped
        return round(done / self.total_functions * 100, 1)


class Job(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    dll_path: Path
    output_dir: Path
    status: JobStatus = JobStatus.PENDING
    stats: JobStats = Field(default_factory=JobStats)
    error: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    session_id: Optional[str] = None   # IDA idalib session id

    def touch(self) -> None:
        self.updated_at = datetime.now()

    def fail(self, reason: str) -> None:
        self.error = reason
        self.status = JobStatus.FAILED
        self.touch()

    def transition(self, new_status: JobStatus) -> None:
        self.status = new_status
        self.touch()
