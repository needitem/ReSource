"""
Simple on-disk artifact cache.

Checks whether raw artifacts for a job_id already exist so re-runs can
skip extraction and go straight to Phase C.
"""
from __future__ import annotations

from pathlib import Path


class CacheService:
    def __init__(self, artifacts_dir: Path) -> None:
        self.artifacts_dir = Path(artifacts_dir)

    def has_raw(self, job_id: str) -> bool:
        raw_dir = self.artifacts_dir / job_id / "raw"
        if not raw_dir.exists():
            return False
        return any(raw_dir.glob("func_*.json"))

    def raw_dir(self, job_id: str) -> Path:
        return self.artifacts_dir / job_id / "raw"

    def load_globals(self, job_id: str):
        import json
        from app.models.artifact import GlobalArtifact
        p = self.artifacts_dir / job_id / "raw" / "globals.json"
        if p.exists():
            return GlobalArtifact.model_validate_json(p.read_text())
        return GlobalArtifact()

    def load_artifacts(self, job_id: str):
        import json
        from app.models.artifact import FunctionArtifact
        raw_dir = self.raw_dir(job_id)
        results = []
        for f in sorted(raw_dir.glob("func_*.json")):
            results.append(FunctionArtifact.model_validate_json(f.read_text()))
        return results
