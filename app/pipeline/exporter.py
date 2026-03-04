"""
Phase D — Exporter.

Writes RecoveredProject to disk and optionally zips the result.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from app.models.recovered_project import RecoveredProject


class Exporter:
    def export(self, project: RecoveredProject) -> Path:
        """Write all files to disk. Returns output directory."""
        project.write_to_disk()
        return project.output_dir / project.job_id

    def zip_export(self, project: RecoveredProject) -> Path:
        """Write files and create a zip archive. Returns zip path."""
        out_dir = self.export(project)
        zip_path = out_dir.parent / f"{project.dll_name}_{project.job_id}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in out_dir.rglob("*"):
                if f.is_file():
                    zf.write(f, f.relative_to(out_dir))
        return zip_path
