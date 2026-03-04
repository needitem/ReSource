"""Tab 5 — Export: project generation, zip export, report."""
from __future__ import annotations

from PyQt6.QtCore import pyqtSlot
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTextEdit, QFileDialog, QMessageBox,
)

from app.models.job import Job
from app.models.recovered_project import RecoveredProject
from app.pipeline.exporter import Exporter


class ExportPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._job: Job | None = None
        self._project: RecoveredProject | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        self._lbl_summary = QLabel("No project yet")
        root.addWidget(self._lbl_summary)

        self._report = QTextEdit()
        self._report.setReadOnly(True)
        self._report.setPlaceholderText("Recovery report will appear here…")
        root.addWidget(self._report)

        row = QHBoxLayout()
        self._btn_open = QPushButton("Open Output Folder")
        self._btn_open.setEnabled(False)
        self._btn_open.clicked.connect(self._open_folder)

        self._btn_zip = QPushButton("Export as ZIP…")
        self._btn_zip.setEnabled(False)
        self._btn_zip.clicked.connect(self._export_zip)

        row.addStretch()
        row.addWidget(self._btn_open)
        row.addWidget(self._btn_zip)
        root.addLayout(row)

    # ------------------------------------------------------------------

    def set_job(self, job: Job) -> None:
        self._job = job
        self._project = None
        self._btn_open.setEnabled(False)
        self._btn_zip.setEnabled(False)
        self._report.clear()
        self._lbl_summary.setText(f"Waiting for job {job.id}…")

    @pyqtSlot(object)
    def on_project_ready(self, project: RecoveredProject) -> None:
        self._project = project
        self._btn_open.setEnabled(True)
        self._btn_zip.setEnabled(True)
        self._lbl_summary.setText(
            f"Project ready — {project.placed_functions}/{project.total_functions} "
            f"functions placed ({project.placement_pct:.0f}%)"
        )
        self._report.setPlainText(project.readme or "")

    def _open_folder(self) -> None:
        if not self._project:
            return
        import subprocess
        path = self._project.output_dir / self._project.job_id
        subprocess.Popen(["explorer", str(path)])

    def _export_zip(self) -> None:
        if not self._project:
            return
        zip_path = Exporter().zip_export(self._project)
        QMessageBox.information(self, "Export complete", f"ZIP saved:\n{zip_path}")
