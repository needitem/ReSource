"""Tab 2 — Analysis: progress bar, real-time log, cancel button."""
from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QProgressBar, QPushButton, QTextEdit,
)

from app.models.job import Job, JobStatus
from app.models.artifact import FunctionArtifact
from app.pipeline.extractor import ExtractionProgress
from app.gui.widgets.log_panel import LogPanel


class AnalysisPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._job: Job | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        # Status label
        self._lbl_status = QLabel("No job running")
        root.addWidget(self._lbl_status)

        # Progress bar
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        root.addWidget(self._progress)

        # Stats row
        row = QHBoxLayout()
        self._lbl_total = QLabel("Total: 0")
        self._lbl_done = QLabel("Done: 0")
        self._lbl_failed = QLabel("Failed: 0")
        for lbl in (self._lbl_total, self._lbl_done, self._lbl_failed):
            row.addWidget(lbl)
        row.addStretch()
        root.addLayout(row)

        # Log panel
        self._log = LogPanel()
        root.addWidget(self._log)

        # Cancel button
        self._btn_cancel = QPushButton("Cancel")
        self._btn_cancel.setEnabled(False)
        root.addWidget(self._btn_cancel, alignment=Qt.AlignmentFlag.AlignRight)

    # ------------------------------------------------------------------

    def set_job(self, job: Job) -> None:
        self._job = job
        self._lbl_status.setText(f"Job {job.id} — {job.dll_path.name}")
        self._progress.setValue(0)
        self._btn_cancel.setEnabled(True)

    @pyqtSlot(object)
    def on_status_changed(self, job: Job) -> None:
        self._lbl_status.setText(f"{job.status} — {job.dll_path.name}")
        if job.status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED):
            self._btn_cancel.setEnabled(False)

    @pyqtSlot(object, object)
    def on_progress(self, prog: ExtractionProgress, art: FunctionArtifact) -> None:
        self._progress.setValue(int(prog.pct))
        self._lbl_total.setText(f"Total: {prog.total}")
        self._lbl_done.setText(f"Done: {prog.done}")
        self._lbl_failed.setText(f"Failed: {prog.failed}")

    @pyqtSlot(str)
    def on_log(self, message: str) -> None:
        self._log.append(message)
