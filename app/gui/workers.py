"""QThread workers — 모든 무거운 작업은 여기서 실행, 메인 스레드 블록 없음."""
from __future__ import annotations

import asyncio
import logging

from PyQt6.QtCore import QThread, pyqtSignal

from app.models.job import Job
from app.models.artifact import FunctionArtifact
from app.models.recovered_project import RecoveredProject
from app.pipeline.extractor import ExtractionProgress
from app.services.job_service import JobService

log = logging.getLogger(__name__)


class AnalysisWorker(QThread):
    """JobService 전체 파이프라인을 백그라운드에서 실행."""

    status_changed   = pyqtSignal(object)         # Job
    progress_updated = pyqtSignal(object, object)  # ExtractionProgress, FunctionArtifact|None
    log_message      = pyqtSignal(str)
    job_done         = pyqtSignal(object)          # RecoveredProject | None
    finished         = pyqtSignal()

    def __init__(self, job: Job) -> None:
        super().__init__()
        self._job = job

    def run(self) -> None:
        service = JobService(
            on_status=lambda j: self.status_changed.emit(j),
            on_progress=lambda p, a: self.progress_updated.emit(p, a),
            on_log=lambda m: self.log_message.emit(m),
        )
        try:
            project = asyncio.run(service.run(self._job))
            self.job_done.emit(project)
        except Exception as e:
            log.exception("Worker error: %s", e)
            self.log_message.emit(f"치명적 오류: {e}")
            self.job_done.emit(None)
        finally:
            self.finished.emit()

    def cancel(self) -> None:
        self.terminate()
        self.wait(3000)
