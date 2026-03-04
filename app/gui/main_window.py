"""Main application window."""
from __future__ import annotations

from PyQt6.QtWidgets import QMainWindow, QTabWidget, QStatusBar

from app.models.job import Job, JobStatus
from app.gui.pages.page_input import InputPage
from app.gui.pages.page_analysis import AnalysisPage
from app.gui.pages.page_functions import FunctionsPage
from app.gui.pages.page_code_viewer import CodeViewerPage
from app.gui.pages.page_export import ExportPage


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ReSource Recover — DLL 소스 복원")
        self.resize(1280, 800)

        self._tabs = QTabWidget()
        self.setCentralWidget(self._tabs)

        self._page_input = InputPage()
        self._page_analysis = AnalysisPage()
        self._page_functions = FunctionsPage()
        self._page_code = CodeViewerPage()
        self._page_export = ExportPage()

        self._tabs.addTab(self._page_input, "입력")
        self._tabs.addTab(self._page_analysis, "분석")
        self._tabs.addTab(self._page_functions, "함수 목록")
        self._tabs.addTab(self._page_code, "코드 뷰어")
        self._tabs.addTab(self._page_export, "내보내기")

        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status.showMessage("준비")

        # 시그널 연결
        self._page_input.job_started.connect(self._on_job_started)
        self._page_input.job_done.connect(self._page_export.on_project_ready)

    # ------------------------------------------------------------------

    def _on_job_started(self, job: Job) -> None:
        worker = self._page_input._worker
        if worker:
            worker.status_changed.connect(self._page_analysis.on_status_changed)
            worker.status_changed.connect(self._on_status_changed)
            worker.progress_updated.connect(self._page_analysis.on_progress)
            worker.log_message.connect(self._page_analysis.on_log)
            worker.progress_updated.connect(self._on_function_progress)

        self._page_analysis.set_job(job)
        self._page_functions.set_job(job)
        self._page_export.set_job(job)
        self._tabs.setCurrentIndex(1)
        self._status.showMessage(f"분석 중: {job.dll_path.name}…")

    def _on_status_changed(self, job: Job) -> None:
        self._status.showMessage(f"{job.status} — {job.dll_path.name}")

    def _on_function_progress(self, prog, art) -> None:
        if art is not None:
            self._page_functions.on_function_ready(art)
