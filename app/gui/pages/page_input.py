"""Tab 1 — Input: DLL 선택, 출력 폴더, 모드, 시작 버튼."""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QFileDialog, QGroupBox,
    QSpinBox, QDoubleSpinBox, QFormLayout, QMessageBox,
    QListWidget,
)

from app.config import get_settings, save_settings
from app.models.job import Job
from app.gui.workers import AnalysisWorker


class InputPage(QWidget):
    """Analyze 버튼 클릭 시 job_started(job) 시그널 방출."""

    job_started = pyqtSignal(object)   # Job
    job_done = pyqtSignal(object)      # RecoveredProject | None

    def __init__(self) -> None:
        super().__init__()
        self._worker: AnalysisWorker | None = None
        self._build_ui()

    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        cfg = get_settings()

        # ── DLL 경로 ──────────────────────────────────────────────────
        grp_dll = QGroupBox("분석 대상 바이너리")
        form_dll = QFormLayout(grp_dll)
        self._dll_edit = QLineEdit()
        self._dll_edit.setPlaceholderText(".dll / .exe 경로…")
        btn_dll = QPushButton("찾기…")
        btn_dll.clicked.connect(self._browse_dll)
        row = QHBoxLayout()
        row.addWidget(self._dll_edit)
        row.addWidget(btn_dll)
        form_dll.addRow("파일:", row)
        root.addWidget(grp_dll)

        # ── 출력 폴더 ─────────────────────────────────────────────────
        grp_out = QGroupBox("출력")
        form_out = QFormLayout(grp_out)
        self._out_edit = QLineEdit()
        self._out_edit.setPlaceholderText(f"기본: {cfg.outputs_dir}")
        btn_out = QPushButton("찾기…")
        btn_out.clicked.connect(self._browse_out)
        row2 = QHBoxLayout()
        row2.addWidget(self._out_edit)
        row2.addWidget(btn_out)
        form_out.addRow("폴더:", row2)
        root.addWidget(grp_out)

        # ── IDA 설정 ──────────────────────────────────────────────────
        grp_ida = QGroupBox("IDA Pro 설정")
        form_ida = QFormLayout(grp_ida)

        self._mode_combo = QComboBox()
        self._mode_combo.addItem("헤드리스 (자동, idat64.exe)", "headless")
        self._mode_combo.addItem("IDA GUI 플러그인 (수동 실행)", "ida_plugin")
        idx = 0 if cfg.mcp_mode == "headless" else 1
        self._mode_combo.setCurrentIndex(idx)
        self._mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        form_ida.addRow("모드:", self._mode_combo)

        # Headless 전용
        self._ida_dir_edit = QLineEdit(cfg.ida_dir)
        btn_ida = QPushButton("찾기…")
        btn_ida.clicked.connect(self._browse_ida)
        row3 = QHBoxLayout()
        row3.addWidget(self._ida_dir_edit)
        row3.addWidget(btn_ida)
        self._ida_dir_row_label = QLabel("IDA 설치 폴더:")
        form_ida.addRow(self._ida_dir_row_label, row3)

        self._timeout_spin = QDoubleSpinBox()
        self._timeout_spin.setRange(60.0, 3600.0)
        self._timeout_spin.setValue(cfg.idat_timeout)
        self._timeout_spin.setSuffix(" 초")
        self._timeout_label = QLabel("분석 타임아웃:")
        form_ida.addRow(self._timeout_label, self._timeout_spin)

        # Plugin 전용
        self._endpoint_edit = QLineEdit(cfg.mcp_endpoint)
        self._endpoint_label = QLabel("MCP 엔드포인트:")
        form_ida.addRow(self._endpoint_label, self._endpoint_edit)

        root.addWidget(grp_ida)
        self._on_mode_changed()  # 초기 표시 상태 설정

        # ── .NET 참조 어셈블리 경로 ───────────────────────────────────
        grp_ref = QGroupBox(".NET 참조 어셈블리 폴더 (선택 — 타입 해석 품질 향상)")
        ref_layout = QVBoxLayout(grp_ref)

        self._ref_list = QListWidget()
        self._ref_list.setMaximumHeight(90)
        for p in cfg.dotnet_ref_paths:
            self._ref_list.addItem(p)
        ref_layout.addWidget(self._ref_list)

        ref_btn_row = QHBoxLayout()
        btn_ref_add = QPushButton("추가…")
        btn_ref_add.clicked.connect(self._add_ref_path)
        btn_ref_remove = QPushButton("제거")
        btn_ref_remove.clicked.connect(self._remove_ref_path)
        ref_btn_row.addWidget(btn_ref_add)
        ref_btn_row.addWidget(btn_ref_remove)
        ref_btn_row.addStretch()
        ref_layout.addLayout(ref_btn_row)

        hint = QLabel("Unity: 게임폴더/Managed  |  BepInEx: BepInEx/core  |  MelonLoader: MelonLoader/Managed")
        hint.setStyleSheet("color: gray; font-size: 11px;")
        ref_layout.addWidget(hint)
        root.addWidget(grp_ref)

        # ── 버튼 ──────────────────────────────────────────────────────
        row_btn = QHBoxLayout()
        self._btn_start = QPushButton("분석 시작")
        self._btn_start.setFixedHeight(44)
        self._btn_start.setStyleSheet(
            "QPushButton { background: #0066cc; color: white; font-size: 14px; border-radius: 4px; }"
            "QPushButton:disabled { background: #999; }"
        )
        self._btn_start.clicked.connect(self._start)

        self._btn_cancel = QPushButton("취소")
        self._btn_cancel.setFixedHeight(44)
        self._btn_cancel.setEnabled(False)
        self._btn_cancel.clicked.connect(self._cancel)

        row_btn.addStretch()
        row_btn.addWidget(self._btn_cancel)
        row_btn.addWidget(self._btn_start)
        root.addLayout(row_btn)
        root.addStretch()

    # ------------------------------------------------------------------

    def _on_mode_changed(self) -> None:
        headless = self._mode_combo.currentData() == "headless"
        for w in (self._ida_dir_edit, self._ida_dir_row_label, self._timeout_spin, self._timeout_label):
            w.setVisible(headless)
        for w in (self._endpoint_edit, self._endpoint_label):
            w.setVisible(not headless)

    def _browse_dll(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "바이너리 선택", "", "바이너리 (*.dll *.exe *.sys);;모든 파일 (*)"
        )
        if path:
            self._dll_edit.setText(path)

    def _browse_out(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "출력 폴더 선택")
        if path:
            self._out_edit.setText(path)

    def _browse_ida(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "IDA Pro 설치 폴더 선택")
        if path:
            self._ida_dir_edit.setText(path)

    def _add_ref_path(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "참조 어셈블리 폴더 선택")
        if path:
            self._ref_list.addItem(path)

    def _remove_ref_path(self) -> None:
        for item in self._ref_list.selectedItems():
            self._ref_list.takeItem(self._ref_list.row(item))

    def _start(self) -> None:
        dll_path = self._dll_edit.text().strip()
        if not dll_path:
            QMessageBox.warning(self, "경고", "DLL 경로를 선택하세요.")
            return

        # 설정 저장
        cfg = get_settings()
        cfg.mcp_mode = self._mode_combo.currentData()
        cfg.ida_dir = self._ida_dir_edit.text().strip()
        cfg.idat_timeout = self._timeout_spin.value()
        cfg.mcp_endpoint = self._endpoint_edit.text().strip()
        out_text = self._out_edit.text().strip()
        if out_text:
            cfg.outputs_dir = out_text
        cfg.dotnet_ref_paths = [
            self._ref_list.item(i).text()
            for i in range(self._ref_list.count())
        ]
        save_settings(cfg)

        job = Job(
            dll_path=Path(dll_path),
            output_dir=Path(cfg.outputs_dir),
        )

        self._btn_start.setEnabled(False)
        self._btn_cancel.setEnabled(True)

        self._worker = AnalysisWorker(job)
        self._worker.status_changed.connect(lambda j: None)  # connected externally
        self._worker.job_done.connect(self._on_done)
        self._worker.finished.connect(self._on_finished)
        self._worker.start()

        self.job_started.emit(job)

    def _cancel(self) -> None:
        if self._worker:
            self._worker.cancel()
        self._btn_cancel.setEnabled(False)
        self._btn_start.setEnabled(True)

    def _on_done(self, project) -> None:
        self.job_done.emit(project)

    def _on_finished(self) -> None:
        self._btn_start.setEnabled(True)
        self._btn_cancel.setEnabled(False)
