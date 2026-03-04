"""Tab 3 — Functions: searchable/filterable table of all functions."""
from __future__ import annotations

from PyQt6.QtCore import Qt, QSortFilterProxyModel, pyqtSlot
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
    QComboBox, QTableView, QLabel,
)

from app.models.job import Job
from app.models.artifact import FunctionArtifact, ConfidenceLevel


_COLS = ["Address", "Name", "Module", "Status", "Confidence"]


class FunctionsPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._artifacts: list[FunctionArtifact] = []
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        # Filter row
        row = QHBoxLayout()
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter by name…")
        self._search.textChanged.connect(self._apply_filter)
        self._conf_combo = QComboBox()
        self._conf_combo.addItems(["All", "HIGH", "MEDIUM", "LOW"])
        self._conf_combo.currentTextChanged.connect(self._apply_filter)
        row.addWidget(QLabel("Search:"))
        row.addWidget(self._search)
        row.addWidget(QLabel("Confidence:"))
        row.addWidget(self._conf_combo)
        root.addLayout(row)

        # Table
        self._model = QStandardItemModel(0, len(_COLS))
        self._model.setHorizontalHeaderLabels(_COLS)

        self._proxy = QSortFilterProxyModel()
        self._proxy.setSourceModel(self._model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._proxy.setFilterKeyColumn(1)  # Filter on Name column

        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSortingEnabled(True)
        self._table.horizontalHeader().setStretchLastSection(True)
        root.addWidget(self._table)

        self._lbl_count = QLabel("0 functions")
        root.addWidget(self._lbl_count)

    # ------------------------------------------------------------------

    def set_job(self, job: Job) -> None:
        self._model.setRowCount(0)
        self._artifacts = []

    @pyqtSlot(object, object)
    def on_function_ready(self, art: FunctionArtifact) -> None:
        self._artifacts.append(art)
        row = [
            QStandardItem(f"0x{art.address:X}"),
            QStandardItem(art.display_name),
            QStandardItem(art.module or ""),
            QStandardItem("OK" if art.decompile_ok else "FAIL"),
            QStandardItem(art.confidence_level),
        ]
        # Color by confidence
        color = {
            ConfidenceLevel.HIGH: QColor("#d4edda"),
            ConfidenceLevel.MEDIUM: QColor("#fff3cd"),
            ConfidenceLevel.LOW: QColor("#f8d7da"),
        }.get(art.confidence_level, QColor("white"))
        for item in row:
            item.setBackground(color)

        self._model.appendRow(row)
        self._lbl_count.setText(f"{self._model.rowCount()} functions")

    def _apply_filter(self) -> None:
        text = self._search.text()
        self._proxy.setFilterFixedString(text)
        # TODO: also filter by confidence combo
