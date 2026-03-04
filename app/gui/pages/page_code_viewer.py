"""Tab 4 — Code Viewer: decompiled code with side-by-side diff view."""
from __future__ import annotations

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTextEdit, QLabel, QListWidget, QListWidgetItem,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

from app.models.artifact import FunctionArtifact


class CodeViewerPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._artifacts: dict[int, FunctionArtifact] = {}
        self._build_ui()

    def _build_ui(self) -> None:
        root = QHBoxLayout(self)

        # Left: function list (xrefs/callees)
        left = QVBoxLayout()
        left.addWidget(QLabel("Callees / XRefs"))
        self._ref_list = QListWidget()
        self._ref_list.itemClicked.connect(self._on_ref_clicked)
        left.addWidget(self._ref_list)
        left_w = QWidget()
        left_w.setLayout(left)
        left_w.setFixedWidth(220)
        root.addWidget(left_w)

        # Right: code panels
        splitter = QSplitter(Qt.Orientation.Horizontal)
        mono = QFont("Consolas", 10)

        self._raw_view = QTextEdit()
        self._raw_view.setReadOnly(True)
        self._raw_view.setFont(mono)
        self._raw_view.setPlaceholderText("Raw decompiled output…")

        self._refined_view = QTextEdit()
        self._refined_view.setReadOnly(True)
        self._refined_view.setFont(mono)
        self._refined_view.setPlaceholderText("Refined output (after type refinement)…")

        splitter.addWidget(self._raw_view)
        splitter.addWidget(self._refined_view)
        splitter.setSizes([600, 600])
        root.addWidget(splitter)

    # ------------------------------------------------------------------

    def show_function(self, art: FunctionArtifact) -> None:
        self._artifacts[art.address] = art
        # Raw = first decompile snapshot; refined = current (with annotations)
        self._raw_view.setPlainText(art.decompiled_code or "// No decompile output")
        self._refined_view.setPlainText(art.decompiled_code or "// No output")

        # Populate callee list
        self._ref_list.clear()
        for callee_addr in art.callees:
            callee = self._artifacts.get(callee_addr)
            label = callee.display_name if callee else f"0x{callee_addr:X}"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, callee_addr)
            self._ref_list.addItem(item)

    def _on_ref_clicked(self, item: QListWidgetItem) -> None:
        addr = item.data(Qt.ItemDataRole.UserRole)
        if addr and addr in self._artifacts:
            self.show_function(self._artifacts[addr])
