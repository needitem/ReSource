"""Reusable function table widget (thin wrapper, main logic in page_functions)."""
from __future__ import annotations

from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtWidgets import QTableView
from PyQt6.QtGui import QStandardItemModel


class FunctionTable(QTableView):
    """Emits function_selected(address) when a row is clicked."""

    function_selected = pyqtSignal(int)

    def __init__(self) -> None:
        super().__init__()
        self.setSortingEnabled(True)
        self.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.horizontalHeader().setStretchLastSection(True)
        self.clicked.connect(self._on_click)

    def _on_click(self, index) -> None:
        addr_index = self.model().index(index.row(), 0)
        addr_str = self.model().data(addr_index)
        try:
            self.function_selected.emit(int(addr_str, 16))
        except (ValueError, TypeError):
            pass
