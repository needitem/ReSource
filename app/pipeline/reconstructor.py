"""
Phase C-4 — Reconstructor.

Renders .h / .c(.cpp) files from collected artifacts using Jinja2 templates.
"""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.models.artifact import FunctionArtifact, GlobalArtifact
from app.models.recovered_project import RecoveredFile, RecoveredProject

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


class Reconstructor:
    """Builds a RecoveredProject from classified artifacts."""

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape([]),  # No HTML escaping for C code
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def build(
        self,
        job_id: str,
        dll_name: str,
        output_dir: Path,
        modules: dict[str, list[FunctionArtifact]],
        globals_: GlobalArtifact,
        all_artifacts: list[FunctionArtifact],
    ) -> RecoveredProject:
        project = RecoveredProject(
            job_id=job_id,
            dll_name=dll_name,
            output_dir=output_dir,
            total_functions=len(all_artifacts),
        )

        # Header
        project.header_file = self._render_header(globals_, all_artifacts)

        # Source files — one per module
        placed = 0
        for module_name, funcs in modules.items():
            source_file = self._render_source(module_name, funcs)
            project.source_files.append(source_file)
            placed += len([f for f in funcs if f.decompile_ok])
        project.placed_functions = placed
        project.failed_functions = sum(1 for a in all_artifacts if not a.decompile_ok)

        # README
        project.readme = self._render_readme(project, modules)

        return project

    # ------------------------------------------------------------------

    def _render_header(
        self,
        globals_: GlobalArtifact,
        artifacts: list[FunctionArtifact],
    ) -> RecoveredFile:
        tmpl = self._env.get_template("recovered_types.h.j2")
        content = tmpl.render(globals=globals_, artifacts=artifacts)
        return RecoveredFile(
            relative_path="include/recovered_types.h",
            content=content,
        )

    def _render_source(
        self,
        module_name: str,
        funcs: list[FunctionArtifact],
    ) -> RecoveredFile:
        tmpl = self._env.get_template("module.c.j2")
        content = tmpl.render(module_name=module_name, functions=funcs)
        return RecoveredFile(
            relative_path=f"src/{module_name}.c",
            content=content,
            function_addresses=[f.address for f in funcs],
        )

    def _render_readme(
        self,
        project: RecoveredProject,
        modules: dict[str, list[FunctionArtifact]],
    ) -> str:
        tmpl = self._env.get_template("README_recovered.md.j2")
        return tmpl.render(project=project, modules=modules)
