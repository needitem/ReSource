"""
Phase C-4 reconstructor.

Renders a buildable C++ skeleton project from collected artifacts.
"""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.models.artifact import FunctionArtifact, GlobalArtifact
from app.models.recovered_project import RecoveredFile, RecoveredProject
from app.pipeline.heuristics import sanitize_identifier

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


class Reconstructor:
    """Builds a RecoveredProject from classified artifacts."""

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape([]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._env.filters["comment_block"] = self._comment_block

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

        project.header_file = self._render_header(globals_, all_artifacts)

        placed = 0
        for module_name, funcs in modules.items():
            source_file = self._render_source(module_name, funcs)
            project.source_files.append(source_file)
            placed += len([f for f in funcs if f.decompile_ok])
        project.placed_functions = placed
        project.failed_functions = sum(1 for a in all_artifacts if not a.decompile_ok)

        project.support_files.extend(self._render_support_files(project, globals_, all_artifacts))
        project.readme = self._render_readme(project, modules)
        return project

    def _render_header(
        self,
        globals_: GlobalArtifact,
        artifacts: list[FunctionArtifact],
    ) -> RecoveredFile:
        tmpl = self._env.get_template("recovered_types.h.j2")
        content = tmpl.render(
            artifacts=artifacts,
            sanitized_structs=self._sanitize_structs(globals_),
        )
        return RecoveredFile(relative_path="include/recovered_types.h", content=content)

    def _render_source(
        self,
        module_name: str,
        funcs: list[FunctionArtifact],
    ) -> RecoveredFile:
        tmpl = self._env.get_template("module.c.j2")
        depth = len([part for part in module_name.split("/") if part])
        include_path = "../" * max(depth, 1) + "include/recovered_types.h"
        content = tmpl.render(
            module_name=module_name,
            functions=funcs,
            include_path=include_path,
        )
        return RecoveredFile(
            relative_path=f"src/{module_name}.cpp",
            content=content,
            function_addresses=[f.address for f in funcs],
        )

    def _render_support_files(
        self,
        project: RecoveredProject,
        globals_: GlobalArtifact,
        artifacts: list[FunctionArtifact],
    ) -> list[RecoveredFile]:
        files: list[RecoveredFile] = []
        source_paths = sorted(sf.relative_path.replace("\\", "/") for sf in project.source_files)

        cmake = self._env.get_template("CMakeLists.txt.j2").render(
            project_name=sanitize_identifier(f"{project.dll_name}_recovered"),
            dll_name=project.dll_name,
            source_paths=source_paths,
            has_exports=bool(globals_.exports),
        )
        files.append(RecoveredFile(relative_path="CMakeLists.txt", content=cmake))

        if globals_.exports:
            addr_to_art = {art.address: art for art in artifacts}
            exports = []
            for exp in globals_.exports:
                addr = exp.get("address")
                if not isinstance(addr, int):
                    continue
                art = addr_to_art.get(addr)
                if not art:
                    continue
                exports.append(
                    {
                        "name": exp.get("name", f"export_{addr:X}"),
                        "ordinal": self._normalize_ordinal(exp.get("ordinal")),
                        "stub_name": art.stub_name,
                    }
                )
            if exports:
                def_text = self._env.get_template("exports.def.j2").render(
                    library_name=sanitize_identifier(f"{project.dll_name}_recovered"),
                    exports=exports,
                )
                files.append(RecoveredFile(relative_path="exports.def", content=def_text))
                proxy_exports = [exp for exp in exports if exp["name"] not in {"DllEntryPoint", "DllMain", "DllMainCRTStartup", "_DllMainCRTStartup"}]
                if proxy_exports:
                    files.extend(self._render_proxy_files(project, proxy_exports))

        return files

    def _render_readme(
        self,
        project: RecoveredProject,
        modules: dict[str, list[FunctionArtifact]],
    ) -> str:
        tmpl = self._env.get_template("README_recovered.md.j2")
        return tmpl.render(project=project, modules=modules)

    @staticmethod
    def _sanitize_structs(globals_: GlobalArtifact) -> list[dict]:
        sanitized: list[dict] = []
        seen: set[str] = set()
        for idx, struct_info in enumerate(globals_.structs):
            raw_name = str(struct_info.get("name", f"struct_{idx}"))
            clean_name = sanitize_identifier(raw_name) or f"struct_{idx}"
            if clean_name[0].isdigit():
                clean_name = f"struct_{clean_name}"
            if clean_name in seen:
                clean_name = f"{clean_name}_{idx}"
            seen.add(clean_name)
            size = struct_info.get("size")
            try:
                opaque_size = max(int(size), 1)
            except (TypeError, ValueError):
                opaque_size = 1
            sanitized.append({"raw_name": raw_name, "name": clean_name, "size": opaque_size})
        return sanitized

    @staticmethod
    def _comment_block(value: str | None) -> str:
        if not value:
            return "// n/a"
        return "\n".join(f"// {line}" if line else "//" for line in value.splitlines())

    @staticmethod
    def _normalize_ordinal(value: object) -> int | None:
        if not isinstance(value, int):
            return None
        if 1 <= value <= 65535:
            return value
        return None

    def _render_proxy_files(
        self,
        project: RecoveredProject,
        exports: list[dict],
    ) -> list[RecoveredFile]:
        base_name = sanitize_identifier(project.dll_name) or "original"
        forward_module = f"{base_name}_original"
        files = [
            RecoveredFile(
                relative_path="proxy/CMakeLists.txt",
                content=self._env.get_template("proxy_CMakeLists.txt.j2").render(
                    project_name=sanitize_identifier(f"{project.dll_name}_proxy"),
                ),
            ),
            RecoveredFile(
                relative_path="proxy/proxy.cpp",
                content=self._env.get_template("proxy.cpp.j2").render(),
            ),
            RecoveredFile(
                relative_path="proxy/proxy_exports.def",
                content=self._env.get_template("proxy_exports.def.j2").render(
                    library_name=sanitize_identifier(f"{project.dll_name}_proxy"),
                    forward_module=forward_module,
                    exports=exports,
                ),
            ),
        ]
        return files
