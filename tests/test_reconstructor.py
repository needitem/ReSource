"""Unit tests for the reconstructor (code generation)."""
import pytest
from pathlib import Path
from app.models.artifact import FunctionArtifact, GlobalArtifact
from app.pipeline.type_refiner import TypeRefiner
from app.pipeline.module_classifier import ModuleClassifier
from app.pipeline.reconstructor import Reconstructor


def _make_art(addr: int, name: str, decompiled: str = "", is_exported: bool = False) -> FunctionArtifact:
    art = FunctionArtifact(
        address=addr, name=name,
        decompiled_code=decompiled or None,
        decompile_ok=bool(decompiled),
        is_exported=is_exported,
    )
    return art


def test_type_refiner_scores_decompile():
    art = _make_art(0x1000, "sub_1000", decompiled="int sub_1000() { return 0; }")
    globals_ = GlobalArtifact()
    TypeRefiner().run([art], globals_)
    assert art.confidence_score >= 30


def test_type_refiner_annotates_low():
    art = _make_art(0x1000, "sub_1000", decompiled="int sub_1000() {}")
    globals_ = GlobalArtifact()
    TypeRefiner().run([art], globals_)
    assert "TODO: inferred" in (art.decompiled_code or "")


def test_module_classifier_by_prefix():
    art = _make_art(0x2000, "net_connect", is_exported=True)
    globals_ = GlobalArtifact(exports=[{"name": "net_connect", "address": 0x2000}])
    modules = ModuleClassifier().run([art], globals_)
    assert "net" in modules or art.module is not None


def test_reconstructor_builds_project(tmp_path):
    art = _make_art(0x3000, "crypto_hash", decompiled="void crypto_hash() {}")
    art.module = "crypto"
    globals_ = GlobalArtifact()
    modules = {"crypto": [art]}

    reconstructor = Reconstructor()
    project = reconstructor.build(
        job_id="test01",
        dll_name="test",
        output_dir=tmp_path,
        modules=modules,
        globals_=globals_,
        all_artifacts=[art],
    )
    assert project.header_file is not None
    assert len(project.source_files) == 1
    assert "crypto_hash" in project.source_files[0].content


def test_reconstructor_write_to_disk(tmp_path):
    art = _make_art(0x4000, "io_read", decompiled="int io_read() { return 1; }")
    art.module = "io"
    globals_ = GlobalArtifact()
    modules = {"io": [art]}

    project = Reconstructor().build("job02", "mylib", tmp_path, modules, globals_, [art])
    project.write_to_disk()

    out = tmp_path / "job02"
    assert (out / "include" / "recovered_types.h").exists()
    assert (out / "src" / "io.c").exists()
    assert (out / "README_recovered.md").exists()
