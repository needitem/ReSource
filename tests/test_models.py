"""Unit tests for data models."""
import pytest
from app.models.job import Job, JobStatus
from app.models.artifact import FunctionArtifact, ConfidenceLevel
from app.models.recovered_project import RecoveredProject, RecoveredFile
from pathlib import Path


def test_job_defaults():
    job = Job(dll_path=Path("test.dll"), output_dir=Path("out"))
    assert job.status == JobStatus.PENDING
    assert job.stats.total_functions == 0
    assert job.stats.progress_pct == 0.0


def test_job_transition():
    job = Job(dll_path=Path("test.dll"), output_dir=Path("out"))
    job.transition(JobStatus.EXTRACTING)
    assert job.status == JobStatus.EXTRACTING


def test_job_fail():
    job = Job(dll_path=Path("test.dll"), output_dir=Path("out"))
    job.fail("connection refused")
    assert job.status == JobStatus.FAILED
    assert job.error == "connection refused"


def test_function_artifact_confidence():
    art = FunctionArtifact(address=0x1000, name="sub_1000")
    assert art.confidence_level == ConfidenceLevel.LOW
    art.add_confidence(30, "decompile_success")
    art.add_confidence(20, "type_inferred")
    assert art.confidence_score == 50
    assert art.confidence_level == ConfidenceLevel.MEDIUM


def test_function_artifact_high_confidence():
    art = FunctionArtifact(address=0x2000, name="net_connect")
    art.add_confidence(30, "decompile_success")
    art.add_confidence(20, "type_inferred")
    art.add_confidence(20, "callgraph_present")
    assert art.confidence_level == ConfidenceLevel.HIGH


def test_recovered_project_placement_pct():
    p = RecoveredProject(
        job_id="abc",
        dll_name="test",
        output_dir=Path("out"),
        total_functions=10,
        placed_functions=7,
    )
    assert p.placement_pct == 70.0


def test_recovered_project_zero_total():
    p = RecoveredProject(job_id="x", dll_name="d", output_dir=Path("."))
    assert p.placement_pct == 0.0
