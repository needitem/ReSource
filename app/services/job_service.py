"""
Job Service — orchestrates the full pipeline for one Job.

Mode "headless" (기본):
    idat64.exe -A -S<script> <dll>  →  JSON artifacts  →  TypeRefiner/Classifier/Reconstructor

Mode "ida_plugin" (IDA GUI 실행 중일 때):
    McpClient  →  localhost:13337 (IDA 플러그인)  →  TypeRefiner/Classifier/Reconstructor
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Callable, Optional

import anyio
import httpx

from app.config import get_settings
from app.mcp.client import McpClient, McpError
from app.models.artifact import FunctionArtifact, GlobalArtifact
from app.models.job import Job, JobStatus
from app.models.recovered_project import RecoveredFile, RecoveredProject
from app.pipeline.extractor import Extractor, ExtractionProgress
from app.pipeline.type_refiner import TypeRefiner
from app.pipeline.module_classifier import ModuleClassifier
from app.pipeline.reconstructor import Reconstructor
from app.pipeline.exporter import Exporter
from app.pipeline.binary_info import is_dotnet
from app.pipeline.dotnet_runner import DotNetRunner, DotNetRunnerError
from app.services.cache_service import CacheService
from app.services.ida_runner import IDARunner, IDARunnerError

log = logging.getLogger(__name__)

StatusCallback = Callable[[Job], None]
ProgressCallback = Callable[[ExtractionProgress, Optional[FunctionArtifact]], None]
LogCallback = Callable[[str], None]


class JobService:
    def __init__(
        self,
        on_status: Optional[StatusCallback] = None,
        on_progress: Optional[ProgressCallback] = None,
        on_log: Optional[LogCallback] = None,
    ) -> None:
        self._on_status = on_status
        self._on_progress = on_progress
        self._on_log = on_log

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, job: Job) -> Optional[RecoveredProject]:
        cfg = get_settings()
        self._log(f"Job {job.id} 시작: {job.dll_path.name}")

        try:
            # .NET 어셈블리 감지 → ilspycmd 파이프라인
            if is_dotnet(job.dll_path):
                self._log(".NET 어셈블리 감지 → ilspycmd 파이프라인")
                return await self._run_dotnet_mode(job, cfg)
            elif cfg.mcp_mode == "ida_plugin":
                return await self._run_plugin_mode(job, cfg)
            else:
                return await self._run_headless_mode(job, cfg)
        except (IDARunnerError, DotNetRunnerError) as e:
            job.fail(str(e))
            self._log(f"실행 오류: {e}")
            self._emit_status(job)
            return None
        except Exception as e:
            job.fail(str(e))
            log.exception("Unexpected error in job %s", job.id)
            self._log(f"오류: {e}")
            self._emit_status(job)
            return None

    # ------------------------------------------------------------------
    # Mode A: Headless (idat64.exe)
    # ------------------------------------------------------------------

    async def _run_headless_mode(self, job: Job, cfg) -> Optional[RecoveredProject]:
        artifacts_dir = Path(cfg.artifacts_dir) / job.id
        raw_dir = artifacts_dir / "raw"

        cache = CacheService(Path(cfg.artifacts_dir))

        # Skip extraction if already cached
        if cache.has_raw(job.id):
            self._log("캐시에서 아티팩트 로드 중…")
            artifacts = cache.load_artifacts(job.id)
            globals_ = cache.load_globals(job.id)
            job.stats.total_functions = len(artifacts)
            job.stats.decompiled = sum(1 for a in artifacts if a.decompile_ok)
            job.stats.failed = sum(1 for a in artifacts if not a.decompile_ok)
        else:
            # Launch idat64 headless
            self._set_status(job, JobStatus.LOADING)
            runner = IDARunner(Path(cfg.ida_dir))

            prog = ExtractionProgress(0)

            def _on_runner_log(msg: str) -> None:
                self._log(msg)

            def _on_runner_progress(done: int, total: int, ok: int, fail: int) -> None:
                prog.total = total
                prog.done = ok
                prog.failed = fail
                job.stats.total_functions = total
                job.stats.decompiled = ok
                job.stats.failed = fail
                if self._on_progress:
                    self._on_progress(prog, None)

            self._set_status(job, JobStatus.EXTRACTING)
            self._log(f"idat64.exe 헤드리스 분석 시작… ({job.dll_path.name})")

            success = await runner.run(
                dll_path=job.dll_path,
                output_dir=artifacts_dir,
                on_log=_on_runner_log,
                on_progress=_on_runner_progress,
                timeout=cfg.idat_timeout,
            )

            if not success:
                job.fail("idat64.exe 분석 실패")
                self._emit_status(job)
                return None

            if not cache.has_raw(job.id):
                raise IDARunnerError(
                    f"IDA 결과 JSON을 찾을 수 없습니다: {raw_dir}\n"
                    f"로그 확인: {artifacts_dir / 'ida.log'}"
                )

            # Load from JSON
            artifacts = cache.load_artifacts(job.id)
            globals_ = cache.load_globals(job.id)
            self._log(
                f"추출 완료: {job.stats.decompiled} 성공 / {job.stats.failed} 실패"
            )

        # Phase C — Analyze & Reconstruct
        return self._analyze_and_export(job, cfg, artifacts, globals_)

    # ------------------------------------------------------------------
    # Mode C: .NET (ilspycmd)
    # ------------------------------------------------------------------

    async def _run_dotnet_mode(self, job: Job, cfg) -> Optional[RecoveredProject]:
        output_dir = Path(cfg.outputs_dir) / job.id / job.dll_path.stem
        output_dir.mkdir(parents=True, exist_ok=True)

        self._set_status(job, JobStatus.EXTRACTING)
        ref_paths = [Path(p) for p in cfg.dotnet_ref_paths if p]
        runner = DotNetRunner()
        await runner.run(
            dll_path=job.dll_path,
            output_dir=output_dir,
            on_log=self._log,
            timeout=cfg.idat_timeout,
            reference_paths=ref_paths,
        )

        # Collect all generated .cs files
        cs_files = sorted(output_dir.rglob("*.cs"))
        source_files = []
        for cs in cs_files:
            try:
                content = cs.read_text(encoding="utf-8", errors="replace")
            except OSError:
                content = ""
            rel = cs.relative_to(output_dir).as_posix()
            source_files.append(
                RecoveredFile(relative_path=rel, content=content)
            )

        # Collect .csproj if present
        csproj_files = sorted(output_dir.rglob("*.csproj"))
        for csproj in csproj_files:
            try:
                content = csproj.read_text(encoding="utf-8", errors="replace")
            except OSError:
                content = ""
            rel = csproj.relative_to(output_dir).as_posix()
            source_files.append(
                RecoveredFile(relative_path=rel, content=content)
            )

        job.stats.total_functions = len(cs_files)
        job.stats.decompiled = len(cs_files)
        job.stats.failed = 0

        readme = (
            f"# {job.dll_path.stem} — .NET 복원 결과\n\n"
            f"원본: `{job.dll_path}`\n\n"
            f"복원 파일: {len(cs_files)} 개 (.cs)\n\n"
            f"도구: ilspycmd\n"
        )

        project = RecoveredProject(
            job_id=job.id,
            dll_name=job.dll_path.stem,
            output_dir=output_dir.parent,
            source_files=source_files,
            readme=readme,
            total_functions=len(cs_files),
            placed_functions=len(cs_files),
        )

        self._log(f"완료: {len(cs_files)} 개 .cs 파일 → {output_dir}")
        self._set_status(job, JobStatus.DONE)
        return project

    # ------------------------------------------------------------------
    # Mode B: IDA Plugin (running GUI)
    # ------------------------------------------------------------------

    async def _run_plugin_mode(self, job: Job, cfg) -> Optional[RecoveredProject]:
        self._set_status(job, JobStatus.LOADING)
        try:
            async with McpClient(cfg.mcp_endpoint, timeout=cfg.decompile_timeout) as client:
                session_info = await client.open_binary(str(job.dll_path))
                job.session_id = session_info.get("session_id")
                self._log(f"IDA 세션: {job.session_id}")

                self._set_status(job, JobStatus.EXTRACTING)
                extractor = Extractor(
                    client, job,
                    artifacts_dir=Path(cfg.artifacts_dir),
                    max_workers=cfg.max_workers,
                    retry_count=cfg.retry_count,
                    timeout=cfg.decompile_timeout,
                )
                artifacts, globals_ = await extractor.run(on_progress=self._on_progress)
                self._log(
                    f"추출 완료: {job.stats.decompiled} 성공 / {job.stats.failed} 실패"
                )
        except httpx.ConnectError:
            msg = (
                f"IDA MCP 서버에 연결할 수 없습니다 ({cfg.mcp_endpoint})\n"
                "IDA Pro를 실행하고 Edit → Plugins → MCP (Ctrl+Alt+M) 으로 서버를 먼저 시작하세요."
            )
            job.fail(msg)
            self._log(msg)
            self._emit_status(job)
            return None
        except McpError as e:
            job.fail(str(e))
            self._log(f"MCP 오류: {e}")
            self._emit_status(job)
            return None

        return self._analyze_and_export(job, cfg, artifacts, globals_)

    # ------------------------------------------------------------------
    # Phase C + D (shared)
    # ------------------------------------------------------------------

    def _analyze_and_export(
        self, job: Job, cfg, artifacts: list[FunctionArtifact], globals_: GlobalArtifact
    ) -> Optional[RecoveredProject]:
        self._set_status(job, JobStatus.ANALYZING)
        TypeRefiner().run(artifacts, globals_)
        modules = ModuleClassifier().run(artifacts, globals_)
        self._log(f"모듈 분류 완료: {list(modules.keys())}")

        self._set_status(job, JobStatus.EXPORTING)
        project = Reconstructor().build(
            job_id=job.id,
            dll_name=job.dll_path.stem,
            output_dir=Path(cfg.outputs_dir),
            modules=modules,
            globals_=globals_,
            all_artifacts=artifacts,
        )
        Exporter().export(project)
        self._log(f"출력: {project.output_dir / project.job_id}")
        self._log(
            f"완료: {project.placed_functions}/{project.total_functions} 함수 복원 ({project.placement_pct:.0f}%)"
        )

        self._set_status(job, JobStatus.DONE)
        return project

    # ------------------------------------------------------------------

    def _set_status(self, job: Job, status: JobStatus) -> None:
        job.transition(status)
        self._log(f"상태 → {status}")
        self._emit_status(job)

    def _emit_status(self, job: Job) -> None:
        if self._on_status:
            self._on_status(job)

    def _log(self, msg: str) -> None:
        log.info(msg)
        if self._on_log:
            self._on_log(msg)
