"""
Phase B artifact extractor.

Collects per-function data from IDA via MCP with bounded parallelism
and retry logic. Saves raw JSON to artifacts/<job_id>/raw/.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Callable, Optional

from app.mcp.client import McpClient, McpError
from app.models.artifact import FunctionArtifact, GlobalArtifact
from app.models.job import Job
from app.pipeline.heuristics import enrich_artifact_metadata

log = logging.getLogger(__name__)


class ExtractionProgress:
    """Progress state passed to callbacks."""

    def __init__(self, total: int) -> None:
        self.total = total
        self.done = 0
        self.failed = 0

    @property
    def pct(self) -> float:
        return round((self.done + self.failed) / max(self.total, 1) * 100, 1)


ProgressCallback = Callable[[ExtractionProgress, FunctionArtifact], None]


class Extractor:
    """
    Extracts all artifacts for a job.

    Usage::

        async with McpClient(endpoint) as client:
            extractor = Extractor(client, job, artifacts_dir)
            functions, globals_ = await extractor.run(on_progress=cb)
    """

    def __init__(
        self,
        client: McpClient,
        job: Job,
        artifacts_dir: Path,
        max_workers: int = 3,
        retry_count: int = 2,
        timeout: float = 30.0,
    ) -> None:
        self.client = client
        self.job = job
        self.artifacts_dir = artifacts_dir
        self.max_workers = max_workers
        self.retry_count = retry_count
        self.timeout = timeout
        self._raw_dir = artifacts_dir / job.id / "raw"
        self._raw_dir.mkdir(parents=True, exist_ok=True)

    async def run(
        self,
        on_progress: Optional[ProgressCallback] = None,
    ) -> tuple[list[FunctionArtifact], GlobalArtifact]:
        session_id = self.job.session_id

        globals_ = await self._collect_globals(session_id)
        export_addrs = {e["address"] for e in globals_.exports if "address" in e}

        func_list = await self.client.list_functions(session_id=session_id)
        log.info("Found %d functions", len(func_list))
        self.job.stats.total_functions = len(func_list)

        progress = ExtractionProgress(len(func_list))
        sem = asyncio.Semaphore(self.max_workers)
        tasks = [
            self._process_function(f, session_id, export_addrs, sem, progress, on_progress)
            for f in func_list
        ]
        results: list[Optional[FunctionArtifact]] = await asyncio.gather(*tasks)
        artifacts = [a for a in results if a is not None]

        self._save_summary(artifacts, globals_)
        return artifacts, globals_

    async def _collect_globals(self, session_id: Optional[str]) -> GlobalArtifact:
        log.info("Collecting global artifacts")
        try:
            imports = await self.client.get_imports(session_id=session_id)
            exports = await self.client.get_exports(session_id=session_id)
            strings = await self.client.get_strings(session_id=session_id)
            structs = await self.client.get_structs(session_id=session_id)
        except McpError as e:
            log.warning("Global collect partial failure: %s", e)
            imports = exports = strings = structs = []

        globals_ = GlobalArtifact(imports=imports, exports=exports, strings=strings, structs=structs)
        path = self._raw_dir / "globals.json"
        path.write_text(globals_.model_dump_json(indent=2), encoding="utf-8")
        return globals_

    async def _process_function(
        self,
        func_info: dict,
        session_id: Optional[str],
        export_addrs: set[int],
        sem: asyncio.Semaphore,
        progress: ExtractionProgress,
        on_progress: Optional[ProgressCallback],
    ) -> Optional[FunctionArtifact]:
        async with sem:
            addr = func_info.get("address", 0)
            name = func_info.get("name", f"sub_{addr:X}")
            artifact = FunctionArtifact(
                address=addr,
                name=name,
                size=func_info.get("size", 0),
                is_exported=addr in export_addrs,
            )

            for attempt in range(self.retry_count + 1):
                try:
                    await self._fill_artifact(artifact, session_id)
                    artifact.decompile_ok = artifact.decompiled_code is not None
                    break
                except (McpError, asyncio.TimeoutError) as e:
                    if attempt < self.retry_count:
                        log.debug("Retry %d for 0x%X: %s", attempt + 1, addr, e)
                        await asyncio.sleep(0.5 * (attempt + 1))
                    else:
                        artifact.decompile_error = str(e)
                        progress.failed += 1
                        self.job.stats.failed += 1
                        log.warning("Failed 0x%X (%s): %s", addr, name, e)

            if artifact.decompile_ok:
                progress.done += 1
                self.job.stats.decompiled += 1

            self._save_artifact(artifact)

            if on_progress:
                on_progress(progress, artifact)

            return artifact

    async def _fill_artifact(self, artifact: FunctionArtifact, session_id: Optional[str]) -> None:
        addr = artifact.address
        artifact.decompiled_code = await asyncio.wait_for(
            self.client.decompile(addr, session_id=session_id),
            timeout=self.timeout,
        )

        type_info = await self.client.infer_types(addr, session_id=session_id)
        artifact.prototype = type_info.get("prototype") if type_info else None
        artifact.type_ok = bool(artifact.prototype)

        callees = await self.client.get_callees(addr, session_id=session_id)
        artifact.callees = [c.get("address", 0) for c in callees if c.get("address") is not None]

        artifact.stack_vars = await self.client.get_stack_frame(addr, session_id=session_id)

        enrich_artifact_metadata(artifact)

    def _save_artifact(self, artifact: FunctionArtifact) -> None:
        path = self._raw_dir / f"func_{artifact.address:016X}.json"
        path.write_text(artifact.model_dump_json(indent=2), encoding="utf-8")

    def _save_summary(self, artifacts: list[FunctionArtifact], globals_: GlobalArtifact) -> None:
        summary = {
            "total": len(artifacts),
            "decompiled": sum(1 for a in artifacts if a.decompile_ok),
            "failed": sum(1 for a in artifacts if not a.decompile_ok),
            "imports": len(globals_.imports),
            "strings": len(globals_.strings),
        }
        path = self._raw_dir.parent / "summary.json"
        path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
