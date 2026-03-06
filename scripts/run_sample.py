"""Run the recovery pipeline for a single sample DLL from the command line."""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from app.models.job import Job
from app.services.job_service import JobService


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", type=Path, help="Path to the DLL/EXE to analyze")
    parser.add_argument(
        "--job-id",
        default=None,
        help="Optional fixed job id. If omitted, Job generates one automatically.",
    )
    return parser.parse_args()


async def _run(job: Job) -> int:
    service = JobService(on_log=lambda msg: print(msg, flush=True))
    project = await service.run(job)
    if project is None:
        print("analysis failed", file=sys.stderr)
        return 1

    print(
        f"JOB={job.id} TOTAL={project.total_functions} "
        f"PLACED={project.placed_functions} FAILED={project.failed_functions}",
        flush=True,
    )
    print(f"OUTPUT={project.output_dir / project.job_id}", flush=True)
    return 0


def main() -> int:
    args = parse_args()
    dll = args.dll.resolve()
    job = Job(dll_path=dll, output_dir=Path("outputs"), id=args.job_id) if args.job_id else Job(
        dll_path=dll,
        output_dir=Path("outputs"),
    )
    return asyncio.run(_run(job))


if __name__ == "__main__":
    raise SystemExit(main())
