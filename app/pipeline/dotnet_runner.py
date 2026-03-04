"""
DotNetRunner — .NET 어셈블리를 ilspycmd로 C# 소스로 복원.

ilspycmd --project -o <output_dir> <dll>
→ .csproj + 네임스페이스별 .cs 파일 생성
"""
from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger(__name__)

LogCallback = Callable[[str], None]
ProgressCallback = Callable[[int, int], None]  # done, total


class DotNetRunnerError(Exception):
    pass


class DotNetRunner:
    def __init__(self) -> None:
        self.ilspycmd = shutil.which("ilspycmd")
        if not self.ilspycmd:
            raise DotNetRunnerError(
                "ilspycmd를 찾을 수 없습니다.\n"
                "설치: dotnet tool install -g ilspycmd"
            )

    async def run(
        self,
        dll_path: Path,
        output_dir: Path,
        on_log: Optional[LogCallback] = None,
        timeout: float = 300.0,
        reference_paths: Optional[list[Path]] = None,
    ) -> Path:
        """
        .NET DLL을 C# 프로젝트로 복원.
        Returns: 생성된 출력 디렉터리
        """
        dll_path = Path(dll_path).resolve()
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            self.ilspycmd,
            "--project",            # .csproj + .cs 파일 구조로 출력
            "-o", str(output_dir),  # 출력 폴더
        ]
        for rp in (reference_paths or []):
            cmd += ["-r", str(rp)]
        cmd.append(str(dll_path))

        log.info("ilspycmd: %s", " ".join(cmd))
        if on_log:
            on_log(f"ilspycmd 실행 중: {dll_path.name}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except FileNotFoundError as e:
            raise DotNetRunnerError(str(e)) from e

        lines: list[str] = []

        async def _read():
            assert proc.stdout
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").rstrip()
                lines.append(line)
                log.debug("ilspy: %s", line)
                if on_log:
                    on_log(line)

        try:
            await asyncio.wait_for(_read(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            raise DotNetRunnerError(f"ilspycmd timeout ({timeout}s)")

        rc = await proc.wait()
        if rc != 0:
            tail = "\n".join(lines[-20:])
            raise DotNetRunnerError(f"ilspycmd exit {rc}\n{tail}")

        if on_log:
            on_log(f"ilspycmd 완료 → {output_dir}")

        return output_dir
