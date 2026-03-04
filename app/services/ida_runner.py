"""
IDARunner — launches idat64.exe headlessly to extract artifacts.

Flow:
  1. Spawn: idat64.exe -A -c -o<idb> -L<ida.log> -S<script> <dll>
  2. Stream stdout, parse [RR] PROGRESS lines → call on_progress
  3. Wait for [RR] DONE or process exit
  4. Return True on success
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import subprocess
import sys
from pathlib import Path, PureWindowsPath
from typing import Callable, Optional

log = logging.getLogger(__name__)

# Parse progress lines: [RR] PROGRESS 50/1000 ok=48 fail=2
_RE_PROGRESS = re.compile(r"\[RR\] PROGRESS (\d+)/(\d+) ok=(\d+) fail=(\d+)")
_RE_DONE = re.compile(r"\[RR\] DONE ok=(\d+) fail=(\d+)")
_RE_ERROR = re.compile(r"\[RR\] ERROR (.+)")

LogCallback = Callable[[str], None]
ProgressCallback = Callable[[int, int, int, int], None]  # done, total, ok, fail


class IDARunnerError(Exception):
    pass


class IDARunner:
    """Manages a single idat64.exe headless analysis run."""

    SCRIPT = Path(__file__).parent.parent / "ida_scripts" / "collect_artifacts.py"
    LOG_NAME = "ida.log"

    def __init__(self, ida_dir: Path) -> None:
        self.ida_dir = self._normalize_host_path(Path(ida_dir))
        self.idat = self.ida_dir / "idat64.exe"
        if not self.idat.exists():
            raise IDARunnerError(f"idat64.exe not found: {self.idat}")

    async def run(
        self,
        dll_path: Path,
        output_dir: Path,
        on_log: Optional[LogCallback] = None,
        on_progress: Optional[ProgressCallback] = None,
        timeout: float = 600.0,
    ) -> bool:
        """
        Run headless extraction. Returns True on success.
        Raises IDARunnerError on hard failure.
        """
        dll_path = Path(dll_path)
        # Always use absolute paths to avoid cwd/relative path confusion
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        idb_path = output_dir / f"{self._stem(dll_path)}.i64"
        ida_log_path = output_dir / self.LOG_NAME

        env = os.environ.copy()
        env["RESOURCE_OUTPUT_DIR"] = self._to_ida_path(output_dir)
        env["PYTHONPATH"] = ""

        cmd = [
            str(self.idat),
            "-A",                                       # autonomous
            "-c",                                       # create fresh database
            f"-o{self._to_ida_path(idb_path)}",        # absolute IDB path
            f"-L{self._to_ida_path(ida_log_path)}",    # absolute log path
            f"-S{self._to_ida_path(self.SCRIPT)}",     # script path
            self._to_ida_path(dll_path),
        ]

        log.info("Launching: %s", " ".join(cmd))
        if on_log:
            on_log(f"idat64.exe 실행 중: {dll_path.name}")
            on_log(f"IDA 로그: {ida_log_path}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
            )
        except FileNotFoundError as e:
            raise IDARunnerError(str(e)) from e

        success = False
        rr_error: Optional[str] = None

        async def _read_output():
            nonlocal success, rr_error
            assert proc.stdout
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").rstrip()
                log.debug("IDA: %s", line)
                if on_log:
                    on_log(line)

                m = _RE_PROGRESS.search(line)
                if m and on_progress:
                    done, total, ok, fail = map(int, m.groups())
                    on_progress(done, total, ok, fail)
                    continue

                m = _RE_DONE.search(line)
                if m:
                    success = True
                    continue

                m = _RE_ERROR.search(line)
                if m:
                    rr_error = m.group(1)
                    if on_log:
                        on_log(f"[IDA 오류] {rr_error}")

        try:
            await asyncio.wait_for(_read_output(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            raise IDARunnerError(
                f"idat64.exe timeout ({timeout}s)\n{self._format_failure_details(ida_log_path, rr_error)}"
            )

        rc = await proc.wait()
        log.info("idat64.exe exited with code %d", rc)

        # Fallback 1: [RR] DONE marker in ida.log
        if not success and ida_log_path.exists():
            log_done, log_error = self._parse_markers_from_log(ida_log_path)
            if log_done:
                success = True
                if on_log:
                    on_log("[IDA] DONE marker recovered from ida.log")
            if not rr_error and log_error:
                rr_error = log_error
                if on_log:
                    on_log(f"[IDA 오류/log] {rr_error}")

        # Fallback 2: summary.json 존재 = 스크립트 완료
        if not success and (output_dir / "summary.json").exists():
            success = True
            if on_log:
                on_log("[IDA] summary.json 확인됨 — 완료 처리")

        # Clean up IDB files (we only need the JSON)
        for ext in (".i64", ".id0", ".id1", ".id2", ".nam", ".til"):
            p = idb_path.with_suffix(ext)
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass

        if not success:
            details = self._format_failure_details(ida_log_path, rr_error)
            if rc != 0:
                raise IDARunnerError(f"idat64.exe exited with code {rc}\n{details}")
            raise IDARunnerError(f"idat64.exe finished without DONE marker\n{details}")

        if rc != 0:
            # Some environments still return non-zero even after script DONE.
            # Keep going, but surface diagnostic context in logs.
            warn = (
                f"idat64.exe exited with code {rc} after DONE marker. "
                "Artifacts may still be usable."
            )
            log.warning("%s\n%s", warn, self._format_failure_details(ida_log_path, rr_error))
            if on_log:
                on_log(warn)

        return True

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_windows_path(path: str) -> bool:
        return bool(re.match(r"^[A-Za-z]:[\\/]", path))

    @classmethod
    def _normalize_host_path(cls, path: Path) -> Path:
        """Make a path usable by the current Python host (Win native or WSL)."""
        if path.exists():
            return path

        raw = str(path)
        if sys.platform.startswith("linux") and cls._looks_windows_path(raw):
            try:
                converted = subprocess.check_output(["wslpath", "-u", raw], text=True).strip()
                p = Path(converted)
                if p.exists():
                    return p
            except (FileNotFoundError, subprocess.CalledProcessError):
                pass

        return path

    @classmethod
    def _to_ida_path(cls, path: Path) -> str:
        """Make a path string that Windows idat64.exe can parse."""
        raw = str(path)
        if sys.platform == "win32" or cls._looks_windows_path(raw):
            return raw

        if sys.platform.startswith("linux"):
            try:
                return subprocess.check_output(["wslpath", "-w", raw], text=True).strip()
            except (FileNotFoundError, subprocess.CalledProcessError):
                return raw

        return raw

    @classmethod
    def _stem(cls, path: Path) -> str:
        raw = str(path)
        if cls._looks_windows_path(raw):
            return PureWindowsPath(raw).stem
        return path.stem

    # ------------------------------------------------------------------
    # Diagnostics helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_failure_details(log_path: Path, rr_error: Optional[str], tail_lines: int = 60) -> str:
        parts: list[str] = [f"ida.log: {log_path}"]
        if rr_error:
            parts.append(f"RR error: {rr_error}")

        if log_path.exists():
            try:
                lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
                tail = "\n".join(lines[-tail_lines:])
                if tail:
                    parts.append("--- ida.log tail ---\n" + tail)
            except OSError:
                pass

        return "\n".join(parts)

    @staticmethod
    def _parse_markers_from_log(log_path: Path) -> tuple[bool, Optional[str]]:
        done = False
        rr_error: Optional[str] = None
        with contextlib.suppress(OSError):
            for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if _RE_DONE.search(line):
                    done = True
                m = _RE_ERROR.search(line)
                if m:
                    rr_error = m.group(1)
        return done, rr_error
