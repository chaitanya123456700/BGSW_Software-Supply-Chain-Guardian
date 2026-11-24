import os
import signal
import subprocess
import sys
import tempfile
import time
from contextvars import ContextVar
from pathlib import Path

from .files import MAX_BYTES, MAX_FILES

WORKSPACE = Path(__file__).resolve().parent.parent
SCAN_DEADLINE = ContextVar("scan_deadline", default=None)
SCAN_CANCEL_CHECK = ContextVar("scan_cancel_check", default=lambda: None)


class ScanCancelled(RuntimeError):
    pass


class ToolError(RuntimeError):
    pass


def run_tool(args: list[str], cwd: Path, timeout: float = 120, *, extra_env=None,
             check=True, monitor: Path | None = None) -> subprocess.CompletedProcess:
    """Run trusted tools against untrusted data with a clean environment and bounds."""
    scan_deadline = SCAN_DEADLINE.get()
    if scan_deadline is not None:
        timeout = min(timeout, scan_deadline - time.monotonic())
    if timeout <= 0:
        raise ToolError("Total scan timeout exceeded")
    with tempfile.TemporaryDirectory(prefix="guardian-home-") as home, tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        env = {
            "PATH": str(WORKSPACE / ".tools/bin") + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": home, "TMPDIR": home, "LANG": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_ALLOW_PROTOCOL": "https", "GIT_CONFIG_COUNT": "0",
            "SYFT_CHECK_FOR_APP_UPDATE": "false",
        }
        env.update(extra_env or {})
        launcher = Path(__file__).with_name("limited_exec.py")
        command = [sys.executable, str(launcher), *args]
        try:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                stdout=out, stderr=err, start_new_session=True)
        except OSError as exc:
            raise ToolError(f"Cannot start {Path(args[0]).name}: {exc}") from exc
        deadline = time.monotonic() + timeout
        last_monitor = 0
        try:
            while process.poll() is None:
                SCAN_CANCEL_CHECK.get()()
                now = time.monotonic()
                if now >= deadline:
                    raise ToolError(f"{Path(args[0]).name} timed out")
                if out.tell() > 30 * 1024 * 1024 or err.tell() > 4 * 1024 * 1024:
                    raise ToolError("Tool output limit exceeded")
                if monitor and now - last_monitor >= 0.5:
                    count = total = 0
                    for directory, dirs, files in os.walk(monitor, followlinks=False):
                        dirs[:] = [d for d in dirs if not (Path(directory) / d).is_symlink()]
                        for name in files:
                            path = Path(directory) / name
                            if not path.is_symlink() and path.is_file():
                                count += 1
                                total += path.stat().st_size
                            if count > MAX_FILES or total > MAX_BYTES:
                                raise ToolError("Repository resource limit exceeded")
                    last_monitor = now
                time.sleep(0.05)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
        out.seek(0)
        err.seek(0)
        stdout = out.read(30 * 1024 * 1024 + 1)
        stderr = err.read(4 * 1024 * 1024 + 1)
        if len(stdout) > 30 * 1024 * 1024 or len(stderr) > 4 * 1024 * 1024:
            raise ToolError("Tool output limit exceeded")
        result = subprocess.CompletedProcess(args, process.returncode,
            stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace"))
        if check and result.returncode:
            raise ToolError(f"{Path(args[0]).name} exited {result.returncode}: {result.stderr[-2000:]}")
        return result
