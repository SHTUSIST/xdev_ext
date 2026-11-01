"""Test-only launcher: fail closed before benchmark/network/device side effects."""
import os
from pathlib import Path
import runpy
import sys

runner = Path(sys.argv[1]).resolve()
sys.argv = [str(runner), *sys.argv[2:]]
sys.path.insert(0, str(runner.parent))
output = Path(sys.argv[sys.argv.index("--output-dir") + 1]).resolve()


def reject_side_effect(event, args):
    if event in {"subprocess.Popen", "os.system", "os.posix_spawn", "os.fork", "os.forkpty", "os.exec", "os.spawn", "socket.connect", "socket.bind", "socket.getaddrinfo"}:
        raise RuntimeError("CONTRACT_SIDE_EFFECT_BLOCKED: " + event)
    if event in {"open", "os.listdir", "os.scandir"} and isinstance(args[0], (str, bytes, os.PathLike)):
        name = os.fsdecode(args[0])
        if name in {"/dev", "/sys"} or (name.startswith("/dev/") and name != "/dev/null") or name.startswith("/sys/"):
            raise RuntimeError("CONTRACT_SIDE_EFFECT_BLOCKED: device probe")
        if event == "open":
            mode, flags = args[1], args[2]
            writes = (isinstance(mode, str) and any(c in mode for c in "wax+")) or bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
            if writes and not Path(name).resolve().is_relative_to(output):
                raise RuntimeError("CONTRACT_SIDE_EFFECT_BLOCKED: write outside output")
    if event in {"os.mkdir", "os.remove", "os.rmdir", "os.rename"}:
        for name in args[:2] if event == "os.rename" else args[:1]:
            if isinstance(name, (str, bytes, os.PathLike)) and not Path(os.fsdecode(name)).resolve().is_relative_to(output):
                raise RuntimeError("CONTRACT_SIDE_EFFECT_BLOCKED: mutation outside output")


sys.addaudithook(reject_side_effect)
runpy.run_path(str(runner), run_name="__main__")
