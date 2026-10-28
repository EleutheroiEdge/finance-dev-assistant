"""Exercise real OCI isolation with a caller-prepared, immutable test image."""

from dataclasses import replace
import argparse
import json
from pathlib import Path
import sys
import tempfile
import shutil
import subprocess

from finassist.config import Config
from finassist.runner import run_recipe


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("--require-runtime", action="store_true")
    args = parser.parse_args()
    if sys.platform != "linux" or not shutil.which("docker"):
        print("SKIP: real container isolation requires Linux with an available Docker daemon")
        return 1 if args.require_runtime else 0
    daemon = subprocess.run(
        [shutil.which("docker"), "info", "--format", "{{.OSType}}"],
        capture_output=True,
        timeout=15,
        check=False,
    )
    if daemon.returncode:
        print("SKIP: Docker daemon is unavailable; no isolation result claimed")
        return 1 if args.require_runtime else 0
    script = """
import os
from pathlib import Path
import socket

assert os.geteuid() != 0
assert os.statvfs('/').f_flag & os.ST_RDONLY
assert os.statvfs('/workspace').f_flag & os.ST_RDONLY
assert {name for _, name in socket.if_nameindex()} == {'lo'}
try:
    Path('/workspace/should-not-write').write_text('fictional')
except (OSError, PermissionError):
    pass
else:
    raise AssertionError('source was writable')
try:
    Path('/should-not-write').write_text('fictional')
except (OSError, PermissionError):
    pass
else:
    raise AssertionError('root was writable')
Path('/tmp/allowed-scratch').write_text('fictional')
sock = socket.socket()
sock.settimeout(0.3)
try:
    sock.connect(('192.0.2.1', 80))
except OSError:
    pass
else:
    raise AssertionError('unexpected network connectivity')
finally:
    sock.close()
assert not os.environ.get('OPENAI_API_KEY')
print('non-root; readonly source and root; writable scratch; no network; no provider key')
"""
    with tempfile.TemporaryDirectory(prefix="finassist-oci-smoke-") as root:
        source = Path(root) / "source"
        source.mkdir(mode=0o755)
        (source / "case.py").write_text(script, encoding="utf-8", newline="\n")
        (source / "case.py").chmod(0o444)
        source.chmod(0o555)
        config = replace(Config(), runner_image=args.image, recipes={"isolation": ["python", "case.py"]})
        result = run_recipe(config, "isolation", source)
    print(json.dumps(result["receipt"], sort_keys=True))
    return 0 if result["receipt"]["passed"] and result["receipt"]["cleanup_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
