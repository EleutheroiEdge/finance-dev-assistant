"""Exercise real OCI isolation with a caller-prepared, immutable test image."""

from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile

from finassist.config import Config
from finassist.runner import run_recipe


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python scripts/container_smoke.py sha256:IMAGE_ID")
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
        (source / "case.py").write_text(script)
        (source / "case.py").chmod(0o444)
        source.chmod(0o555)
        config = replace(Config(), runner_image=sys.argv[1], recipes={"isolation": ["python", "case.py"]})
        result = run_recipe(config, "isolation", source)
    print(json.dumps(result["receipt"], sort_keys=True))
    return 0 if result["receipt"]["passed"] and result["receipt"]["cleanup_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
