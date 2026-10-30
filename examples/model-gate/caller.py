"""Example caller: pass a private process variable to a trusted installed gate.

Run this trusted wrapper outside candidate-controlled execution. It never reads
an environment file and never prints a key or puts one in command arguments.
All command arguments after the script name are ordinary `finassist gate run`
arguments. REVIEW_PROVIDER_KEY is a NAME; the real value comes from the caller.
"""

import os
import subprocess
import sys


def main() -> int:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print("Use the event-validating Action adapter in GitHub Actions", file=sys.stderr)
        return 2
    variable = "REVIEW_PROVIDER_KEY"  # Must match the reviewed policy's api_key_env.
    value = os.environ.get(variable, "")
    if not value:
        print("Model gate key is absent", file=sys.stderr)
        return 2
    # Inherit only tool/OS necessities plus the explicitly named key. GitHub
    # Actions should use the Action adapter, which also verifies event identity.
    child = {name: os.environ[name] for name in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "LANG") if name in os.environ}
    child[variable] = value
    return subprocess.run([sys.executable, "-I", "-m", "finassist", "gate", "run", *sys.argv[1:]],
                          env=child, check=False, shell=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
