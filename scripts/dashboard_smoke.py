"""Verify packaged dashboard assets and APIs without Node or external calls."""

from importlib import metadata
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading

import finassist
from finassist.config import Config, save_config
from finassist.dashboard import DashboardServer, DashboardState


def main():
    assert "site-packages" in str(Path(finassist.__file__).resolve())
    with tempfile.TemporaryDirectory(prefix="dashboard-wheel-") as directory:
        root = Path(directory).resolve()
        config = root / "configuration.json"
        save_config(config, Config())
        state = DashboardState(config, root / "state")
        previous = os.environ.get("PATH")
        os.environ["PATH"] = ""  # Runtime must not need Node, Git or a package manager.
        try:
            with DashboardServer(state) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    for target in ["/", *server.assets, "/api/config", "/api/statistics", "/api/health"]:
                        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                        try:
                            connection.request("GET", target, headers={"X-Finassist-Token": state.token})
                            response = connection.getresponse()
                            content = response.read()
                            assert response.status == 200, target
                            if target == "/api/health":
                                health = json.loads(content)
                                assert health["configuration"]["valid"]
                                assert health["doctor"]["version"] == metadata.version("finledgerpoli")
                        finally:
                            connection.close()
                finally:
                    server.shutdown()
                    thread.join(timeout=5)
        finally:
            if previous is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = previous
    print("Installed dashboard assets and APIs: PASS (no Node on runtime PATH)")


if __name__ == "__main__":
    main()
