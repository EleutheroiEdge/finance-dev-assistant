from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Thread

from finassist.config import Config
from finassist.review import review_packet
from finassist.scope import build_packet


def test_actual_loopback_protocol_ignores_proxy_and_validates_source(repository, tmp_path, monkeypatch):
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.append({"path": self.path, "body": body, "auth": self.headers.get("Authorization")})
            source = json.loads(body["messages"][1]["content"])
            reply = {
                "head": source["head"],
                "summary": "Fictional protocol response",
                "findings": [],
                "reviewed_paths": [file["path"] for file in source["files"]],
            }
            data = json.dumps(
                {
                    "done": True,
                    "message": {"content": json.dumps(reply)},
                    "prompt_eval_count": 100,
                    "eval_count": 50,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    config = replace(
        Config(),
        provider="ollama",
        model="fictional",
        allow_network=True,
        endpoint=f"http://127.0.0.1:{server.server_port}/api/chat",
    )
    try:
        report = review_packet(
            packet,
            config,
            tmp_path / "audit.db",
            network_approved=True,
            approved_packet_hash=packet["packet_hash"],
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
    assert report["status"] == "no-findings-reported"
    assert len(received) == 1 and received[0]["auth"] is None
    assert received[0]["body"]["stream"] is False
    assert received[0]["body"]["messages"][0]["role"] == "system"
