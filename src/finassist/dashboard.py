"""Loopback-only, offline configuration and audit dashboard. No model/tool actions."""

from dataclasses import asdict, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import secrets
from socketserver import TCPServer
import sqlite3
import threading
import time
from urllib.parse import urlsplit, unquote

from .auditing import command_audit
from .config import Config, DEFAULT_KEYS, PROVIDERS, load_config, config_document
from .errors import AssistantError, OperationOutcomeUnknown
from .health import doctor_report
from .ledger import Ledger
from .profiles import PROFILES
from .security import canonical, check_text, digest, regular_path, write_private
from .statistics import statistics

EDITABLE = frozenset(
    {
        "provider",
        "model",
        "daily_budget_usd",
        "monthly_budget_usd",
        "allow_paths",
        "generated_paths",
        "protected_paths",
        "extra_sensitive_patterns",
        "profile",
        "required_recipes",
        "blocking_severities",
        "readiness_max_age_seconds",
    }
)


class DashboardState:
    def __init__(self, config_path: Path, state_dir: Path):
        self.config_path = regular_path(config_path)
        self.ledger_path = regular_path(state_dir / "audit.sqlite")
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.pending = {}

    def _configuration_snapshot(self):
        try:
            if self.config_path.exists() and self.config_path.stat().st_size > 2_000_000:
                raise AssistantError("config_file_too_large")
            raw = self.config_path.read_bytes() if self.config_path.exists() else None
            config = load_config(self.config_path, content=raw) if raw is not None else Config().validate()
            check_text(canonical(asdict(config)).decode())
            revision = digest((raw or b"") + canonical(asdict(config)))
            return config, revision, raw
        except (AssistantError, OSError, ValueError, TypeError) as exc:
            raise AssistantError("configuration_invalid") from exc

    def configuration(self):
        config, revision, _ = self._configuration_snapshot()
        return config, revision

    def public_config(self):
        config, revision = self.configuration()
        values = asdict(config)
        return {
            "revision": revision,
            "values": {key: values[key] for key in EDITABLE},
            "options": {
                "providers": sorted(PROVIDERS),
                "profiles": sorted(getattr(config, "profiles", PROFILES)),
                "recipes": sorted(config.recipes),
            },
            "key_presence": {
                **{provider: bool(os.environ.get(name)) for provider, name in DEFAULT_KEYS.items()},
                "configured": bool(os.environ.get(config.key_name)) if config.key_name else False,
            },
        }

    def preview(self, document):
        if not isinstance(document, dict) or set(document) != {"revision", "changes"}:
            raise AssistantError("invalid_preview")
        changes = document["changes"]
        if not isinstance(changes, dict) or set(changes) - EDITABLE:
            raise AssistantError("unsupported_setting")
        with self.lock:
            current, revision = self.configuration()
            if document["revision"] != revision:
                raise AssistantError("configuration_changed_reload")
            candidate = replace(current, **changes).validate()
            check_text(canonical(asdict(candidate)).decode())
            before, after = asdict(current), asdict(candidate)
            diff = [
                {"field": key, "before": before[key], "after": after[key]}
                for key in sorted(EDITABLE)
                if canonical(before[key]) != canonical(after[key])
            ]
            identifier = secrets.token_urlsafe(24)
            if len(self.pending) >= 16:
                self.pending.pop(next(iter(self.pending)))
            self.pending[identifier] = (revision, candidate, diff)
            return {"proposal_id": identifier, "revision": revision, "diff": diff}

    def confirm(self, document):
        if (
            not isinstance(document, dict)
            or set(document) != {"proposal_id", "confirm"}
            or document["confirm"] is not True
        ):
            raise AssistantError("explicit_confirmation_required")
        identifier = document["proposal_id"]
        if not isinstance(identifier, str):
            raise AssistantError("invalid_proposal")
        with self.lock:
            proposal = self.pending.pop(identifier, None)
            if proposal is None:
                raise AssistantError("proposal_missing_or_consumed")
            revision, candidate, diff = proposal
            _, current, before_bytes = self._configuration_snapshot()
            if current != revision:
                raise AssistantError("configuration_changed_reload")
            payload = canonical(config_document(candidate)) + b"\n"
            saved = False
            try:
                with command_audit(self.ledger_path, "dashboard-save", candidate):
                    with Ledger(self.ledger_path) as ledger:
                        ledger.append(
                            {
                                "event": "configuration_save_requested",
                                "before_revision": revision,
                                "after_hash": digest(payload),
                                "fields": [item["field"] for item in diff],
                            }
                        )
                    # Reuse one captured byte snapshot for both backup digest
                    # and backup content, without rereading a concurrent writer.
                    if before_bytes is not None:
                        backup = self.ledger_path.parent / "config-backups" / (digest(before_bytes) + ".json")
                        if not backup.exists():
                            write_private(backup, before_bytes)
                    try:
                        write_private(self.config_path, payload, replace=before_bytes is not None)
                        saved = True
                        with Ledger(self.ledger_path) as ledger:
                            ledger.append(
                                {
                                    "event": "configuration_saved",
                                    "after_hash": digest(payload),
                                    "fields": [item["field"] for item in diff],
                                }
                            )
                    except Exception as exc:
                        # A replacement attempt can take effect before an IO
                        # acknowledgement fails. Retain the open audit run even
                        # when write_private itself cannot confirm completion.
                        raise OperationOutcomeUnknown("configuration_saved_audit_unknown_reload") from exc

            except Exception as exc:
                if saved:
                    raise OperationOutcomeUnknown("configuration_saved_audit_unknown_reload") from exc
                raise
            return self.public_config()

    def health(self):
        try:
            config, _ = self.configuration()
            status = {"valid": True, "code": None}
        except (AssistantError, OSError, ValueError, TypeError):
            config = Config()
            status = {"valid": False, "code": "configuration_invalid"}
        return {"doctor": doctor_report(config), "configuration": status}


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, state: DashboardState, port: int = 0):
        if type(port) is not int or not 0 <= port <= 65535:
            raise AssistantError("invalid_dashboard_port")
        self.state = state
        self.assets = {}
        resource = files("finassist").joinpath("resources/dashboard")
        manifest = json.loads(resource.joinpath("manifest.json").read_text(encoding="utf-8"))
        if not isinstance(manifest, dict) or not 1 <= len(manifest) <= 64:
            raise AssistantError("dashboard_assets_invalid")
        for name, expected in manifest.items():
            if (
                not isinstance(name, str)
                or ".." in PurePosixPath(name).parts
                or name.startswith("/")
                or "\\" in name
                or ":" in name
            ):
                raise AssistantError("dashboard_assets_invalid")
            data = resource.joinpath(name).read_bytes()
            if digest(data) != expected:
                raise AssistantError("dashboard_assets_invalid")
            self.assets["/" + name] = data
        if "/index.html" not in self.assets:
            raise AssistantError("dashboard_assets_missing")
        super().__init__(("127.0.0.1", port), DashboardHandler)
        self.origin = "http://127.0.0.1:" + str(self.server_port)

    def server_bind(self):
        # HTTPServer normally calls socket.getfqdn() here. A fixed loopback
        # listener needs no DNS, which can block on offline macOS hosts.
        TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return connection, address

    def handle_error(self, *_):
        pass  # HTTP failures must not print request data or private stack paths.


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "LocalAssistant"
    sys_version = ""

    def log_message(self, *_):
        pass  # Never log request URLs, bodies, tokens or local paths.

    def allowed(self, *, mutation=False, token=True):
        expected_host = self.server.origin.removeprefix("http://")
        if self.headers.get_all("Host", []) != [expected_host]:
            raise AssistantError("origin_rejected")
        origins = self.headers.get_all("Origin", [])
        if (mutation and origins != [self.server.origin]) or (origins and origins != [self.server.origin]):
            raise AssistantError("origin_rejected")
        if self.headers.get("Sec-Fetch-Site", "none") not in {"same-origin", "none"}:
            raise AssistantError("origin_rejected")
        if token:
            values = self.headers.get_all("X-Finassist-Token", [])
            if (
                len(values) != 1
                or not values[0].isascii()
                or not hmac.compare_digest(values[0], self.server.state.token)
            ):
                raise AssistantError("session_token_required")

    def respond(self, status, body, content_type="application/json; charset=utf-8"):
        data = canonical(body) if not isinstance(body, bytes) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        self.end_headers()
        self.wfile.write(data)

    def discard_oversized_body(self, length):
        # Windows may reset a connection closed with unread request bytes,
        # hiding the refusal response. Drain only a small authenticated excess;
        # never parse it or wait without both a byte cap and a total deadline.
        if not 65536 < length <= 131072:
            return
        deadline = time.monotonic() + 0.25
        previous_timeout = self.connection.gettimeout()
        try:
            while length:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.connection.settimeout(remaining)
                chunk = self.rfile.read1(min(length, 16384))
                if not chunk:
                    break
                length -= len(chunk)
        except OSError:
            pass  # A truncated/stalled rejected body cannot authorize an action.
        finally:
            self.connection.settimeout(previous_timeout)

    def dispatch(self, mutation=False):
        try:
            parsed = urlsplit(self.path)
            path = unquote(parsed.path)
            if parsed.query or parsed.fragment:
                raise AssistantError("request_target_invalid")
            self.allowed(mutation=mutation, token=path.startswith("/api/") and path != "/api/session")
            if mutation:
                self.allowed(mutation=True)
                lengths = self.headers.get_all("Content-Length", [])
                if (
                    self.headers.get("Transfer-Encoding")
                    or len(lengths) != 1
                    or not lengths[0].isdigit()
                ):
                    raise AssistantError("request_size_invalid")
                length = int(lengths[0])
                if not 0 < length <= 65536:
                    self.discard_oversized_body(length)
                    raise AssistantError("request_size_invalid")
                if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
                    raise AssistantError("json_required")
                document = json.loads(self.rfile.read(length).decode("utf-8"))
                if path == "/api/config/preview":
                    result = self.server.state.preview(document)
                elif path == "/api/config/confirm":
                    result = self.server.state.confirm(document)
                else:
                    return self.respond(404, {"code": "not_found"})
            elif path == "/api/session":
                result = {"token": self.server.state.token}
            elif path == "/api/config":
                result = self.server.state.public_config()
            elif path == "/api/health":
                result = self.server.state.health()
            elif path == "/api/statistics":
                config, _ = self.server.state.configuration()
                result = statistics(self.server.state.ledger_path, config)
            else:
                asset = "/index.html" if path == "/" else path
                if asset not in self.server.assets:
                    return self.respond(404, {"code": "not_found"})
                suffix = PurePosixPath(asset).suffix
                kind = {
                    ".html": "text/html; charset=utf-8",
                    ".js": "text/javascript; charset=utf-8",
                    ".css": "text/css; charset=utf-8",
                    ".txt": "text/plain; charset=utf-8",
                    ".svg": "image/svg+xml",
                    ".png": "image/png",
                }.get(suffix, "application/octet-stream")
                return self.respond(200, self.server.assets[asset], kind)
            return self.respond(200, result)
        except AssistantError as exc:
            if exc.code == "configuration_invalid":
                return self.respond(409, {"kind": "configuration", "code": exc.code})
            return self.respond(
                403 if exc.code in {"origin_rejected", "session_token_required"} else 409, {"code": exc.code}
            )
        except sqlite3.Error:
            return self.respond(409, {"code": "audit_unavailable"})
        except (OSError, ValueError, TypeError, KeyError):
            return self.respond(400, {"code": "invalid_request"})

    def do_GET(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch(mutation=True)

    def do_OPTIONS(self):
        self.respond(403, {"code": "origin_rejected"})


def serve_dashboard(config_path: Path, state_dir: Path, port: int = 0):
    state = DashboardState(config_path, state_dir)
    with DashboardServer(state, port) as server:
        print("Dashboard: " + server.origin, flush=True)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            pass
    return 0
