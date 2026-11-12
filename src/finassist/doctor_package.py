"""Offline package self-checks, separate from shared dashboard health."""

from importlib import metadata
from importlib.resources import files
import json
import sys

import jsonschema

from . import __version__
from .error_hints import error_fields, hints
from .guides import GUIDES


def package_status() -> dict:
    warnings = []
    try:
        installed = metadata.version("finledgerpoli")
    except metadata.PackageNotFoundError:
        installed = None
    if installed != __version__:
        warnings.append({"code": "doctor_version_mismatch", **error_fields("doctor_version_mismatch")})
    results = {}
    resources = files("finassist").joinpath("resources")
    for kind in ("hints", "guides", "schemas"):
        try:
            if kind == "hints":
                hints.__wrapped__()  # Re-read actual package files, even if cached earlier.
            elif kind == "guides":
                for _title, _source, resource in GUIDES.values():
                    text = resources.joinpath(resource).read_text(encoding="utf-8")
                    if not text.lstrip().startswith("#") or "\0" in text:
                        raise ValueError("malformed guide")
            else:
                expected = ("finassist", "review", "model-gate-report", "model-gate-report-v1",
                            "triage-request", "triage-result", "triage-gold")
                for name in expected:
                    schema = json.loads(resources.joinpath(name + ".schema.json").read_text(encoding="utf-8"))
                    if not isinstance(schema, dict) or schema.get("type") != "object":
                        raise ValueError("malformed schema")
                    jsonschema.Draft202012Validator.check_schema(schema)
            results[kind] = "ok"
        except Exception:  # noqa: BLE001 - damaged installed resources must yield a diagnostic, not hide it.
            results[kind] = "unavailable"
            warnings.append({"code": "doctor_resources_unavailable", "resource_kind": kind,
                             **error_fields("doctor_resources_unavailable")})
    return {"code_version": __version__, "metadata_version": installed, "python_executable": sys.executable,
            "resources": results, "warnings": warnings}


def add_package_details(report: dict) -> None:
    """Enrich the CLI report only; dashboard health retains its smaller contract."""
    from .doctor_environment import _shown_path
    from .platform_support import locate_tool

    package = package_status()
    package["python_executable"] = _shown_path(package["python_executable"])
    report["version"] = package["code_version"]
    report["package"] = package
    report["python_executable"] = package["python_executable"]
    report["tools"] = {name: _shown_path(path) if (path := locate_tool(name)) else None
                       for name in ("docker", "podman", "gh")}
    report["environment"]["warnings"].extend(package["warnings"])
    report["key_value_read"] = report["environment"]["key_value_read"]
    report["key_values_returned"] = False
