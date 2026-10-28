"""Explicit, validated configuration. A key's presence never chooses a provider."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from fnmatch import fnmatchcase
from pathlib import Path
from urllib.parse import urlsplit

from .errors import AssistantError
from .security import check_path, check_text, pinned_image, regular_path, write_private, canonical

PROVIDERS = {"offline", "openai", "anthropic", "google", "compatible", "ollama"}
PROFILES = {"finance-saas", "investment-research", "quant-review", "general"}
DEFAULT_ENDPOINTS = {
    "openai": "https://api.openai.com/v1/responses",
    "anthropic": "https://api.anthropic.com/v1/messages",
    "google": "https://generativelanguage.googleapis.com/v1beta",
    "ollama": "http://127.0.0.1:11434/api/chat",
}
DEFAULT_KEYS = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY", "google": "GEMINI_API_KEY"}


@dataclass(frozen=True)
class Config:
    schema_version: int = 1
    provider: str = "offline"
    model: str = ""
    endpoint: str = ""
    api_key_env: str = ""
    auth_header: str = "Authorization"
    profile: str = "finance-saas"
    allow_network: bool = False
    allow_partial_review: bool = False
    allowed_hosts: tuple[str, ...] = ()
    allow_paths: tuple[str, ...] = ("src/", "tests/", "docs/", "scripts/", "README.md", "pyproject.toml")
    protected_paths: tuple[str, ...] = (
        ".github/",
        "LICENSE",
        "AGENTS.md",
        "finassist.json",
        "pyproject.toml",
        "scripts/",
        "requirements-dev.lock",
    )
    protected_branches: tuple[str, ...] = ("main", "master", "trunk", "production", "release", "release/*")
    extra_sensitive_patterns: tuple[str, ...] = ()
    max_file_bytes: int = 48_000
    max_packet_bytes: int = 120_000
    max_output_tokens: int = 4096
    timeout_seconds: int = 60
    max_run_usd: float = 1.0
    daily_budget_usd: float = 5.0
    monthly_budget_usd: float = 100.0
    input_usd_per_million: float = 0.0
    output_usd_per_million: float = 0.0
    recipes: dict = field(default_factory=dict)
    runner_image: str = ""
    required_recipes: tuple[str, ...] = ()
    blocking_severities: tuple[str, ...] = ("critical", "high")
    readiness_max_age_seconds: int = 86400
    allow_local_readiness: bool = False

    def validate(self) -> Config:
        import math
        import re

        for key in ("provider", "model", "endpoint", "api_key_env", "profile", "runner_image"):
            if not isinstance(getattr(self, key), str):
                raise AssistantError("invalid_config_string")
        if self.api_key_env and not re.fullmatch(r"[A-Z][A-Z0-9_]*", self.api_key_env):
            raise AssistantError("invalid_key_variable")
        if self.model and (len(self.model) > 200 or not re.fullmatch(r"[A-Za-z0-9._:/-]+", self.model)):
            raise AssistantError("invalid_model_identifier")
        check_text(self.model)
        check_text(self.endpoint)
        if self.runner_image:
            pinned_image(self.runner_image)
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or self.provider not in PROVIDERS
            or self.profile not in PROFILES
        ):
            raise AssistantError("unsupported_config")
        if self.auth_header not in {"Authorization", "api-key", "x-api-key"}:
            raise AssistantError("unsupported_auth_header")
        for key in (
            "max_file_bytes",
            "max_packet_bytes",
            "max_output_tokens",
            "timeout_seconds",
            "readiness_max_age_seconds",
        ):
            if type(getattr(self, key)) is not int or not 0 < getattr(self, key) <= 2_000_000:
                raise AssistantError("invalid_limit")
        if any(
            type(getattr(self, key)) is not bool
            for key in ("allow_network", "allow_partial_review", "allow_local_readiness")
        ):
            raise AssistantError("invalid_network_permission")
        for key in (
            "max_run_usd",
            "daily_budget_usd",
            "monthly_budget_usd",
            "input_usd_per_million",
            "output_usd_per_million",
        ):
            value = getattr(self, key)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
            ):
                raise AssistantError("invalid_cost_limit")
        for key in (
            "allow_paths",
            "protected_paths",
            "protected_branches",
            "extra_sensitive_patterns",
            "allowed_hosts",
            "required_recipes",
            "blocking_severities",
        ):
            if not isinstance(getattr(self, key), (tuple, list)) or any(
                not isinstance(x, str) for x in getattr(self, key)
            ):
                raise AssistantError("invalid_list")
        for prefix in self.allow_paths:
            check_path(prefix.rstrip("/"), source_only=False)
        for prefix in self.protected_paths:
            check_path(prefix.rstrip("/"), source_only=False)
        if not self.protected_branches or any(
            not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./*?-]*", branch) for branch in self.protected_branches
        ):
            raise AssistantError("invalid_protected_branches")
        try:
            for pattern in self.extra_sensitive_patterns:
                re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise AssistantError("invalid_content_pattern") from exc
        if self.provider != "offline" and not self.model:
            raise AssistantError("model_required")
        if self.provider != "offline":
            try:
                parsed = urlsplit(self.resolved_endpoint)
                port = parsed.port
            except ValueError as exc:
                raise AssistantError("invalid_endpoint") from exc
            if not parsed.hostname or (port is not None and not 1 <= port <= 65535):
                raise AssistantError("invalid_endpoint")
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise AssistantError("unsafe_endpoint")
            local = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
            if parsed.scheme != "https" and not (
                self.provider in {"ollama", "compatible"} and local and parsed.scheme == "http"
            ):
                raise AssistantError("https_required")
            default = urlsplit(DEFAULT_ENDPOINTS.get(self.provider, "")).hostname
            if parsed.hostname != default and parsed.hostname not in self.allowed_hosts:
                raise AssistantError("endpoint_host_not_approved")
        if not isinstance(self.recipes, dict):
            raise AssistantError("invalid_recipes")
        for name, argv in self.recipes.items():
            if (
                not isinstance(name, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name)
                or not isinstance(argv, list)
                or not argv
                or any(not isinstance(a, str) or "\0" in a for a in argv)
            ):
                raise AssistantError("invalid_recipe")
        if len(set(self.required_recipes)) != len(self.required_recipes) or any(
            name not in self.recipes for name in self.required_recipes
        ):
            raise AssistantError("invalid_required_recipes")
        if any(
            value not in {"critical", "high", "medium", "low", "info"} for value in self.blocking_severities
        ):
            raise AssistantError("invalid_blocking_severities")
        return self

    @property
    def resolved_endpoint(self) -> str:
        return self.endpoint or DEFAULT_ENDPOINTS.get(self.provider, "")

    @property
    def key_name(self) -> str:
        return self.api_key_env or DEFAULT_KEYS.get(self.provider, "")

    def allows(self, path: str) -> bool:
        return any(path.startswith(p) if p.endswith("/") else path == p for p in self.allow_paths)

    def protected(self, path: str) -> bool:
        return any(
            path == p.rstrip("/") or path.startswith(p.rstrip("/") + "/") for p in self.protected_paths
        )

    def protected_branch(self, branch: str) -> bool:
        return any(fnmatchcase(branch, pattern) for pattern in self.protected_branches)


def load_config(path: Path | None = None) -> Config:
    if path is None:
        return Config().validate()
    try:
        raw = json.loads(regular_path(path).read_text(encoding="utf-8"))
        for key in (
            "allow_paths",
            "protected_paths",
            "protected_branches",
            "extra_sensitive_patterns",
            "allowed_hosts",
            "required_recipes",
            "blocking_severities",
        ):
            if key in raw and isinstance(raw[key], list):
                raw[key] = tuple(raw[key])
        return Config(**raw).validate()
    except (ValueError, TypeError, OSError) as exc:
        raise AssistantError("invalid_config") from exc


def save_config(path: Path, config: Config) -> None:
    write_private(path, canonical(asdict(config.validate())) + b"\n")
