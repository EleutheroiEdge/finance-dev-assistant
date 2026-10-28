"""Explicit, validated configuration. A key's presence never chooses a provider."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from copy import deepcopy
import json
from fnmatch import fnmatchcase
from pathlib import Path
from urllib.parse import urlsplit

from .errors import AssistantError
from .security import (
    check_path,
    check_text,
    pinned_image,
    regular_path,
    write_private,
    canonical,
    DENIED_PARTS,
    TEXT_SUFFIXES,
)
from .profiles import PROFILES as DEFAULT_PROFILES

PROVIDERS = {"offline", "openai", "anthropic", "google", "compatible", "ollama"}
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
    profiles: dict = field(default_factory=lambda: deepcopy(DEFAULT_PROFILES))
    profile_files: tuple[str, ...] = ()
    denied_parts: tuple[str, ...] = tuple(sorted(DENIED_PARTS))
    text_suffixes: tuple[str, ...] = tuple(sorted(TEXT_SUFFIXES))
    github_host: str = "github.com"
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
        if type(self.schema_version) is not int or self.schema_version != 1 or self.provider not in PROVIDERS:
            raise AssistantError("unsupported_config")
        if (
            not isinstance(self.denied_parts, (list, tuple))
            or any(
                not isinstance(value, str)
                or not re.fullmatch(r"[a-z0-9_.-]{1,64}", value)
                or value in {".", ".."}
                for value in self.denied_parts
            )
            or len(self.denied_parts) > 128
            or len(set(self.denied_parts)) != len(self.denied_parts)
        ):
            raise AssistantError("invalid_denied_parts")
        if not {".git", ".finassist"} <= set(self.denied_parts):
            raise AssistantError("required_denied_parts_missing")
        if (
            not isinstance(self.text_suffixes, (list, tuple))
            or not self.text_suffixes
            or any(
                not isinstance(value, str) or not re.fullmatch(r"\.[a-z][a-z0-9]{0,15}", value)
                for value in self.text_suffixes
            )
            or len(self.text_suffixes) > 128
            or len(set(self.text_suffixes)) != len(self.text_suffixes)
        ):
            raise AssistantError("invalid_text_suffixes")
        if (
            not isinstance(self.github_host, str)
            or len(self.github_host) > 253
            or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in self.github_host.split(".")
            )
        ):
            raise AssistantError("invalid_github_host")
        if (
            not isinstance(self.profiles, dict)
            or not 1 <= len(self.profiles) <= 64
            or "general" not in self.profiles
        ):
            raise AssistantError("invalid_profiles")
        for name, checklist in self.profiles.items():
            if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name):
                raise AssistantError("invalid_profile_name")
            if (
                not isinstance(checklist, list)
                or not 1 <= len(checklist) <= 64
                or any(
                    not isinstance(item, str) or not item.strip() or len(item) > 2000 for item in checklist
                )
            ):
                raise AssistantError("invalid_profile_checklist")
            for item in checklist:
                check_text(item)
        if self.profile not in self.profiles:
            raise AssistantError("unknown_profile")
        if (
            not isinstance(self.profile_files, (list, tuple))
            or len(self.profile_files) > 16
            or any(not isinstance(item, str) or not item or "\0" in item for item in self.profile_files)
        ):
            raise AssistantError("invalid_profile_files")
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
        for key in ("max_run_usd", "daily_budget_usd", "input_usd_per_million", "output_usd_per_million"):
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
            self.check_path(prefix.rstrip("/"), source_only=False)
        for prefix in self.protected_paths:
            self.check_path(prefix.rstrip("/"), source_only=False)
        if not self.protected_branches or any(
            not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./*?-]*", branch) for branch in self.protected_branches
        ):
            raise AssistantError("invalid_protected_branches")
        try:
            for pattern in self.extra_sensitive_patterns:
                re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise AssistantError("invalid_content_pattern") from exc
        check_text(canonical(self.profiles).decode(), extra_patterns=self.extra_sensitive_patterns)
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

    def check_path(self, path: str, **kwargs) -> str:
        return check_path(path, denied_parts=self.denied_parts, text_suffixes=self.text_suffixes, **kwargs)

    def instructions(self) -> str:
        from .profiles import instructions

        self.validate()
        return instructions(self.profile, self.profiles)

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
        path = regular_path(path)
        if path.stat().st_size > 2_000_000:
            raise AssistantError("config_file_too_large")
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or set(raw) - {item.name for item in fields(Config)}:
            raise AssistantError("unknown_config_option")
        for key in (
            "allow_paths",
            "protected_paths",
            "protected_branches",
            "extra_sensitive_patterns",
            "allowed_hosts",
            "required_recipes",
            "blocking_severities",
            "denied_parts",
            "text_suffixes",
            "profile_files",
        ):
            if key in raw and isinstance(raw[key], list):
                raw[key] = tuple(raw[key])
        config = Config(**raw)
        if not isinstance(config.profile_files, (list, tuple)) or len(config.profile_files) > 16:
            raise AssistantError("invalid_profile_files")
        profiles = deepcopy(config.profiles)
        if not isinstance(profiles, dict):
            raise AssistantError("invalid_profiles")
        loaded = set()
        for filename in config.profile_files:
            if not isinstance(filename, str) or not filename or "\0" in filename:
                raise AssistantError("invalid_profile_files")
            try:
                source = regular_path(path.parent / filename)
                if source.stat().st_size > 128_000:
                    raise AssistantError("profile_file_too_large")
                definitions = json.loads(source.read_text(encoding="utf-8"))
            except OSError as exc:
                raise AssistantError("profile_file_unavailable") from exc
            except ValueError as exc:
                raise AssistantError("profile_file_invalid") from exc
            if not isinstance(definitions, dict) or loaded.intersection(definitions):
                raise AssistantError("duplicate_or_invalid_profile_file")
            loaded.update(definitions)
            profiles.update(definitions)
        from dataclasses import replace

        return replace(config, profiles=profiles).validate()
    except (ValueError, TypeError, OSError) as exc:
        raise AssistantError("invalid_config") from exc


def save_config(path: Path, config: Config) -> None:
    write_private(path, canonical(asdict(config.validate())) + b"\n")
