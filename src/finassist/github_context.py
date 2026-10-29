"""Narrow GitHub pull-request identity projection; event text never authorizes tools."""

from dataclasses import asdict, dataclass
import re

from .ci_policy import repository_name, revision
from .errors import AssistantError
from .scope import git

_ACTIONS = {"opened", "reopened", "synchronize", "ready_for_review", "edited"}


@dataclass(frozen=True)
class PullRequestContext:
    repository: str
    event: str
    action: str
    number: int
    base_branch: str
    base_sha: str
    head_sha: str
    head_repository: str

    def __post_init__(self):
        if (
            self.event != "pull_request" or self.action not in _ACTIONS
            or type(self.number) is not int or self.number <= 0
            or not isinstance(self.base_branch, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,255}", self.base_branch) is None
            or ".." in self.base_branch
        ):
            raise AssistantError("ci_event_invalid")
        repository_name(self.repository)
        repository_name(self.head_repository)
        revision(self.base_sha)
        revision(self.head_sha)

    def document(self) -> dict:
        return asdict(self)


def pull_request_context(document: dict, event: str, repository: str) -> PullRequestContext:
    expected = repository_name(repository)
    if event != "pull_request":
        raise AssistantError("ci_event_not_allowed")
    try:
        pr = document["pull_request"]
        if (
            document["action"] not in _ACTIONS or type(document["number"]) is not int
            or document["number"] <= 0 or type(pr["number"]) is not int or pr["number"] != document["number"]
            or repository_name(document["repository"]["full_name"]) != expected
            or repository_name(pr["base"]["repo"]["full_name"]) != expected
            or not isinstance(pr["base"]["ref"], str) or not 1 <= len(pr["base"]["ref"]) <= 256
        ):
            raise AssistantError("ci_event_invalid")
        return PullRequestContext(expected, event, document["action"], document["number"], pr["base"]["ref"],
                                  revision(pr["base"]["sha"]), revision(pr["head"]["sha"]),
                                  repository_name(pr["head"]["repo"]["full_name"]))
    except (KeyError, TypeError) as exc:
        raise AssistantError("ci_event_invalid") from exc


def verify_origin(repo, repository: str) -> None:
    # A routing check, not proof against a malicious runner rewriting Git config.
    origin = git(repo, "remote", "get-url", "origin")
    identity = re.escape(repository_name(repository))
    if re.fullmatch(r"(?:https://github\.com/|git@github\.com:)" + identity + r"(?:\.git)?", origin, re.IGNORECASE) is None:
        raise AssistantError("ci_origin_mismatch")
