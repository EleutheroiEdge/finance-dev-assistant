"""One registry for doctor key-use rows and the public command table."""

_SENT = ("Screened packet and instructions, with the required response schema; the key authenticates "
         "only this request. No other local files or environment values.")
KEY_USES = tuple(
    {"command": command, "source": source, "variable": variable, "host": host, "sends": _SENT}
    for commands, source, variable, host in [
        (("review", "propose", "evaluate"), "configuration", "api_key_env or provider default", "configured endpoint"),
        (("gate run", "GitHub Action model-review mode"), "gate policy",
         "model_review.api_key_env", "model_review.allowed_host"),
    ] for command in commands
)


def key_use_markdown() -> str:
    lines = ["| Command | Key variable | Destination host | What is sent |",
             "|---|---|---|---|"]
    lines += [f"| {row['command']} | {row['variable']} | {row['host']} | {row['sends']} |" for row in KEY_USES]
    return "\n".join(lines)
