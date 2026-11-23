"""Gate A9: the credential screen's recall and precision on a labelled synthetic corpus, offline.

Positives are synthetic values in the formats real credentials take (cloud and service keys, tokens, private keys,
signed web tokens, passwords in configuration and connection strings), each placed in the files and languages
they appear in. Negatives are what a screen must let through: lookups of a variable or the environment, empty or
placeholder values, hashes, identifiers and checksums, and words such as "key" that name no secret. Every value
is generated from a seed at run time, so this file holds no credential-shaped literal of its own.

Only counts are printed: by format and by file kind, then recall and precision with 95% Wilson intervals.

    python scripts/secret_screen_accuracy.py [--seed N] [--per-cell N]

Exit status: 0 when recall is at least 0.88 and precision at least 0.75 (the bar the best single tools reach on a
public labelled set); 1 otherwise.
"""

from __future__ import annotations

import argparse
import base64
import collections
import math
import random
import string
import sys

from finassist.errors import AssistantError
from finassist.security import check_credentials

RECALL_BAR = 0.88
PRECISION_BAR = 0.75
UPPER_DIGITS = string.ascii_uppercase + string.digits
ALNUM = string.ascii_letters + string.digits
B64 = string.ascii_letters + string.digits + "+/"


def _pick(rng: random.Random, alphabet: str, size: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(size))


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


# Each format returns (name, value). Prefixes are joined from parts so that no line here looks like a credential.
def _cloud_access_key(rng):
    return "cloud access key id", "AK" + "IA" + _pick(rng, UPPER_DIGITS, 16)


def _cloud_secret(rng):
    return "cloud secret key", _pick(rng, B64, 40)


def _code_host_token(rng):
    return "code-host token", "gh" + "p_" + _pick(rng, ALNUM, 36)


def _chat_bot_token(rng):
    digits = string.digits
    return "chat bot token", "xo" + "xb-" + _pick(rng, digits, 12) + "-" + _pick(rng, digits, 13) + "-" + _pick(
        rng, ALNUM, 24)


def _payment_key(rng):
    return "payment live key", "sk" + "_live_" + _pick(rng, ALNUM, 24)


def _maps_key(rng):
    return "maps API key", "AI" + "za" + _pick(rng, ALNUM + "-_", 35)


def _web_token(rng):
    header = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    payload = _b64url(('{"sub":"%d","name":"%s"}' % (rng.randrange(10**6), _pick(rng, string.ascii_lowercase, 8)))
                      .encode())
    return "signed web token", header + "." + payload + "." + _b64url(bytes(rng.randrange(256) for _ in range(32)))


def _api_token(rng):
    return "api token", _pick(rng, ALNUM, 32)


def _password(rng):
    """Half are letters and digits only; half hold one or two marks such as ! or %, at random places."""
    characters = list(_pick(rng, ALNUM, rng.randrange(14, 21)))
    if rng.random() < 0.5:
        for _ in range(rng.randrange(1, 3)):
            characters[rng.randrange(1, len(characters))] = rng.choice("!#$%&*?")
    return "password", "".join(characters)


FORMATS = (_cloud_access_key, _cloud_secret, _code_host_token, _chat_bot_token, _payment_key, _maps_key,
           _web_token, _api_token, _password)


def _private_key(rng) -> str:
    body = "\n".join(_pick(rng, B64, 64) for _ in range(12))
    kind = "RSA " + "PRI" + "VATE KEY"
    return "-----BEGIN " + kind + "-----\n" + body + "\n-----END " + kind + "-----\n"


# Each placement returns (file kind, path, text) for a credential label and a value.
def _placements(label: str, value: str):
    upper = label.upper().replace(" ", "_")
    lower = label.lower().replace(" ", "_")
    return (
        ("dotenv", "deploy/.env.production", f"{upper}={value}\n"),
        ("yaml", "config/service.yaml", f"service:\n  {lower}: {value}\n"),
        ("json", "config/service.json", '{"%s": "%s"}\n' % (lower, value)),
        ("python", "src/app/settings.py", f'{upper} = "{value}"\n'),
        ("typescript", "src/client.ts", f'const {lower} = "{value}";\n'),
        ("shell", "scripts/deploy.sh", f"export {upper}='{value}'\n"),
    )


LABELS = {
    "cloud access key id": "aws access key id", "cloud secret key": "aws secret access key",
    "code-host token": "github token", "chat bot token": "slack bot token", "payment live key": "stripe secret key",
    "maps API key": "google api key", "signed web token": "auth token", "api token": "api token",
    "password": "db password",
}


def positives(rng: random.Random, per_cell: int):
    for make in FORMATS:
        for _ in range(per_cell):
            name, value = make(rng)
            for kind, path, text in _placements(LABELS[name], value):
                yield name, kind, path, text
    for _ in range(per_cell):
        user, password = _pick(rng, string.ascii_lowercase, 6), _pick(rng, ALNUM, 16)
        yield ("connection string", "yaml", "config/database.yaml",
               f"database:\n  url: postgres://{user}:{password}@db.internal:5432/app\n")
        yield "private key", "pem", "deploy/service.pem", _private_key(rng)
        yield "private key", "yaml", "config/tls.yaml", "tls:\n  key: |\n" + "".join(
            "    " + line + "\n" for line in _private_key(rng).splitlines())


def negatives(rng: random.Random, per_cell: int):
    for _ in range(per_cell):
        name = rng.choice(["API_TOKEN", "DB_PASSWORD", "SERVICE_SECRET", "AUTH_KEY"])
        lower = name.lower()
        yield "environment lookup", "python", "src/app/settings.py", f'{name} = os.environ["{name}"]\n'
        yield "environment lookup", "typescript", "src/client.ts", f"const {lower} = process.env.{name};\n"
        yield "environment lookup", "yaml", ".github/workflows/ci.yml", (
            "env:\n  %s: ${{ secrets.%s }}\n" % (name, name))
        yield "variable reference", "yaml", "config/service.yaml", f"service:\n  {lower}: ${{{name}}}\n"
        yield "variable reference", "dotenv", "deploy/.env.example", f"{name}=\n"
        hyphened = lower.replace("_", "-")
        yield "placeholder", "yaml", "config/service.yaml", f"service:\n  {lower}: <your-{hyphened}>\n"
        yield "placeholder", "python", "src/app/settings.py", f'{name} = "YOUR_{name}_HERE"\n'
        yield "placeholder", "json", "config/service.json", '{"%s": ""}\n' % lower
        yield "placeholder", "yaml", "config/service.yaml", f"service:\n  {lower}: changeme\n"
        digest = "".join(rng.choice("0123456789abcdef") for _ in range(64))
        yield "checksum", "json", "package-lock.json", '{"integrity": "sha512-%s"}\n' % _pick(rng, B64, 86)
        yield "checksum", "yaml", "config/release.yaml", f"release:\n  sha256: {digest}\n"
        record = f"{digest[:8]}-{digest[8:12]}-4{digest[13:16]}-a{digest[17:20]}-{digest[20:32]}"
        yield "identifier", "python", "src/app/models.py", f'RECORD_ID = "{record}"\n'
        yield "identifier", "yaml", "config/service.yaml", f"service:\n  commit: {digest[:40]}\n"
        yield "word key", "python", "src/app/models.py", 'primary_key = "id"\nsort_key = "created_at"\n'
        yield "word key", "yaml", "config/keyboard.yaml", "keyboard:\n  layout: us\n  key_repeat: 30\n"
        yield "documentation", "markdown", "docs/setup.md", f"Set `{name}` in your environment before you start.\n"
        yield "function call", "python", "src/app/settings.py", f'{name} = vault.read("{lower}")\n'


def refused(text: str, path: str) -> bool:
    try:
        check_credentials(text, source_path=path)
    except AssistantError as exc:
        return exc.code == "sensitive_content"
    return False


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return 0.0, 1.0
    p = successes / total
    centre = p + z * z / (2 * total)
    spread = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
    denominator = 1 + z * z / total
    return (centre - spread) / denominator, (centre + spread) / denominator


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--seed", type=int, default=20261113)
    parser.add_argument("--per-cell", type=int, default=20)
    args = parser.parse_args(argv)
    rng = random.Random(args.seed)
    cells: dict[tuple[str, str, str], list[int]] = collections.defaultdict(lambda: [0, 0])
    true_positive = false_negative = false_positive = true_negative = 0
    for label, source in (("secret", positives(rng, args.per_cell)), ("clean", negatives(rng, args.per_cell))):
        for name, kind, path, text in source:
            hit = refused(text, path)
            cell = cells[(label, name, kind)]
            cell[0] += hit
            cell[1] += 1
            if label == "secret":
                true_positive += hit
                false_negative += not hit
            else:
                false_positive += hit
                true_negative += not hit
    print(f"seed {args.seed}; {args.per_cell} per cell")
    for (label, name, kind), (hits, total) in sorted(cells.items()):
        if (label == "secret" and hits < total) or (label == "clean" and hits):
            print(f"  {label:<6} {name:<22} {kind:<11} refused {hits} of {total}")
    recall = true_positive / max(1, true_positive + false_negative)
    precision = true_positive / max(1, true_positive + false_positive)
    r_low, r_high = wilson(true_positive, true_positive + false_negative)
    p_low, p_high = wilson(true_positive, true_positive + false_positive)
    print(f"secrets {true_positive + false_negative}: refused {true_positive}, missed {false_negative}")
    print(f"clean {false_positive + true_negative}: refused {false_positive}")
    print(f"recall {recall:.3f} (95% {r_low:.3f} to {r_high:.3f}); precision {precision:.3f} "
          f"(95% {p_low:.3f} to {p_high:.3f})")
    met = recall >= RECALL_BAR and precision >= PRECISION_BAR
    print(f"A9 {'met' if met else 'NOT met'}: recall bar {RECALL_BAR}, precision bar {PRECISION_BAR}")
    return 0 if met else 1


if __name__ == "__main__":
    sys.exit(main())
