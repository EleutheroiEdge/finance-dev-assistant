"""Record actual offline demo output as a portable asciinema v2 recording."""
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
result = subprocess.run([sys.executable, "-m", "finassist", "demo"], check=True, capture_output=True, text=True, encoding="utf-8", shell=False)
output = json.dumps(json.loads(result.stdout), indent=2, ensure_ascii=False)
header = {"version": 2, "width": 100, "height": 30, "title": "finassist demo — synthetic, offline", "env": {"TERM": "xterm-256color"}}
rows = [json.dumps(header), json.dumps([0.0, "o", "$ finassist demo | python -m json.tool\r\n"])]
rows.extend(json.dumps([round(0.2 + index * 0.07, 2), "o", line + "\r\n"]) for index, line in enumerate(output.splitlines()))
path = root / "docs/images/demo.cast.txt"
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")
