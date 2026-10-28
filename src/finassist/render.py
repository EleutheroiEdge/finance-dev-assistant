"""Escaped, static HTML reports. Untrusted model prose never becomes markup."""

from html import escape
import json


def report_html(report: dict) -> str:
    text = json.dumps(report, indent=2, ensure_ascii=False)
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<title>Developer review evidence</title><style>"
        "body{font:16px/1.5 system-ui;max-width:1000px;margin:3rem auto;padding:1rem;color:#18283a}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f8;padding:1rem}"
        "</style><h1>Developer review evidence</h1><p>Advisory result. "
        "Source references and executed checks are distinct. Human project gates remain.</p><pre>"
        + escape(text)
        + "</pre></html>"
    )
