"""The security design guide names the forms that hold or read an environment variable's name. Each must behave as
it says: a constant named like a credential is refused, the documented alternatives pass. Synthetic text only."""

import pytest

from finassist.errors import AssistantError
from finassist.security import check_text

PATH = "src/app/settings.py"


def test_a_credential_named_constant_holding_a_name_is_refused():
    with pytest.raises(AssistantError) as refused:
        check_text("API_" + 'KEY = "GEMINI_API_KEY"\n', source_path=PATH)  # built here, never stored whole
    assert refused.value.local_details["rule"] == "credential_label"


@pytest.mark.parametrize("source", [
    'API_KEY_ENV = "GEMINI_API_KEY"\n',
    'API_KEY_NAME = "GEMINI_API_KEY"\n',
    'import os\napi_key = os.environ["GEMINI_API_KEY"]\n',
    'import os\napi_key = os.getenv("GEMINI_API_KEY")\n',
])
def test_the_documented_alternatives_pass(source):
    check_text(source, source_path=PATH)


def test_the_guide_states_these_forms():
    from pathlib import Path

    guide = (Path(__file__).resolve().parents[1] / "docs" / "security-design.md").read_text(encoding="utf-8")
    for form in ('API_KEY_ENV = "GEMINI_API_KEY"', "API_KEY_NAME",
                 'os.environ["GEMINI_API_KEY"]', 'os.getenv("GEMINI_API_KEY")'):
        assert form in guide, form
