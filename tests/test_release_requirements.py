"""Release asset boundaries are tested offline; no publishing or real index calls."""
import hashlib
from pathlib import Path
import subprocess
import zipfile

import pytest
import yaml

from scripts import release_requirements as locks

HASH = "a" * 64


def wheel(tmp_path, version="9.8.7", metadata_version=None):
    path = tmp_path / f"finledgerpoli-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"finledgerpoli-{version}.dist-info/METADATA",
                         f"Metadata-Version: 2.4\nName: finledgerpoli\nVersion: {metadata_version or version}\n"
                         "Requires-Python: >=3.11\nRequires-Dist: synthetic-dependency==1.2.3\n")
    return path


@pytest.mark.parametrize("text", [
    "synthetic-dependency==1.2.3", "synthetic-dependency>=1.2 --hash=sha256:" + HASH,
    "synthetic-dependency==1.* --hash=sha256:" + HASH,
    "synthetic-dependency @ https://example.invalid/package.whl --hash=sha256:" + HASH,
    "--index-url https://example.invalid/", "finledgerpoli==9.8.7 --hash=sha256:" + HASH,
    "synthetic-dependency==1.2.3 --hash=md5:" + HASH,
])
def test_unportable_or_unhashed_dependency_lock_is_refused(text):
    with pytest.raises(ValueError):
        locks.validate_dependencies(text)


def test_marked_pins_with_multiple_hashes_are_preserved():
    locks.validate_dependencies('synthetic-dependency==1.2.3 ; python_version < "3.12" \\\n'
                                '    --hash=sha256:' + HASH + ' \\\n    --hash=sha256:' + 'b' * 64 + '\n')


def test_wheel_identity_rejects_different_metadata_or_prerelease(tmp_path):
    with pytest.raises(ValueError, match="disagree"):
        locks.wheel_identity(wheel(tmp_path, metadata_version="9.8.6"))
    with pytest.raises(ValueError, match="stable"):
        locks.wheel_identity(wheel(tmp_path, version="9.8.7rc1"))


def test_asset_binds_exact_wheel_and_is_emitted_only_after_verification(tmp_path, monkeypatch):
    built = wheel(tmp_path)
    verified = []
    def compile_lock(*argv):
        source = Path(argv[5]).read_text(encoding="utf-8")
        assert built.as_uri() in source
        assert '--universal' in argv and '--generate-hashes' in argv
        Path(argv[argv.index('--output-file') + 1]).write_text('synthetic-dependency==1.2.3 --hash=sha256:' + HASH + '\n', encoding='utf-8')
    def verify(actual_wheel, asset, dependencies, root):
        assert actual_wheel == built
        text = asset.read_text(encoding="utf-8")
        assert 'finledgerpoli==9.8.7 --hash=sha256:' + hashlib.sha256(built.read_bytes()).hexdigest() in text
        assert 'synthetic-dependency==1.2.3' in text
        assert str(tmp_path) not in text and 'file:' not in text
        assert not (tmp_path/'output'/asset.name).exists()
        verified.append(text)
    monkeypatch.setattr(locks, 'run', compile_lock)
    monkeypatch.setattr(locks, 'verify_install', verify)
    asset = locks.generate(built, tmp_path/'output')
    assert asset.name == 'finledgerpoli-9.8.7-requirements.txt' and asset.read_text(encoding="utf-8") == verified[0]
    with pytest.raises(ValueError, match='replace'):
        locks.generate(built, tmp_path/'output')


def test_failed_install_leaves_no_publishable_asset(tmp_path, monkeypatch):
    def compile_lock(*argv):
        Path(argv[argv.index('--output-file') + 1]).write_text('synthetic-dependency==1.2.3 --hash=sha256:' + HASH + '\n', encoding='utf-8')
    def refuse(*args):
        raise subprocess.CalledProcessError(1, 'synthetic pip hash mismatch')
    monkeypatch.setattr(locks, 'run', compile_lock)
    monkeypatch.setattr(locks, 'verify_install', refuse)
    with pytest.raises(subprocess.CalledProcessError):
        locks.generate(wheel(tmp_path), tmp_path/'output')
    assert not list((tmp_path/'output').iterdir())


def test_release_requirements_travel_to_approval_and_github_but_not_pypi():
    root = Path(__file__).resolve().parent.parent
    workflow = yaml.safe_load((root/'.github/workflows/release.yml').read_text(encoding="utf-8"))
    build = workflow['jobs']['build']['steps']
    generation = next(i for i,s in enumerate(build) if 'scripts/release_requirements.py' in s.get('run',''))
    upload = next(i for i,s in enumerate(build) if s.get('uses','').startswith('actions/upload-artifact@'))
    assert generation < upload and 'release-assets/*-requirements.txt' in build[upload]['with']['path']
    publish = workflow['jobs']['publish']
    assert publish['environment']['name'] == 'pypi'
    assert 'release/release-assets/*-requirements.txt' in publish['steps'][-1]['run']
    publisher = next(s for s in publish['steps'] if s.get('uses','').startswith('pypa/gh-action-pypi-publish@'))
    assert publisher['with']['packages-dir'] == 'release/dist/'
    assert any('release/release-assets/*-requirements.txt' in s.get('with',{}).get('subject-path','')
               for s in publish['steps'])
