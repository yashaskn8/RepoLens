"""Optional and peer npm dependencies must be represented in structural change evidence."""

import json

from app.analysis.diff_engine import ChangeDiffEngine, _parse_package_json


def test_optional_and_peer_dependencies_have_distinct_scopes():
    parsed = _parse_package_json(json.dumps({
        "dependencies": {"shared": "^1"},
        "optionalDependencies": {"shared": "^2", "optional-only": "^3"},
        "peerDependencies": {"shared": "^4", "peer-only": "^5"},
    }))
    assert parsed == {
        "shared": "^1",
        "shared[optional]": "^2",
        "optional-only[optional]": "^3",
        "shared[peer]": "^4",
        "peer-only[peer]": "^5",
    }


def test_optional_and_peer_reference_credentials_are_not_emitted():
    parsed = _parse_package_json(json.dumps({
        "optionalDependencies": {"private": "https://user:secret@example.com/dep.tgz"},
        "peerDependencies": {"peer": "git+https://user:secret@example.com/peer.git"},
    }))
    assert parsed["private[optional]"].startswith("DIRECT_REFERENCE_SHA256:")
    assert parsed["peer[peer]"].startswith("DIRECT_REFERENCE_SHA256:")
    assert "secret" not in str(parsed)


def test_structural_diff_detects_optional_and_peer_updates(tmp_path):
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / "package.json").write_text(
        '{"optionalDependencies":{"optional-only":"^1"}}', encoding="utf-8"
    )
    (head / "package.json").write_text(
        '{"optionalDependencies":{"optional-only":"^2"},'
        '"peerDependencies":{"peer-only":"^3"}}', encoding="utf-8"
    )
    result = ChangeDiffEngine().compute_structural_diff(
        base_workspace=str(base),
        head_workspace=str(head),
        base_commit_sha="1" * 40,
        head_commit_sha="2" * 40,
        repository_url="https://github.com/example/repo",
    )
    deltas = {(item.package_name, item.change_type) for item in result.dependency_deltas}
    assert ("optional-only[optional]", "UPDATED") in deltas
    assert ("peer-only[peer]", "ADDED") in deltas
