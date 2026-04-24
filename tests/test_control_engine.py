import json
from pathlib import Path

from src.evaluators.control_engine import (
    _coerce_value,
    _latest_json_file,
    dummy_condition_eval,
    evaluate_controls,
    load_controls,
    load_latest_evidence,
)


def test_dummy_condition_eval_numeric_and_boolean():
    assert dummy_condition_eval({"condition": "percentage_mfa_enabled >= 0.98"}, {"percentage_mfa_enabled": 0.99})
    assert dummy_condition_eval({"condition": "mfa == true"}, {"mfa": True})
    assert not dummy_condition_eval({"condition": "mfa == true"}, {"mfa": False})


def test_evaluate_controls_finds_failures(tmp_path: Path, monkeypatch):
    controls_dir = tmp_path / "controls" / "soc2"
    controls_dir.mkdir(parents=True)
    evidence_dir = tmp_path / "evidence" / "processed" / "2026-01-01"
    evidence_dir.mkdir(parents=True)

    (controls_dir / "cc6_1.yml").write_text(
        "\n".join([
            'id: "SOC2-CC6.1"',
            'owner: "Security Engineering"',
            'evaluation:',
            '  rules:',
            '    - id: "mfa_enforced"',
            '      source: "idp.mfa_enforcement"',
            '      condition: "percentage_mfa_enabled >= 0.98"',
            '      severity: "critical"',
        ]),
        encoding="utf-8",
    )
    (evidence_dir / "idp_mfa.json").write_text(
        json.dumps({"percentage_mfa_enabled": 0.9}), encoding="utf-8"
    )

    monkeypatch.chdir(tmp_path)
    results = evaluate_controls()
    assert results[0]["status"] == "fail"
    assert results[0]["failed_rules"] == ["mfa_enforced"]
    assert results[0]["failed_rule_details"][0]["severity"] == "critical"
    assert results[0]["data_error_rules"] == []


def test_load_controls_supports_yaml_extension(tmp_path: Path):
    controls_dir = tmp_path / "controls" / "soc2"
    controls_dir.mkdir(parents=True)
    (controls_dir / "cc6_8.yaml").write_text(
        "\n".join([
            'id: "SOC2-CC6.8"',
            'owner: "Security Engineering"',
            "evaluation:",
            "  rules:",
        ]),
        encoding="utf-8",
    )

    controls = load_controls(str(tmp_path / "controls"))
    assert controls[0]["id"] == "SOC2-CC6.8"


def test_dummy_condition_eval_type_mismatch_returns_false():
    assert not dummy_condition_eval({"condition": "mfa >= 1"}, {"mfa": "enabled"})


def test_coerce_value_supports_common_boolean_representations():
    assert _coerce_value("True") is True
    assert _coerce_value("yes") is True
    assert _coerce_value("No") is False
    assert _coerce_value("0.98") == 0.98
    assert _coerce_value("100") == 100


def test_dummy_condition_eval_supports_contains_in_exists():
    data = {"scopes": ["repo", "admin:org"], "actor": "security-bot", "mfa": True}
    assert dummy_condition_eval({"condition": "scopes contains 'repo'"}, data)
    assert dummy_condition_eval({"condition": "actor in ['security-bot', 'renovate[bot]']"}, data)
    assert dummy_condition_eval({"condition": "mfa exists"}, data)


def test_coerce_value_list_parsing_preserves_quoted_commas():
    value = _coerce_value('["CN=User,OU=Dev", "admin"]')
    assert value == ["CN=User,OU=Dev", "admin"]


def test_dummy_condition_eval_unsupported_operator_raises():
    try:
        dummy_condition_eval({"condition": "mfa ~~ true"}, {"mfa": True})
    except ValueError as exc:
        assert "Unsupported condition operator" in str(exc)
    else:
        raise AssertionError("Expected ValueError for unsupported operator")


def test_latest_json_file_prefers_embedded_date_over_mtime(tmp_path: Path):
    old_named_newly_touched = tmp_path / "idp_mfa_2026-01-01.json"
    new_named_older_mtime = tmp_path / "idp_mfa_2026-03-01.json"
    old_named_newly_touched.write_text("{}", encoding="utf-8")
    new_named_older_mtime.write_text("{}", encoding="utf-8")

    old_named_newly_touched.touch()
    assert _latest_json_file(str(tmp_path / "idp_mfa*.json")) == new_named_older_mtime


def test_load_latest_evidence_includes_missing_sources_as_none(tmp_path: Path):
    processed = tmp_path / "evidence" / "processed"
    processed.mkdir(parents=True)
    (processed / "idp_mfa_2026-01-01.json").write_text(
        json.dumps({"percentage_mfa_enabled": 1.0}),
        encoding="utf-8",
    )

    loaded = load_latest_evidence(str(processed))
    assert loaded["idp.mfa_enforcement"]["percentage_mfa_enabled"] == 1.0
    assert loaded["github.branch_protection"] is None


def test_evaluate_controls_marks_missing_evidence_as_data_error(tmp_path: Path, monkeypatch):
    controls_dir = tmp_path / "controls" / "soc2"
    controls_dir.mkdir(parents=True)
    (controls_dir / "cc6_1.yml").write_text(
        "\n".join([
            'id: "SOC2-CC6.1"',
            'owner: "Security Engineering"',
            'evaluation:',
            '  rules:',
            '    - id: "mfa_enforced"',
            '      source: "idp.mfa_enforcement"',
            '      condition: "percentage_mfa_enabled >= 0.98"',
            '      severity: "critical"',
        ]),
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)
    results = evaluate_controls()
    assert results[0]["status"] == "data_error"
    assert results[0]["data_error_rules"] == ["mfa_enforced"]


def test_load_controls_supports_yaml_flow_style(tmp_path: Path):
    controls_dir = tmp_path / "controls" / "soc2"
    controls_dir.mkdir(parents=True)
    (controls_dir / "cc6_9.yaml").write_text(
        "\n".join([
            'id: "SOC2-CC6.9"',
            'owner: "Security Engineering"',
            "evaluation:",
            '  rules: [{id: "rule1", source: "idp.mfa_enforcement", condition: "mfa == true", severity: "high"}]',
        ]),
        encoding="utf-8",
    )

    controls = load_controls(str(tmp_path / "controls"))
    assert controls[0]["evaluation"]["rules"][0]["id"] == "rule1"
