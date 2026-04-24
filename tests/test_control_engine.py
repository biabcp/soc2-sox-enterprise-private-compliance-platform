import json
from pathlib import Path

from src.evaluators.control_engine import dummy_condition_eval, evaluate_controls, load_controls


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
