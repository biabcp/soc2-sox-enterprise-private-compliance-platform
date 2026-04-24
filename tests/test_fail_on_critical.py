import json
import subprocess
import sys
from pathlib import Path


def _run_fail_on_critical(results_file: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "scripts/fail_on_critical.py", str(results_file)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_fail_on_critical_blocks_unknown_severity(tmp_path: Path):
    results = [
        {
            "id": "SOC2-CC6.1",
            "status": "fail",
            "failed_rule_details": [{"id": "mfa_enforced", "severity": "unknown"}],
        }
    ]
    report = tmp_path / "results.json"
    report.write_text(json.dumps(results), encoding="utf-8")

    run = _run_fail_on_critical(report)
    assert run.returncode == 1
    assert "Critical compliance failures detected" in run.stdout


def test_fail_on_critical_passes_without_blocking_severity(tmp_path: Path):
    results = [
        {
            "id": "SOC2-CC6.1",
            "status": "fail",
            "failed_rule_details": [{"id": "mfa_enforced", "severity": "low"}],
        }
    ]
    report = tmp_path / "results.json"
    report.write_text(json.dumps(results), encoding="utf-8")

    run = _run_fail_on_critical(report)
    assert run.returncode == 0
    assert "No critical compliance failures found." in run.stdout
