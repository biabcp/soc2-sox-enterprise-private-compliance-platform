import json
import sys
from pathlib import Path


def _read_controls(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)

    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("controls"), list):
        return payload["controls"]
    raise ValueError("Results file must contain a list or a {'controls': [...]} object")


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python scripts/fail_on_critical.py <compliance_results.json>")
        return 2

    results_path = Path(sys.argv[1])
    controls = _read_controls(results_path)

    critical_failures = []
    for control in controls:
        if control.get("status") != "fail":
            continue
        for failed_rule in control.get("failed_rule_details", []):
            if failed_rule.get("severity") == "critical":
                critical_failures.append((control.get("id", "unknown_control"), failed_rule.get("id", "unknown_rule")))

    if critical_failures:
        print("Critical compliance failures detected:")
        for control_id, rule_id in critical_failures:
            print(f"- {control_id}: {rule_id}")
        return 1

    print("No critical compliance failures found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
