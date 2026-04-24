import glob
import csv
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RuleFailure:
    id: str
    severity: str


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _parse_simple_control_yaml(text: str) -> dict[str, Any]:
    """Minimal parser for the control schema used in this repository examples."""
    control: dict[str, Any] = {"evaluation": {"rules": []}}
    current_rule: dict[str, Any] | None = None
    in_rules = False

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue

        stripped = line.strip()
        if stripped.startswith("id:") and not line.startswith("      "):
            control["id"] = _strip_quotes(stripped.split(":", 1)[1])
            continue
        if stripped.startswith("owner:"):
            control["owner"] = _strip_quotes(stripped.split(":", 1)[1])
            continue
        if stripped.startswith("rules:"):
            in_rules = True
            inline = stripped.split(":", 1)[1].strip()
            if inline.startswith("[") and inline.endswith("]"):
                normalized = re.sub(r'([{\s,])([A-Za-z_][A-Za-z0-9_-]*)\s*:', r'\1"\2":', inline)
                try:
                    parsed = json.loads(normalized)
                except json.JSONDecodeError:
                    parsed = []
                if isinstance(parsed, list):
                    control["evaluation"]["rules"].extend([rule for rule in parsed if isinstance(rule, dict)])
            continue

        if in_rules and stripped.startswith("- "):
            current_rule = {}
            control["evaluation"]["rules"].append(current_rule)
            stripped = stripped[2:].strip()
            if ":" in stripped:
                k, v = stripped.split(":", 1)
                current_rule[k.strip()] = _strip_quotes(v)
            continue

        if in_rules and current_rule is not None and ":" in stripped:
            k, v = stripped.split(":", 1)
            current_rule[k.strip()] = _strip_quotes(v)

    if "id" not in control:
        return {}
    return control


def load_controls(base_dir: str = "controls") -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []
    patterns = (f"{base_dir}/**/*.yml", f"{base_dir}/**/*.yaml")
    paths = [path for pattern in patterns for path in glob.glob(pattern, recursive=True)]
    for path in sorted(set(paths)):
        with open(path, "r", encoding="utf-8") as f:
            doc = _parse_simple_control_yaml(f.read())
        if doc:
            controls.append(doc)
        else:
            logger.warning("Skipping control file with missing/invalid 'id': %s", path)
    return controls


_DATE_PATTERN = re.compile(r"(\d{4}-\d{2}-\d{2})(?:[T_](\d{2})[-:]?(\d{2})[-:]?(\d{2}))?")


def _extract_datetime_from_filename(path: Path) -> datetime | None:
    match = _DATE_PATTERN.search(path.name)
    if not match:
        return None
    day = match.group(1)
    hh = match.group(2) or "00"
    mm = match.group(3) or "00"
    ss = match.group(4) or "00"
    try:
        return datetime.fromisoformat(f"{day}T{hh}:{mm}:{ss}")
    except ValueError:
        return None


def _latest_json_file(pattern: str) -> Path | None:
    matches = [Path(p) for p in glob.glob(pattern, recursive=True)]
    if not matches:
        return None

    with_embedded_dt = [(path, _extract_datetime_from_filename(path)) for path in matches]
    dated = [(path, dt) for path, dt in with_embedded_dt if dt is not None]
    if dated:
        return max(dated, key=lambda item: item[1])[0]
    return max(matches, key=lambda p: p.stat().st_mtime)


def load_latest_evidence(base_dir: str = "evidence/processed") -> dict[str, Any]:
    mapping = {
        "github.branch_protection": "**/github_branch_protection*.json",
        "idp.mfa_enforcement": "**/idp_mfa*.json",
    }

    loaded: dict[str, Any] = {}
    for source, suffix in mapping.items():
        latest = _latest_json_file(os.path.join(base_dir, suffix))
        if not latest:
            logger.warning("No evidence file found for source '%s' in %s", source, base_dir)
            loaded[source] = None
            continue
        with open(latest, "r", encoding="utf-8") as f:
            loaded[source] = json.load(f)

    return loaded


def _coerce_value(raw: str) -> Any:
    value = raw.strip()
    lowered = value.lower()
    if lowered in {"true", "false", "yes", "no", "on", "off"}:
        return lowered in {"true", "yes", "on"}
    if lowered in {"null", "none"}:
        return None
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        row = next(csv.reader([inner], skipinitialspace=True), [])
        return [_coerce_value(item.strip()) for item in row]
    if value.startswith(('"', "'")) and value.endswith(('"', "'")):
        return value[1:-1]
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _resolve_current_value(rule: dict[str, Any], source: Any, left: str) -> Any:
    current = source.get(left) if isinstance(source, dict) else None
    if current is None and left == "all_repos_enforced" and rule.get("source") == "github.branch_protection" and isinstance(source, list):
        return all(
            item.get("required_status_checks")
            and (item.get("required_approving_review_count", 0) or 0) >= 1
            for item in source
        )
    return current


def dummy_condition_eval(rule: dict[str, Any], source: Any) -> bool:
    if source is None:
        return False

    condition = (rule.get("condition") or "").strip()
    if not condition:
        return True

    if condition.endswith(" exists"):
        left = condition[:-7].strip()
        return _resolve_current_value(rule, source, left) is not None

    if " contains " in condition:
        left, right = [part.strip() for part in condition.split(" contains ", 1)]
        current = _resolve_current_value(rule, source, left)
        if current is None:
            return False
        target = _coerce_value(right)
        try:
            return target in current
        except TypeError:
            return False

    if " in " in condition:
        left, right = [part.strip() for part in condition.split(" in ", 1)]
        current = _resolve_current_value(rule, source, left)
        if current is None:
            return False
        target = _coerce_value(right)
        try:
            return current in target
        except TypeError:
            return False

    ops = [">=", "<=", "==", "!=", ">", "<"]
    op = next((operator for operator in ops if operator in condition), None)
    if op is None:
        raise ValueError(f"Unsupported condition operator in expression: {condition}")

    left, right = [part.strip() for part in condition.split(op, 1)]
    target = _coerce_value(right)

    current = _resolve_current_value(rule, source, left)

    if current is None:
        return False

    try:
        if op == "==":
            return current == target
        if op == "!=":
            return current != target
        if op == ">=":
            return current >= target
        if op == "<=":
            return current <= target
        if op == ">":
            return current > target
        if op == "<":
            return current < target
    except TypeError:
        return False
    return False


def evaluate_controls() -> list[dict[str, Any]]:
    controls = load_controls()
    evidence = load_latest_evidence()
    results: list[dict[str, Any]] = []

    for c in controls:
        failures: list[RuleFailure] = []
        data_errors: list[str] = []
        for rule in c.get("evaluation", {}).get("rules", []):
            source = evidence.get(rule.get("source", ""))
            if source is None:
                data_errors.append(rule.get("id", "unknown_rule"))
                failures.append(
                    RuleFailure(
                        id=rule.get("id", "unknown_rule"),
                        severity=rule.get("severity", "unknown"),
                    )
                )
                continue
            try:
                passed = dummy_condition_eval(rule, source)
            except ValueError as exc:
                logger.error(
                    "Invalid condition for control=%s rule=%s: %s",
                    c.get("id", "unknown_control"),
                    rule.get("id", "unknown_rule"),
                    exc,
                )
                passed = False
            if not passed:
                failures.append(
                    RuleFailure(
                        id=rule.get("id", "unknown_rule"),
                        severity=rule.get("severity", "unknown"),
                    )
                )

        status = "pass"
        if failures:
            status = "data_error" if len(data_errors) == len(failures) else "fail"

        results.append(
            {
                "id": c.get("id", "unknown_control"),
                "status": status,
                "failed_rules": [failure.id for failure in failures],
                "failed_rule_details": [failure.__dict__ for failure in failures],
                "data_error_rules": data_errors,
                "owner": c.get("owner"),
            }
        )
    return results


if __name__ == "__main__":
    print(json.dumps(evaluate_controls(), indent=2))
