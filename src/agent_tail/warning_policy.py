from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib


WARNING_POLICY_VERSION = 1
WARNING_CODES = frozenset({"LOOP", "RETRY"})


class WarningPolicyError(ValueError):
    """Raised when a warning policy is not valid and cannot be applied safely."""


@dataclass(frozen=True)
class ToolWarningRule:
    name: str
    loop_threshold: int | None = None
    retry_threshold: int | None = None
    suppress: frozenset[str] = frozenset()


@dataclass(frozen=True)
class WarningPolicy:
    path: str
    version: int
    rules: tuple[ToolWarningRule, ...]

    def rule_for(self, operation_name: object) -> ToolWarningRule | None:
        if not isinstance(operation_name, str) or not operation_name.strip():
            return None
        return next((rule for rule in self.rules if rule.name == operation_name), None)

    def projection(
        self,
        *,
        default_loop_threshold: int,
        default_retry_threshold: int,
        suppressed: tuple[object, ...] = (),
    ) -> dict[str, object]:
        counts = {code: 0 for code in sorted(WARNING_CODES)}
        for warning in suppressed:
            code = getattr(warning, "code", None)
            if code in counts:
                counts[code] += 1
        return {
            "path": self.path,
            "version": self.version,
            "restart_required": True,
            "rules": [
                {
                    "operation_name": rule.name,
                    "loop_threshold": rule.loop_threshold or default_loop_threshold,
                    "retry_threshold": rule.retry_threshold or default_retry_threshold,
                    "suppress": sorted(rule.suppress),
                }
                for rule in self.rules
            ],
            "suppressed_counts": {
                "total": sum(counts.values()),
                "by_code": counts,
            },
        }


def load_warning_policy(path: str | Path) -> WarningPolicy:
    supplied_path = str(path)
    try:
        with open(path, "rb") as source:
            document = tomllib.load(source)
    except tomllib.TOMLDecodeError as error:
        raise WarningPolicyError("policy is not valid TOML") from error
    except (OSError, UnicodeError) as error:
        reason = getattr(error, "strerror", None) or "could not read policy"
        raise WarningPolicyError(str(reason)) from error

    _keys(document, {"version", "tools"}, "policy")
    version = document.get("version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise WarningPolicyError("version must be the integer 1")
    if version != WARNING_POLICY_VERSION:
        raise WarningPolicyError(f"unsupported policy version: {version}")

    tools = document.get("tools", [])
    if not isinstance(tools, list):
        raise WarningPolicyError("tools must be an array of tables")
    rules = []
    names = set()
    for position, value in enumerate(tools, 1):
        location = f"tools[{position}]"
        if not isinstance(value, dict):
            raise WarningPolicyError(f"{location} must be a table")
        _keys(
            value,
            {"name", "loop_threshold", "retry_threshold", "suppress"},
            location,
        )
        name = value.get("name")
        if not isinstance(name, str):
            raise WarningPolicyError(f"{location}.name must be a string")
        if not name.strip():
            raise WarningPolicyError(f"{location}.name must not be blank")
        if name in names:
            raise WarningPolicyError(f"duplicate tool rule: {name}")
        names.add(name)

        loop_threshold = _threshold(value, "loop_threshold", location)
        retry_threshold = _threshold(value, "retry_threshold", location, minimum=3)
        suppress = value.get("suppress", [])
        if not isinstance(suppress, list):
            raise WarningPolicyError(f"{location}.suppress must be an array")
        if any(not isinstance(code, str) for code in suppress):
            raise WarningPolicyError(f"{location}.suppress values must be strings")
        unknown_codes = sorted(set(suppress) - WARNING_CODES)
        if unknown_codes:
            raise WarningPolicyError(
                f"{location}.suppress has unsupported warning code: {unknown_codes[0]}"
            )
        if len(suppress) != len(set(suppress)):
            raise WarningPolicyError(f"{location}.suppress contains a duplicate code")
        if not any((loop_threshold, retry_threshold, suppress)):
            raise WarningPolicyError(f"{location} must configure at least one behavior")
        rules.append(ToolWarningRule(
            name,
            loop_threshold=loop_threshold,
            retry_threshold=retry_threshold,
            suppress=frozenset(suppress),
        ))
    return WarningPolicy(supplied_path, version, tuple(rules))


def _keys(value: dict[str, object], allowed: set[str], location: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise WarningPolicyError(f"unknown key in {location}: {unknown[0]}")


def _threshold(
    value: dict[str, object],
    name: str,
    location: str,
    minimum: int = 2,
) -> int | None:
    if name not in value:
        return None
    threshold = value[name]
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        raise WarningPolicyError(f"{location}.{name} must be an integer")
    if threshold < minimum:
        raise WarningPolicyError(f"{location}.{name} must be at least {minimum}")
    return threshold
