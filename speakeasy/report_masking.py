from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from speakeasy.config import MaskingRuleConfig


@dataclass(frozen=True)
class CompiledMaskingRule:
    """A masking rule with its pattern compiled for export-time use."""

    name: str
    pattern: re.Pattern[str]
    replacement: str


def compile_masking_rules(rules: Iterable[MaskingRuleConfig]) -> list[CompiledMaskingRule]:
    """Compile validated config rules into runnable masking rules."""

    return [
        CompiledMaskingRule(name=rule.name, pattern=re.compile(rule.pattern), replacement=rule.replacement)
        for rule in rules
    ]


def _mask_value(
    value: Any,
    rules: list[CompiledMaskingRule],
    counts: dict[str, int],
) -> Any:
    if isinstance(value, str):
        masked = value
        for rule in rules:
            masked, hits = rule.pattern.subn(rule.replacement, masked)
            counts[rule.name] += hits
        return masked
    if isinstance(value, dict):
        # Dict keys are structural field names and must stay intact.
        return {key: _mask_value(item, rules, counts) for key, item in value.items()}
    if isinstance(value, list):
        return [_mask_value(item, rules, counts) for item in value]
    return value


def mask_report_data(
    data: Any,
    rules: Iterable[MaskingRuleConfig],
) -> tuple[Any, dict[str, int]]:
    """Return a masked deep copy of JSON-compatible report data.

    Only string *values* are rewritten. Dict keys, list lengths, and non-string
    values are preserved, so the output keeps the original report structure.
    The input object is never mutated.

    Returns:
        A tuple of the masked copy and a ``rule name -> replacement count`` map.
        Rules with zero matches are included with a count of zero so that a rule
        that silently failed to hit anything stays visible.
    """

    compiled = compile_masking_rules(rules)
    counts: dict[str, int] = {rule.name: 0 for rule in compiled}
    return _mask_value(data, compiled, counts), counts


def mask_report_json(
    report_text: str,
    rules: Iterable[MaskingRuleConfig],
) -> tuple[str, dict[str, int]]:
    """Mask a serialized JSON report and re-serialize it.

    Returns:
        A tuple of the masked JSON text and the per-rule replacement counts.
    """

    masked_data, counts = mask_report_data(json.loads(report_text), rules)
    return json.dumps(masked_data, indent=4, ensure_ascii=False), counts
