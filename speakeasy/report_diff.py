"""Compare two Speakeasy run reports produced from the same sample.

The reports are the JSON documents written by ``--output`` /
``Speakeasy.get_json_report``. Events are aligned per run by their
``(module, action)`` identity (for ``api`` events the DLL prefix and the
function name from ``api_name``; for the other event types the subsystem,
such as ``file`` or ``registry``, plus the event name). Repeated occurrences
of the same identity are paired in execution order.

For every paired run the comparison reports three buckets:

- added items, present only in the new report,
- removed items, present only in the old report,
- changed items, present in both but with different payload values.

Changed items include each changed field's before/after value and the
position (``pc``/``tid``/``pid``/``tick``) where each side occurred. The
fully written files of each run (``dropped_files``) are compared the same
way, keyed by their emulated path.

Reports can only be compared when they describe the same sample (matching
``sha256``) and their run records line up and are structurally complete.
Otherwise the result is flagged incomparable with a human-readable reason.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

ABSENT = "<absent>"
NONE = "<none>"

# Subsystem (the "module" of non-API events) for each event type.
_EVENT_SUBSYSTEMS: dict[str, str] = {
    "process_create": "process",
    "mem_alloc": "memory",
    "mem_write": "memory",
    "mem_read": "memory",
    "mem_protect": "memory",
    "mem_free": "memory",
    "thread_create": "thread",
    "thread_inject": "thread",
    "module_load": "module",
    "file_create": "file",
    "file_open": "file",
    "file_read": "file",
    "file_write": "file",
    "reg_open_key": "registry",
    "reg_create_key": "registry",
    "reg_read_value": "registry",
    "reg_write_value": "registry",
    "reg_list_subkeys": "registry",
    "net_dns": "network",
    "net_traffic": "network",
    "net_http": "network",
    "exception": "exception",
}


class IncomparableReports(Exception):
    """Raised while validating reports that cannot be compared."""


@dataclass
class FieldChange:
    """One changed field of a paired item."""

    label: str
    before: str
    after: str


@dataclass
class DiffItem:
    """One added, removed, or changed event or dropped file."""

    kind: str  # one of: added, removed, changed
    section: str  # one of: events, dropped_files
    identity: str
    show_occurrence: bool = False
    occurrence: int = 0
    summary: str = ""
    changes: list[FieldChange] = field(default_factory=list)
    before_loc: str | None = None
    after_loc: str | None = None


@dataclass
class RunDiff:
    """Differences found between one pair of aligned runs (entry points)."""

    label: str
    items: list[DiffItem] = field(default_factory=list)


@dataclass
class ReportComparison:
    """Result of comparing two reports."""

    old_path: str
    new_path: str
    comparable: bool = True
    reason: str = ""
    sample_sha256: str | None = None
    runs: list[RunDiff] = field(default_factory=list)


def load_report_file(path: str) -> dict[str, Any]:
    """Load and parse a saved JSON report file.

    Args:
        path: Path to the report JSON document.

    Returns:
        The parsed report object.

    Raises:
        IncomparableReports: The file is missing, not JSON, or not a report object.
    """

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise IncomparableReports(f"report file not found: {path}")
    except (OSError, json.JSONDecodeError) as err:
        raise IncomparableReports(f"could not read {path} as a report: {err}")
    if not isinstance(data, dict):
        raise IncomparableReports(f"{path} is not a report object (top-level JSON value is not an object)")
    return data


def _hex_addr(value: Any) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        return hex(value)
    if isinstance(value, str):
        try:
            return hex(int(value, 0))
        except ValueError:
            return value.lower()
    raise IncomparableReports(f"run start address is not an address: {value!r}")


def _run_key(ep: dict[str, Any], side: str) -> tuple[str, str]:
    ep_type = ep.get("ep_type")
    start = ep.get("start_addr")
    if not isinstance(ep_type, str) or start is None:
        raise IncomparableReports(f"a run in the {side} record is missing ep_type or start_addr")
    return ep_type, _hex_addr(start)


def _run_label(ep: dict[str, Any]) -> str:
    ep_type, start = _run_key(ep, "report")
    return f"{ep_type} @ {start}"


def _validate_report(report: dict[str, Any], side: str) -> str:
    """Validate the structure required for a comparison and return the sample sha256."""

    sha = report.get("sha256")
    if not isinstance(sha, str) or not sha:
        raise IncomparableReports(
            f"the {side} record is incomplete: it has no sample sha256, so the same sample cannot be confirmed"
        )

    eps = report.get("entry_points")
    if not isinstance(eps, list):
        raise IncomparableReports(f"the {side} record is incomplete: it has no entry_points list")

    for index, ep in enumerate(eps):
        if not isinstance(ep, dict):
            raise IncomparableReports(f"the {side} record is incomplete: run #{index} is not an object")
        _run_label(ep)
        events = ep.get("events")
        if events is not None and not isinstance(events, list):
            raise IncomparableReports(f"the {side} record is incomplete: run {_run_label(ep)} has no event list")
        if isinstance(events, list):
            for ev_index, ev in enumerate(events):
                if not isinstance(ev, dict) or not isinstance(ev.get("event"), str):
                    raise IncomparableReports(
                        f"the {side} record is incomplete: event #{ev_index} in run {_run_label(ep)} has no event type"
                    )
                if not isinstance(ev.get("pos"), dict):
                    raise IncomparableReports(
                        f"the {side} record is incomplete: event {ev['event']} #{ev_index} in run "
                        f"{_run_label(ep)} has no position (pos)"
                    )
        dropped = ep.get("dropped_files")
        if dropped is not None:
            if not isinstance(dropped, list):
                raise IncomparableReports(
                    f"the {side} record is incomplete: run {_run_label(ep)} has no dropped_files list"
                )
            for f_index, f in enumerate(dropped):
                if not isinstance(f, dict) or not isinstance(f.get("path"), str):
                    raise IncomparableReports(
                        f"the {side} record is incomplete: dropped file #{f_index} in run {_run_label(ep)} has no path"
                    )
    return sha


def compare_reports(
    old: dict[str, Any], new: dict[str, Any], old_path: str = "", new_path: str = ""
) -> ReportComparison:
    """Compare two parsed report objects.

    The returned :class:`ReportComparison` is either ``comparable`` with one
    :class:`RunDiff` per aligned run, or flagged incomparable with a reason.
    """

    result = ReportComparison(old_path=old_path, new_path=new_path)

    try:
        old_sha = _validate_report(old, "old")
        new_sha = _validate_report(new, "new")
    except IncomparableReports as err:
        result.comparable = False
        result.reason = str(err)
        return result

    if old_sha != new_sha:
        result.comparable = False
        result.reason = (
            "the records are from different samples "
            f"(old sha256 {old_sha}, new sha256 {new_sha}); only two runs of the same sample can be compared"
        )
        return result
    result.sample_sha256 = old_sha

    # Pair runs by their (ep_type, start_addr) multiset so repeated runs with
    # the same identity are kept in order instead of being collapsed.
    old_pairs = sorted(((_run_key(ep, "old"), ep) for ep in old["entry_points"]), key=lambda pair: pair[0])
    new_pairs = sorted(((_run_key(ep, "new"), ep) for ep in new["entry_points"]), key=lambda pair: pair[0])
    old_counts = Counter(key for key, _ in old_pairs)
    new_counts = Counter(key for key, _ in new_pairs)
    only_old = sorted((old_counts - new_counts).elements())
    only_new = sorted((new_counts - old_counts).elements())
    if only_old or only_new:
        details = []
        if only_old:
            details.append("runs only in the old record: " + ", ".join(f"{t} @ {a}" for t, a in only_old))
        if only_new:
            details.append("runs only in the new record: " + ", ".join(f"{t} @ {a}" for t, a in only_new))
        result.comparable = False
        result.reason = "the run records do not line up (" + "; ".join(details) + ")"
        return result

    for (key, old_ep), (_, new_ep) in zip(old_pairs, new_pairs):
        label = f"{key[0]} @ {key[1]}"
        result.runs.append(RunDiff(label=label, items=_diff_run(old_ep, new_ep)))

    return result


def _render_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if value is None:
        return NONE
    if isinstance(value, str):
        return value
    return str(value)


def _flatten(value: Any, path: str, out: dict[str, str]) -> None:
    """Flatten an event payload into ``field path -> rendered value`` leaves."""

    if value is None:
        return
    if isinstance(value, dict):
        for key in sorted(value, key=str):
            _flatten(value[key], f"{path}.{key}", out)
    elif isinstance(value, list):
        if not value:
            return
        if all(not isinstance(item, (dict, list)) for item in value):
            out[path] = ", ".join(_render_scalar(item) for item in value)
        else:
            for index, item in enumerate(value):
                _flatten(item, f"{path}[{index}]", out)
    else:
        out[path] = _render_scalar(value)


def _api_fields(event: dict[str, Any]) -> dict[str, str]:
    """Comparable field map for an ``api`` event.

    Each argument is rendered as ``parameter=display`` so a value change is
    one field change instead of separate name/value noise; ``ret_val`` is
    always included so a dropped return value is still a change.
    """

    fields: dict[str, str] = {}
    for index, arg in enumerate(event.get("args") or []):
        label = f"args[{index}]"
        if isinstance(arg, dict):
            name = arg.get("name") or f"arg{index}"
            fields[label] = f"{name}={_render_scalar(arg.get('display', ''))}"
        else:
            fields[label] = _render_scalar(arg)
    fields["ret_val"] = _render_scalar(event.get("ret_val"))
    return fields


def _generic_fields(event: dict[str, Any]) -> dict[str, str]:
    """Comparable field map for a non-API event (everything except pos/type)."""

    fields: dict[str, str] = {}
    for key in sorted(event):
        if key in ("event", "pos"):
            continue
        _flatten(event[key], key, fields)
    return fields


def _event_fields(event: dict[str, Any]) -> dict[str, str]:
    if event.get("event") == "api":
        return _api_fields(event)
    return _generic_fields(event)


def _module_action(event: dict[str, Any]) -> tuple[str, str, str, str]:
    """Return ``(key_module, key_action, display_module, display_action)``."""

    event_type = event["event"]
    if event_type == "api":
        name = event.get("api_name") or "api"
        if "." in name:
            module, action = name.rsplit(".", 1)
        else:
            module, action = "api", name
        return module.lower(), action.lower(), module, action
    subsystem = _EVENT_SUBSYSTEMS.get(event_type)
    if subsystem is None:
        subsystem = event_type.split("_", 1)[0] if "_" in event_type else "other"
    return subsystem, event_type, subsystem, event_type


def _render_pos(pos: dict[str, Any]) -> str:
    pc = pos.get("pc")
    if isinstance(pc, bool):
        pc_text = None
    elif isinstance(pc, int):
        pc_text = hex(pc)
    elif isinstance(pc, str):
        try:
            pc_text = hex(int(pc, 0))
        except ValueError:
            pc_text = pc
    else:
        pc_text = None

    parts = [f"pc {pc_text}"] if pc_text else []
    for key in ("tid", "pid", "tick"):
        value = pos.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            parts.append(f"{key} {value}")
    return ", ".join(parts) if parts else "unknown position"


def _event_summary(event: dict[str, Any]) -> str:
    fields = _event_fields(event)
    return "; ".join(f"{label}={value}" for label, value in fields.items())


def _index_events(events: list[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for event in events:
        key_module, key_action, _, _ = _module_action(event)
        grouped.setdefault((key_module, key_action), []).append(event)
    return grouped


def _field_changes(old_fields: dict[str, str], new_fields: dict[str, str]) -> list[FieldChange]:
    changes = []
    for label in sorted(set(old_fields) | set(new_fields)):
        before = old_fields.get(label)
        after = new_fields.get(label)
        if before == after:
            continue
        changes.append(FieldChange(label=label, before=before or ABSENT, after=after or ABSENT))
    return changes


def _diff_events(old_ep: dict[str, Any], new_ep: dict[str, Any]) -> list[DiffItem]:
    old_events = old_ep.get("events") or []
    new_events = new_ep.get("events") or []
    old_groups = _index_events(old_events)
    new_groups = _index_events(new_events)

    items: list[DiffItem] = []
    for key in sorted(set(old_groups) | set(new_groups)):
        old_list = old_groups.get(key, [])
        new_list = new_groups.get(key, [])
        repeated = max(len(old_list), len(new_list)) > 1

        for index in range(max(len(old_list), len(new_list))):
            old_event = old_list[index] if index < len(old_list) else None
            new_event = new_list[index] if index < len(new_list) else None
            representative = old_event or new_event
            assert representative is not None
            _, _, disp_module, disp_action = _module_action(representative)
            identity = f"[{disp_module}] {disp_action}"

            if old_event is not None and new_event is not None:
                changes = _field_changes(_event_fields(old_event), _event_fields(new_event))
                if changes:
                    items.append(
                        DiffItem(
                            kind="changed",
                            section="events",
                            identity=identity,
                            show_occurrence=repeated,
                            occurrence=index + 1,
                            changes=changes,
                            before_loc=_render_pos(old_event["pos"]),
                            after_loc=_render_pos(new_event["pos"]),
                        )
                    )
            elif new_event is not None:
                items.append(
                    DiffItem(
                        kind="added",
                        section="events",
                        identity=identity,
                        show_occurrence=repeated,
                        occurrence=index + 1,
                        summary=_event_summary(new_event),
                        after_loc=_render_pos(new_event["pos"]),
                    )
                )
            else:
                assert old_event is not None
                items.append(
                    DiffItem(
                        kind="removed",
                        section="events",
                        identity=identity,
                        show_occurrence=repeated,
                        occurrence=index + 1,
                        summary=_event_summary(old_event),
                        before_loc=_render_pos(old_event["pos"]),
                    )
                )
    return items


def _dropped_index(ep: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {f["path"]: f for f in ep.get("dropped_files") or []}


def _diff_dropped_files(old_ep: dict[str, Any], new_ep: dict[str, Any]) -> list[DiffItem]:
    old_files = _dropped_index(old_ep)
    new_files = _dropped_index(new_ep)
    items: list[DiffItem] = []

    for path in sorted(set(old_files) | set(new_files)):
        old_file = old_files.get(path)
        new_file = new_files.get(path)
        if old_file is not None and new_file is not None:
            changes = _field_changes(
                {key: _render_scalar(old_file[key]) for key in ("size", "sha256") if key in old_file},
                {key: _render_scalar(new_file[key]) for key in ("size", "sha256") if key in new_file},
            )
            if changes:
                items.append(DiffItem(kind="changed", section="dropped_files", identity=path, changes=changes))
        elif new_file is not None:
            items.append(
                DiffItem(
                    kind="added",
                    section="dropped_files",
                    identity=path,
                    summary=_file_summary(new_file),
                )
            )
        else:
            assert old_file is not None
            items.append(
                DiffItem(
                    kind="removed",
                    section="dropped_files",
                    identity=path,
                    summary=_file_summary(old_file),
                )
            )
    return items


def _file_summary(entry: dict[str, Any]) -> str:
    parts = []
    if "size" in entry:
        parts.append(f"size={_render_scalar(entry['size'])}")
    if "sha256" in entry:
        parts.append(f"sha256={_render_scalar(entry['sha256'])}")
    return ", ".join(parts)


def _diff_run(old_ep: dict[str, Any], new_ep: dict[str, Any]) -> list[DiffItem]:
    return _diff_events(old_ep, new_ep) + _diff_dropped_files(old_ep, new_ep)


def _format_item(item: DiffItem) -> list[str]:
    sign = {"added": "+", "removed": "-", "changed": "~"}[item.kind]
    identity = item.identity + (f" #{item.occurrence}" if item.show_occurrence else "")
    lines = [f"      {sign} {identity}"]

    if item.kind == "changed":
        for change in item.changes:
            lines.append(f"          {change.label}: {change.before} -> {change.after}")
        if item.before_loc:
            lines.append(f"          before: {item.before_loc}")
        if item.after_loc:
            lines.append(f"          after:  {item.after_loc}")
    else:
        if item.summary:
            lines.append(f"          {item.summary}")
        loc = item.after_loc if item.kind == "added" else item.before_loc
        if loc:
            lines.append(f"          at: {loc}")
    return lines


_SECTION_TITLES = (
    ("events", "Events"),
    ("dropped_files", "Dropped files"),
)
_KIND_TITLES = (
    ("added", "Added"),
    ("removed", "Removed"),
    ("changed", "Changed"),
)


def render_comparison(comparison: ReportComparison) -> str:
    """Render a comparison as the human-readable text printed by the CLI."""

    if not comparison.comparable:
        return f"Cannot compare reports: {comparison.reason}"

    lines = [
        f"Report comparison: {comparison.old_path or 'old report'} -> {comparison.new_path or 'new report'}",
        f"Sample sha256: {comparison.sample_sha256}",
        "",
    ]

    totals = {section: {kind: 0 for kind, _ in _KIND_TITLES} for section, _ in _SECTION_TITLES}
    for run in comparison.runs:
        lines.append(f"Run: {run.label}")
        if not run.items:
            lines.append("  No differences.")
            lines.append("")
            continue
        for section, section_title in _SECTION_TITLES:
            section_items = [item for item in run.items if item.section == section]
            lines.append(f"  {section_title}")
            if not section_items:
                lines.append("    No differences.")
                continue
            for kind, kind_title in _KIND_TITLES:
                kind_items = [item for item in section_items if item.kind == kind]
                totals[section][kind] += len(kind_items)
                if not kind_items:
                    continue
                lines.append(f"    {kind_title} ({len(kind_items)}):")
                for item in kind_items:
                    lines.extend(_format_item(item))
        lines.append("")

    summary_parts = []
    for kind, kind_title in _KIND_TITLES:
        event_count = totals["events"][kind]
        file_count = totals["dropped_files"][kind]
        total = event_count + file_count
        if total:
            breakdown = []
            if event_count:
                breakdown.append(f"{event_count} events")
            if file_count:
                breakdown.append(f"{file_count} files")
            summary_parts.append(f"{total} {kind_title.lower()} ({', '.join(breakdown)})")
    if summary_parts:
        lines.append("Summary: " + "; ".join(summary_parts))
    else:
        lines.append("No differences found.")
    return "\n".join(lines)
