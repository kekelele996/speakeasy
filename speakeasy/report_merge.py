# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

"""Merge several Speakeasy run reports into one combined report.

Colleagues often run the same input file separately, leaving one report JSON per
run in different directories. This module combines such reports into a single
:class:`~speakeasy.report.Report` without losing information:

* sources are ordered by emulation start timestamp;
* identical actions are kept once, annotated with every contributing source;
* the same logical action observed with different parameters/results is kept
  once per variant, with differing fields called out explicitly;
* input file metadata, failure reasons, and the deduplicated ``data`` payload
  store (and every ``*_ref`` into it) are preserved.

The merged document uses the same :class:`Report` schema, so existing report
viewing workflows keep working: merge-only fields are optional and absent from
ordinary single-run reports.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from speakeasy.profiler_events import (
    AnyEvent,
    ApiEvent,
    EventVariantDiff,
    ExceptionEvent,
    FileCreateEvent,
    FileOpenEvent,
    FileReadEvent,
    FileWriteEvent,
    MemAllocEvent,
    MemFreeEvent,
    MemProtectEvent,
    MemReadEvent,
    MemWriteEvent,
    MergeSourceRef,
    ModuleLoadEvent,
    NetDnsEvent,
    NetHttpEvent,
    NetTrafficEvent,
    ProcessCreateEvent,
    RegCreateKeyEvent,
    RegListSubkeysEvent,
    RegOpenKeyEvent,
    RegReadValueEvent,
    RegWriteValueEvent,
    ThreadCreateEvent,
    ThreadInjectEvent,
)
from speakeasy.report import (
    DataArtifact,
    DroppedFile,
    DynamicCodeSegment,
    EntryPoint,
    EntryPointOutcome,
    ErrorInfo,
    LoadedModule,
    MemoryLayout,
    MemoryRegion,
    MergedSource,
    Report,
    StringCollection,
    StringsReport,
    SymAccessReport,
)

# Event fields that describe when/where an action happened rather than what the
# action was. Ticks/PIDs/PCs legitimately differ between independent runs of the
# same file, so they never participate in identity or parameter comparisons.
EVENT_POSITION_FIELDS = frozenset({"pos", "sources", "variant_group", "variant_diff"})

_MAX_DIFF_VALUE_LEN = 200


class ReportMergeError(Exception):
    """Raised when report inputs cannot be found, parsed, or merged."""


@dataclass
class _Source:
    report: Report
    label: str
    path: str | None


@dataclass
class _VariantSlot:
    """One aligned logical action (same key, same per-source occurrence index)."""

    group_id: str
    variants: list[AnyEvent] = field(default_factory=list)
    fingerprints: list[str] = field(default_factory=list)
    refs: dict[str, dict[str, int]] = field(default_factory=dict)


def _canonical(obj: Any, *, exclude: frozenset[str] | None = None) -> str:
    """Render a pydantic model as stable JSON for content comparisons."""

    dumped = obj.model_dump(mode="json", exclude_none=True, exclude=set(exclude) if exclude else None)
    return json.dumps(dumped, sort_keys=True, ensure_ascii=False, default=str)


def _render_leaf(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        rendered = value
    else:
        rendered = json.dumps(value, ensure_ascii=True, default=str)
    if len(rendered) > _MAX_DIFF_VALUE_LEN:
        rendered = rendered[:_MAX_DIFF_VALUE_LEN] + "..."
    return rendered


def _flatten(value: Any, prefix: str = "") -> dict[str, str | None]:
    """Flatten a JSON-like value into ``dotted.path[0]`` leaf entries."""

    out: dict[str, str | None] = {}
    if isinstance(value, dict):
        for key in sorted(value):
            child = f"{prefix}.{key}" if prefix else str(key)
            out.update(_flatten(value[key], child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            out.update(_flatten(item, f"{prefix}[{index}]"))
    else:
        out[prefix] = _render_leaf(value)
    return out


def _action_key(event: AnyEvent) -> tuple[Any, ...]:
    """Identify the logical operation an event represents.

    Events sharing a key are the "same action"; differing payload fields make
    them parameter variants instead of duplicates.
    """

    etype = event.event
    if isinstance(event, ApiEvent):
        return (etype, event.api_name)
    if isinstance(event, (FileCreateEvent, FileOpenEvent, FileReadEvent, FileWriteEvent)):
        return (etype, event.path)
    if isinstance(event, (RegOpenKeyEvent, RegCreateKeyEvent, RegListSubkeysEvent)):
        return (etype, event.path)
    if isinstance(event, (RegReadValueEvent, RegWriteValueEvent)):
        return (etype, event.path, event.value_name or "")
    if isinstance(event, NetDnsEvent):
        return (etype, event.query)
    if isinstance(event, NetTrafficEvent):
        return (etype, event.server, event.port, event.proto, event.type or "")
    if isinstance(event, NetHttpEvent):
        return (etype, event.server, event.port, event.proto)
    if isinstance(event, (MemAllocEvent, MemWriteEvent, MemReadEvent, MemProtectEvent, MemFreeEvent)):
        return (etype, event.path, event.base)
    if isinstance(event, ModuleLoadEvent):
        return (etype, event.name)
    if isinstance(event, (ThreadCreateEvent, ThreadInjectEvent)):
        return (etype, event.path, event.start_addr)
    if isinstance(event, ProcessCreateEvent):
        return (etype, event.path)
    if isinstance(event, ExceptionEvent):
        return (etype, event.instr, event.exception_code)
    # Unknown event shape: never over-merge; use the full content as the key.
    return (etype, _canonical(event, exclude=EVENT_POSITION_FIELDS))


def _group_id_for(key: tuple[Any, ...], index: int) -> str:
    descriptor = ":".join(str(part) for part in key)
    return f"{descriptor}#{index}"


def _event_variant_diffs(variants: Sequence[AnyEvent]) -> list[EventVariantDiff]:
    """Find flattened fields that distinguish parameter variants of one action."""

    flat_variants = [
        _flatten(variant.model_dump(mode="json", exclude_none=True, exclude=set(EVENT_POSITION_FIELDS)))
        for variant in variants
    ]
    diffs: list[EventVariantDiff] = []
    for path in sorted(set().union(*(set(flat) for flat in flat_variants))):
        values = [flat.get(path) for flat in flat_variants]
        if len(set(values)) > 1:
            diffs.append(EventVariantDiff(field=path, values=values))
    return diffs


def _merge_entry_events(members: Sequence[tuple[str, EntryPoint]]) -> list[AnyEvent] | None:
    """Merge event streams of the same entry point across source reports."""

    slots: dict[tuple[Any, ...], _VariantSlot] = {}
    out_events: list[AnyEvent] = []

    for source_label, ep in members:
        occurrence_counts: dict[tuple[Any, ...], int] = {}
        for original in ep.events or []:
            key = _action_key(original)
            occurrence_counts[key] = occurrence_counts.get(key, 0) + 1
            occurrence_index = occurrence_counts[key]
            slot_key = (key, occurrence_index)
            fingerprint = _canonical(original, exclude=EVENT_POSITION_FIELDS)

            slot = slots.get(slot_key)
            if slot is None:
                slot = _VariantSlot(group_id=_group_id_for(key, occurrence_index))
                slots[slot_key] = slot

            try:
                variant_index = slot.fingerprints.index(fingerprint)
            except ValueError:
                variant_index = len(slot.variants)
                variant = original.model_copy(deep=True)
                slot.variants.append(variant)
                slot.fingerprints.append(fingerprint)
                slot.refs[fingerprint] = {}
                out_events.append(variant)

            variant_refs = slot.refs[slot.fingerprints[variant_index]]
            variant_refs[source_label] = variant_refs.get(source_label, 0) + 1

    for slot in slots.values():
        is_variant_group = len(slot.variants) > 1
        for index, variant in enumerate(slot.variants):
            fingerprint = slot.fingerprints[index]
            # Rebuild refs in global source order so output is deterministic.
            variant.sources = [
                MergeSourceRef(source=label, count=count)
                for label, count in sorted(slot.refs[fingerprint].items())
            ]
            if is_variant_group:
                variant.variant_group = slot.group_id
                variant.variant_diff = _event_variant_diffs(slot.variants) if index == 0 else None

    return out_events or None


def _merge_sym_accesses(members: Sequence[tuple[str, EntryPoint]]) -> list[SymAccessReport] | None:
    counters: dict[str, list[int]] = {}
    order: list[str] = []
    for _, ep in members:
        for access in ep.sym_accesses or []:
            if access.symbol not in counters:
                counters[access.symbol] = [0, 0, 0]
                order.append(access.symbol)
            counters[access.symbol][0] += access.reads
            counters[access.symbol][1] += access.writes
            counters[access.symbol][2] += access.execs
    if not counters:
        return None
    return [
        SymAccessReport(symbol=symbol, reads=counters[symbol][0], writes=counters[symbol][1], execs=counters[symbol][2])
        for symbol in order
    ]


def _dedupe_models(items: Iterable[Any]) -> list[Any]:
    seen: set[str] = set()
    out: list[Any] = []
    for item in items:
        fingerprint = _canonical(item)
        if fingerprint not in seen:
            seen.add(fingerprint)
            out.append(item.model_copy(deep=True))
    return out


def _merge_memory(members: Sequence[tuple[str, EntryPoint]]) -> MemoryLayout | None:
    regions: list[MemoryRegion] = []
    modules: list[LoadedModule] = []
    for _, ep in members:
        if ep.memory is None:
            continue
        regions.extend(ep.memory.layout)
        modules.extend(ep.memory.modules)
    if not regions and not modules:
        return None
    return MemoryLayout(layout=_dedupe_models(regions), modules=_dedupe_models(modules))


def _merge_dropped_files(members: Sequence[tuple[str, EntryPoint]]) -> list[DroppedFile] | None:
    dropped = _dedupe_models(dropped for _, ep in members for dropped in (ep.dropped_files or []))
    return dropped or None


def _merge_dynamic_segments(members: Sequence[tuple[str, EntryPoint]]) -> list[DynamicCodeSegment] | None:
    segments = _dedupe_models(segment for _, ep in members for segment in (ep.dynamic_code_segments or []))
    return segments or None


def _entry_identity(ep: EntryPoint) -> str:
    return json.dumps(
        {"ep_type": ep.ep_type, "start_addr": ep.start_addr, "ep_args": ep.ep_args},
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )


def _outcome_fingerprint(ep: EntryPoint) -> str:
    return json.dumps(
        {"ret_val": ep.ret_val, "error": _error_dump(ep.error)},
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )


def _error_dump(error: ErrorInfo | None) -> Any:
    if error is None:
        return None
    return error.model_dump(mode="json", exclude_none=True, exclude={"sources"})


def _merge_entry_point_group(members: Sequence[tuple[str, EntryPoint]]) -> EntryPoint:
    """Combine all source observations of one logical entry point."""

    first_label, base = members[0]

    outcome_order: list[str] = []
    outcome_refs: dict[str, dict[str, int]] = {}
    for label, ep in members:
        fingerprint = _outcome_fingerprint(ep)
        if fingerprint not in outcome_refs:
            outcome_refs[fingerprint] = {}
            outcome_order.append(fingerprint)
        outcome_refs[fingerprint][label] = outcome_refs[fingerprint].get(label, 0) + 1

    outcome_variants: list[EntryPointOutcome] | None = None
    if len(outcome_order) > 1:
        outcome_variants = []
        for fingerprint in outcome_order:
            ep = next(ep for label, ep in members if _outcome_fingerprint(ep) == fingerprint)
            refs = [
                MergeSourceRef(source=label, count=count)
                for label, count in sorted(outcome_refs[fingerprint].items())
            ]
            outcome_variants.append(EntryPointOutcome(sources=refs, ret_val=ep.ret_val, error=ep.error))

    coverage: set[int] = set()
    for _, ep in members:
        coverage.update(ep.coverage or [])

    return EntryPoint(
        ep_type=base.ep_type,
        start_addr=base.start_addr,
        ep_args=list(base.ep_args),
        pid=base.pid,
        tid=base.tid,
        instr_count=base.instr_count,
        apihash=base.apihash,
        ret_val=base.ret_val,
        error=base.error.model_copy(deep=True) if base.error is not None else None,
        events=_merge_entry_events(members),
        sym_accesses=_merge_sym_accesses(members),
        dynamic_code_segments=_merge_dynamic_segments(members),
        coverage=sorted(coverage) or None,
        dropped_files=_merge_dropped_files(members),
        memory=_merge_memory(members),
        sources=[MergeSourceRef(source=label) for label, _ in members],
        outcome_variants=outcome_variants,
    )


def _merge_entry_points(sources: Sequence[_Source]) -> list[EntryPoint]:
    groups: dict[str, list[tuple[str, EntryPoint]]] = {}
    order: list[str] = []
    for source in sources:
        for ep in source.report.entry_points:
            identity = _entry_identity(ep)
            if identity not in groups:
                groups[identity] = []
                order.append(identity)
            groups[identity].append((source.label, ep))
    return [_merge_entry_point_group(groups[identity]) for identity in order]


def _merge_errors(sources: Sequence[_Source]) -> list[ErrorInfo] | None:
    merged: dict[str, ErrorInfo] = {}
    refs: dict[str, dict[str, int]] = {}
    order: list[str] = []
    for source in sources:
        for error in source.report.errors or []:
            fingerprint = _canonical(error, exclude=frozenset({"sources"}))
            if fingerprint not in merged:
                merged[fingerprint] = error.model_copy(deep=True)
                refs[fingerprint] = {}
                order.append(fingerprint)
            refs[fingerprint][source.label] = refs[fingerprint].get(source.label, 0) + 1

    if not merged:
        return None
    for fingerprint in order:
        merged[fingerprint].sources = [
            MergeSourceRef(source=label, count=count) for label, count in sorted(refs[fingerprint].items())
        ]
    return [merged[fingerprint] for fingerprint in order]


def _merge_strings(sources: Sequence[_Source]) -> StringsReport | None:
    def union(values: Iterable[str | None]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for value in values:
            if value is not None and value not in seen:
                seen.add(value)
                out.append(value)
        return out

    static_ansi = union(
        value
        for source in sources
        for value in ((source.report.strings.static.ansi if source.report.strings else []) or [])
    )
    static_unicode = union(
        value
        for source in sources
        for value in ((source.report.strings.static.unicode if source.report.strings else []) or [])
    )
    memory_ansi = union(
        value
        for source in sources
        for value in ((source.report.strings.in_memory.ansi if source.report.strings else []) or [])
    )
    memory_unicode = union(
        value
        for source in sources
        for value in ((source.report.strings.in_memory.unicode if source.report.strings else []) or [])
    )
    if not (static_ansi or static_unicode or memory_ansi or memory_unicode):
        return None
    return StringsReport(
        static=StringCollection(ansi=static_ansi, unicode=static_unicode),
        in_memory=StringCollection(ansi=memory_ansi, unicode=memory_unicode),
    )


def _merge_data(sources: Sequence[_Source]) -> dict[str, DataArtifact] | None:
    merged: dict[str, DataArtifact] = {}
    for source in sources:
        for key, artifact in (source.report.data or {}).items():
            if key in merged and merged[key] != artifact:
                raise ReportMergeError(
                    f"data store entry {key} disagrees between source reports; "
                    "the reports may describe different inputs"
                )
            merged[key] = artifact
    return merged or None


def _first_present(sources: Sequence[_Source], field_name: str) -> Any:
    for source in sources:
        value = getattr(source.report, field_name)
        if value is not None:
            return value
    return None


def _version_key(version: str | None) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in (version or "0").split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _sort_sources(sources: list[_Source]) -> list[_Source]:
    # Stable sort keeps caller/directory order for equal timestamps.
    return sorted(sources, key=lambda source: (source.report.timestamp is None, source.report.timestamp or 0))


def merge_reports(
    reports: Iterable[Report | dict[str, Any]],
    *,
    labels: Sequence[str] | None = None,
    paths: Sequence[str | None] | None = None,
) -> Report:
    """Merge multiple run reports into one combined report.

    Args:
        reports: Source reports, as :class:`Report` instances or raw report dicts.
        labels: Optional source labels, aligned with ``reports``. Defaults to
            ``report-1``, ``report-2``, ... when no paths/labels are available.
        paths: Optional source file paths, aligned with ``reports``.

    Returns:
        A merged :class:`Report` sorted by source start time, with merge-only
        provenance and variant-difference fields populated.

    Raises:
        ReportMergeError: if no reports were supplied or payload stores conflict.
    """

    report_list = list(reports)
    if not report_list:
        raise ReportMergeError("no reports to merge")

    validated: list[Report] = []
    for index, item in enumerate(report_list):
        if isinstance(item, Report):
            validated.append(item)
        else:
            try:
                validated.append(Report.model_validate(item))
            except Exception as err:
                raise ReportMergeError(f"input {index + 1} is not a valid Speakeasy report: {err}") from err

    resolved_labels = list(labels) if labels is not None else [f"report-{index + 1}" for index in range(len(validated))]
    resolved_paths = list(paths) if paths is not None else [None] * len(validated)
    if len(resolved_labels) != len(validated) or len(resolved_paths) != len(validated):
        raise ReportMergeError("labels/paths must align one-to-one with reports")

    sources = _sort_sources(
        [
            _Source(report=report, label=resolved_labels[index], path=resolved_paths[index])
            for index, report in enumerate(validated)
        ]
    )

    merged_from = [
        MergedSource(
            source=source.label,
            path=source.path,
            timestamp=source.report.timestamp,
            arch=source.report.arch,
            filepath=source.report.filepath,
            sha256=source.report.sha256,
            size=source.report.size,
            filetype=source.report.filetype,
            entry_points=len(source.report.entry_points),
            errors=len(source.report.errors or []),
        )
        for source in sources
    ]

    latest_version = max((source.report.report_version for source in sources), key=_version_key)

    return Report(
        report_version=latest_version,
        emulation_total_runtime=round(sum(source.report.emulation_total_runtime for source in sources), 3),
        timestamp=min(source.report.timestamp for source in sources),
        arch=_first_present(sources, "arch"),
        filepath=_first_present(sources, "filepath"),
        sha256=_first_present(sources, "sha256"),
        size=_first_present(sources, "size"),
        filetype=_first_present(sources, "filetype"),
        image_base=_first_present(sources, "image_base"),
        errors=_merge_errors(sources),
        strings=_merge_strings(sources),
        data=_merge_data(sources),
        entry_points=_merge_entry_points(sources),
        merged_from=merged_from,
    )


def _load_report_file(path: str, *, strict: bool) -> Report | None:
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        return Report.model_validate(raw)
    except (OSError, json.JSONDecodeError, ValueError) as err:
        if strict:
            raise ReportMergeError(f"cannot read report {path}: {err}") from err
        return None


def _iter_input_files(input_path: str) -> tuple[list[str], bool]:
    """Return candidate JSON files for an input path and whether it was explicit."""

    if os.path.isfile(input_path):
        return [input_path], True
    if os.path.isdir(input_path):
        found: list[str] = []
        for root, dirnames, filenames in os.walk(input_path):
            dirnames.sort()
            for filename in sorted(filenames):
                if filename.lower().endswith(".json"):
                    found.append(os.path.join(root, filename))
        return found, False
    raise ReportMergeError(f"merge input not found: {input_path}")


def merge_report_files(input_paths: Iterable[str]) -> Report:
    """Merge report JSON files and/or directories of report JSON files.

    Explicit file arguments must be valid report JSON. JSON files discovered
    while walking a directory are included only when they validate as reports,
    so unrelated JSON sitting next to run outputs is ignored.

    Args:
        input_paths: Files and/or directories to read. Directory order and the
            sorted walk order provide a stable tie-breaker for equal timestamps.

    Returns:
        The merged :class:`Report`.

    Raises:
        ReportMergeError: if no usable reports are found or an explicit file is invalid.
    """

    reports: list[Report] = []
    labels: list[str] = []
    seen_paths: set[str] = set()
    for input_path in input_paths:
        candidates, explicit = _iter_input_files(input_path)
        for candidate in candidates:
            normalized = os.path.abspath(candidate)
            if normalized in seen_paths:
                continue
            report = _load_report_file(candidate, strict=explicit)
            if report is None:
                continue
            seen_paths.add(normalized)
            reports.append(report)
            labels.append(candidate)

    if not reports:
        raise ReportMergeError("no Speakeasy report JSON files found in the merge inputs")

    return merge_reports(reports, labels=labels, paths=labels)


def get_merged_json_report(report: Report) -> str:
    """Serialize a merged report the same way single-run reports are written."""

    return report.model_dump_json(indent=4, exclude_none=True)
