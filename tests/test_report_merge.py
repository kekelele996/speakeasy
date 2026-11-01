import base64
import hashlib
import json
import os
import subprocess
import sys
import zlib

import pytest

from speakeasy.profiler_events import ApiEvent
from speakeasy.report import Report
from speakeasy.report_merge import ReportMergeError, get_merged_json_report, merge_report_files, merge_reports

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHA = "a" * 64


def pos(tick):
    return {"tick": tick, "tid": 1, "pid": 100, "pc": 4198400 + tick}


def api_event(tick, name, display, *, arg_name="lpFileName", ret_val="0x1", value=4096):
    return {
        "pos": pos(tick),
        "event": "api",
        "api_name": name,
        "args": [{"name": arg_name, "type": "str", "value": value, "display": display}],
        "ret_val": ret_val,
    }


def mem_write_event(tick, path, base, payload_ref, size=4):
    return {
        "pos": pos(tick),
        "event": "mem_write",
        "path": path,
        "base": base,
        "size": size,
        "data_ref": payload_ref,
    }


def entry_point(start_addr="0x401000", events=None, *, error=None, ret_val=None, ep_args=None,
                coverage=None, sym_accesses=None, dropped_files=None, dynamic_code_segments=None, memory=None):
    ep = {
        "ep_type": "module_entry",
        "start_addr": start_addr,
        "ep_args": ep_args if ep_args is not None else [],
        "apihash": "b" * 64,
    }
    if events is not None:
        ep["events"] = events
    if error is not None:
        ep["error"] = error
    if ret_val is not None:
        ep["ret_val"] = ret_val
    if coverage is not None:
        ep["coverage"] = coverage
    if sym_accesses is not None:
        ep["sym_accesses"] = sym_accesses
    if dropped_files is not None:
        ep["dropped_files"] = dropped_files
    if dynamic_code_segments is not None:
        ep["dynamic_code_segments"] = dynamic_code_segments
    if memory is not None:
        ep["memory"] = memory
    return ep


def make_report(timestamp, entry_points, *, filepath="/samples/sample.exe", errors=None, data=None,
                sha256=SHA, size=512, arch="x86", filetype="exe", image_base="0x400000", runtime=0.1,
                version="5.0.0", strings=None):
    report = {
        "report_version": version,
        "emulation_total_runtime": runtime,
        "timestamp": timestamp,
        "arch": arch,
        "filepath": filepath,
        "sha256": sha256,
        "size": size,
        "filetype": filetype,
        "image_base": image_base,
        "entry_points": entry_points,
    }
    if errors is not None:
        report["errors"] = errors
    if data is not None:
        report["data"] = data
    if strings is not None:
        report["strings"] = strings
    return report


def artifact_entry(payload):
    return {
        "compression": "zlib",
        "encoding": "base64",
        "size": len(payload),
        "data": base64.b64encode(zlib.compress(payload)).decode("ascii"),
    }


def write_report(directory, name, report):
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def api_events(ep):
    return [event for event in ep.events if isinstance(event, ApiEvent)]


def test_merge_orders_sources_and_entry_points_by_start_time(tmp_path):
    late = make_report(
        300, [entry_point(events=[api_event(30, "kernel32.CreateFileA", "C:\\late.txt")])],
        filepath="/users/alice/sample.exe",
    )
    early = make_report(
        100,
        [
            entry_point(events=[api_event(10, "kernel32.CreateFileA", "C:\\early.txt")]),
            entry_point("0x402000", events=[api_event(11, "kernel32.ExitThread", "")]),
        ],
        filepath="/users/bob/sample.exe",
    )
    middle = make_report(200, [entry_point()], filepath="/users/carol/sample.exe")

    merged = merge_reports([late, middle, early], labels=["alice", "carol", "bob"])

    assert merged.timestamp == 100
    assert [source.source for source in merged.merged_from] == ["bob", "carol", "alice"]
    assert [source.filepath for source in merged.merged_from] == [
        "/users/bob/sample.exe",
        "/users/carol/sample.exe",
        "/users/alice/sample.exe",
    ]
    assert merged.filepath == "/users/bob/sample.exe"
    # Entry points are grouped by identity and first seen in start-time order.
    assert [ep.start_addr for ep in merged.entry_points] == [0x401000, 0x402000]
    merged_ep = merged.entry_points[0]
    assert [event.args[0].display for event in api_events(merged_ep)] == ["C:\\early.txt", "C:\\late.txt"]
    assert [source.source for source in merged_ep.sources] == ["bob", "carol", "alice"]


def test_identical_actions_collapse_to_one_event_with_every_source():
    def common(tick):
        return [
            api_event(tick, "kernel32.LoadLibraryA", "ws2_32.dll", value=0x2000),
            api_event(tick + 1, "ntdll.RtlInitUnicodeString", "C:\\Windows", value=0x3000),
        ]

    first = make_report(100, [entry_point(events=common(10))])
    second = make_report(200, [entry_point(events=common(50))])

    merged = merge_reports([first, second], labels=["run-a", "run-b"])
    events = api_events(merged.entry_points[0])

    assert len(events) == 2
    assert all(event.variant_group is None for event in events)
    assert all(event.variant_diff is None for event in events)
    assert [(ref.source, ref.count) for event in events for ref in event.sources] == [
        ("run-a", 1),
        ("run-b", 1),
        ("run-a", 1),
        ("run-b", 1),
    ]
    # The representative event keeps one concrete execution position.
    assert events[0].pos.tick == 10


def test_parameter_variants_are_kept_and_differences_are_shown():
    first = make_report(
        100,
        [
            entry_point(
                events=[
                    api_event(10, "kernel32.CreateFileA", "C:\\config.bin", ret_val="0x80"),
                    api_event(11, "kernel32.GetTickCount", "", ret_val="0x100"),
                ]
            )
        ],
    )
    second = make_report(
        200,
        [
            entry_point(
                events=[
                    api_event(99, "kernel32.CreateFileA", "C:\\other.bin", ret_val="0x84"),
                    api_event(98, "kernel32.GetTickCount", "", ret_val="0x100"),
                ]
            )
        ],
    )

    merged = merge_reports([first, second], labels=["run-a", "run-b"])
    events = {event.api_name: event for event in api_events(merged.entry_points[0])}

    assert "kernel32.GetTickCount" in events
    tick = events["kernel32.GetTickCount"]
    assert tick.variant_group is None
    assert [ref.source for ref in tick.sources] == ["run-a", "run-b"]

    create_variants = [
        event for event in api_events(merged.entry_points[0]) if event.api_name == "kernel32.CreateFileA"
    ]
    assert len(create_variants) == 2
    group = "api:kernel32.CreateFileA#1"
    assert [event.args[0].display for event in create_variants] == ["C:\\config.bin", "C:\\other.bin"]
    assert all(event.variant_group == group for event in create_variants)
    assert [ref.source for ref in create_variants[0].sources] == ["run-a"]
    assert [ref.source for ref in create_variants[1].sources] == ["run-b"]

    diff = create_variants[0].variant_diff
    assert create_variants[1].variant_diff is None
    diff_fields = {entry.field: entry.values for entry in diff}
    assert diff_fields["args[0].display"] == ["C:\\config.bin", "C:\\other.bin"]
    assert diff_fields["ret_val"] == ["0x80", "0x84"]


def test_repeated_calls_align_by_occurrence_across_runs():
    def call(repeated_arg, other_arg, tick):
        return [
            api_event(tick, "kernel32.LoadLibraryA", repeated_arg),
            api_event(tick + 1, "kernel32.CreateFileA", other_arg),
        ]

    first = make_report(100, [entry_point(events=call("a.dll", "C:\\x", 10) + call("b.dll", "C:\\x", 30))])
    second = make_report(200, [entry_point(events=call("a.dll", "C:\\x", 70) + call("b.dll", "C:\\x", 90))])

    merged = merge_reports([first, second], labels=["run-a", "run-b"])
    loads = [event for event in api_events(merged.entry_points[0]) if event.api_name == "kernel32.LoadLibraryA"]
    assert [event.args[0].display for event in loads] == ["a.dll", "b.dll"]
    assert [[ref.source for ref in event.sources] for event in loads] == [["run-a", "run-b"], ["run-a", "run-b"]]


def test_input_metadata_and_strings_are_preserved():
    first = make_report(
        100,
        [entry_point()],
        filepath="/downloads/sample.exe",
        strings={"static": {"ansi": ["alpha"], "unicode": []}, "in_memory": {"ansi": [], "unicode": []}},
    )
    second = make_report(
        200,
        [entry_point()],
        filepath="/inbox/sample.exe",
        sha256=SHA,
        strings={"static": {"ansi": ["alpha", "beta"], "unicode": []}, "in_memory": {"ansi": ["gamma"], "unicode": []}},
    )

    merged = merge_reports([first, second], labels=["run-a", "run-b"])

    assert merged.sha256 == SHA
    assert merged.size == 512
    assert merged.arch == "x86"
    assert merged.filetype == "exe"
    assert merged.image_base == 0x400000
    assert merged.strings.static.ansi == ["alpha", "beta"]
    assert merged.strings.in_memory.ansi == ["gamma"]
    assert [source.filepath for source in merged.merged_from] == ["/downloads/sample.exe", "/inbox/sample.exe"]
    assert [source.sha256 for source in merged.merged_from] == [SHA, SHA]


def test_failure_reasons_are_kept_for_every_outcome():
    failed = make_report(
        100,
        [
            entry_point(
                events=[api_event(10, "kernel32.LoadLibraryA", "bad.dll")],
                error={"type": "unsupported_api", "api_name": "mystery.DoThing"},
            )
        ],
        errors=[{"type": "top_level_thing", "context_summary": "session hiccup"}],
    )
    clean = make_report(
        200,
        [entry_point(events=[api_event(20, "kernel32.LoadLibraryA", "bad.dll")], ret_val="0x0")],
        errors=[{"type": "top_level_thing", "context_summary": "session hiccup"}],
    )

    merged = merge_reports([failed, clean], labels=["run-fail", "run-ok"])
    ep = merged.entry_points[0]

    # The earliest variant provides the top-level error fields.
    assert ep.error.type == "unsupported_api"
    outcomes = ep.outcome_variants
    assert len(outcomes) == 2
    assert [ref.source for ref in outcomes[0].sources] == ["run-fail"]
    assert outcomes[0].error.api_name == "mystery.DoThing"
    assert outcomes[0].ret_val is None
    assert [ref.source for ref in outcomes[1].sources] == ["run-ok"]
    assert outcomes[1].error is None
    assert outcomes[1].ret_val == 0

    # The shared action is still collapsed; top-level duplicate error is kept once with both sources.
    assert len(api_events(ep)) == 1
    assert len(merged.errors) == 1
    assert [ref.source for ref in merged.errors[0].sources] == ["run-fail", "run-ok"]


def test_data_store_is_unioned_and_all_refs_stay_resolvable():
    shared = b"shared preview bytes"
    only_a = b"alice-only payload"
    only_b = b"bob-only payload"
    shared_ref = hashlib.sha256(shared).hexdigest()
    a_ref = hashlib.sha256(only_a).hexdigest()
    b_ref = hashlib.sha256(only_b).hexdigest()

    first = make_report(
        100,
        [entry_point(events=[mem_write_event(10, "C:\\Windows\\notepad.exe", "0x10000000", a_ref, len(only_a))])],
        data={shared_ref: artifact_entry(shared), a_ref: artifact_entry(only_a)},
    )
    second = make_report(
        200,
        [entry_point(events=[mem_write_event(40, "C:\\Windows\\notepad.exe", "0x10000000", b_ref, len(only_b))])],
        data={shared_ref: artifact_entry(shared), b_ref: artifact_entry(only_b)},
    )

    merged = merge_reports([first, second], labels=["run-a", "run-b"])

    assert set(merged.data) == {shared_ref, a_ref, b_ref}
    for key, payload in ((shared_ref, shared), (a_ref, only_a), (b_ref, only_b)):
        artifact = merged.data[key]
        decoded = zlib.decompress(base64.b64decode(artifact.data))
        assert decoded == payload
        assert artifact.size == len(payload)
    refs = [event.data_ref for ep in merged.entry_points for event in ep.events]
    assert refs == [a_ref, b_ref]
    assert all(ref in merged.data for ref in refs)


def test_supplementary_run_data_is_merged_without_duplication():
    memory = {
        "layout": [{"tag": "emu.heap", "address": "0x500000", "size": "0x1000", "prot": "rw-"}],
        "modules": [
            {"name": "sample.exe", "path": "C:\\sample.exe", "base": "0x400000", "size": "0x5000", "segments": []}
        ],
    }
    dropped = [{"path": "C:\\ProgramData\\drop.bin", "size": 3, "sha256": "c" * 64, "data_ref": "c" * 64}]
    segments = [{"tag": "emu.alloc.0x10000000", "base": "0x10000000", "size": "0x200"}]
    first = make_report(
        100,
        [
            entry_point(
                coverage=[0x401000, 0x401010],
                sym_accesses=[{"symbol": "kernel32.X", "reads": 1, "writes": 0, "execs": 2}],
                dropped_files=dropped,
                dynamic_code_segments=segments,
                memory=memory,
            )
        ],
        data={"c" * 64: artifact_entry(b"abc")},
    )
    second = make_report(
        200,
        [
            entry_point(
                coverage=[0x401010, 0x401020],
                sym_accesses=[{"symbol": "kernel32.X", "reads": 3, "writes": 1, "execs": 0}],
                dropped_files=dropped,
                dynamic_code_segments=segments,
                memory=memory,
            )
        ],
        data={"c" * 64: artifact_entry(b"abc")},
    )

    merged = merge_reports([first, second], labels=["run-a", "run-b"])
    ep = merged.entry_points[0]

    assert ep.coverage == [0x401000, 0x401010, 0x401020]
    assert ep.sym_accesses[0].reads == 4
    assert ep.sym_accesses[0].writes == 1
    assert ep.sym_accesses[0].execs == 2
    assert len(ep.dropped_files) == 1
    assert len(ep.dynamic_code_segments) == 1
    assert len(ep.memory.layout) == 1
    assert len(ep.memory.modules) == 1


def test_conflicting_payloads_for_same_ref_fail_the_merge():
    payloads = [
        Report.model_validate(make_report(100, [entry_point()], data={"k": artifact_entry(b"one")})),
        Report.model_validate(make_report(200, [entry_point()], data={"k": artifact_entry(b"two")})),
    ]

    with pytest.raises(ReportMergeError, match="data store entry k disagrees"):
        merge_reports(payloads, labels=["run-a", "run-b"])


def test_merge_without_reports_is_an_error():
    with pytest.raises(ReportMergeError, match="no reports to merge"):
        merge_reports([])


def test_invalid_report_dict_is_rejected_with_context():
    with pytest.raises(ReportMergeError, match="input 2 is not a valid Speakeasy report"):
        merge_reports([make_report(100, []), {"not": "a report"}], labels=["ok", "bad"])


def test_directory_inputs_are_scanned_and_unrelated_json_is_ignored(tmp_path):
    write_report(tmp_path / "alice", "run1.json", make_report(100, [entry_point(events=[api_event(1, "a.B", "x")])]))
    write_report(tmp_path / "bob", "run2.json", make_report(200, [entry_point(events=[api_event(2, "a.B", "x")])]))
    (tmp_path / "bob" / "config.json").write_text(json.dumps({"unrelated": True}), encoding="utf-8")

    merged = merge_report_files([str(tmp_path)])

    assert [source.path for source in merged.merged_from] == [
        str(tmp_path / "alice" / "run1.json"),
        str(tmp_path / "bob" / "run2.json"),
    ]
    assert len(api_events(merged.entry_points[0])) == 1


def test_explicit_invalid_file_is_rejected_but_directory_scan_skips_it(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps(make_report(100, [])), encoding="utf-8")
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")

    with pytest.raises(ReportMergeError, match="cannot read report"):
        merge_report_files([str(broken), str(good)])

    nested = tmp_path / "runs"
    nested.mkdir()
    (nested / "broken.json").write_text("{not json", encoding="utf-8")
    merged = merge_report_files([str(nested), str(good)])
    assert len(merged.merged_from) == 1


def test_missing_input_path_is_an_error(tmp_path):
    with pytest.raises(ReportMergeError, match="merge input not found"):
        merge_report_files([str(tmp_path / "nope")])


def test_merged_json_is_parseable_and_plain_reports_carry_no_merge_fields():
    report = make_report(100, [entry_point(events=[api_event(1, "a.B", "x")])])
    rendered = get_merged_json_report(merge_reports([report], labels=["solo"], paths=["/tmp/solo.json"]))
    parsed = json.loads(rendered)

    assert parsed["merged_from"][0]["source"] == "solo"
    assert parsed["entry_points"][0]["events"][0]["sources"] == [{"source": "solo", "count": 1}]
    assert Report.model_validate(parsed)

    plain = Report.model_validate(make_report(100, [entry_point()]))
    plain_json = json.loads(plain.model_dump_json(exclude_none=True))
    assert "merged_from" not in plain_json
    assert "sources" not in plain_json["entry_points"][0]


def run_cli(*args):
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "speakeasy.cli", *args],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def test_cli_merges_colleague_directories_to_output_file(tmp_path):
    write_report(
        tmp_path / "alice",
        "report.json",
        make_report(200, [entry_point(events=[api_event(20, "kernel32.CreateFileA", "C:\\b.txt")])],
                    filepath="/alice/sample.exe"),
    )
    explicit = write_report(
        tmp_path / "bob",
        "report.json",
        make_report(100, [entry_point(events=[api_event(10, "kernel32.CreateFileA", "C:\\a.txt")])],
                    filepath="/bob/sample.exe"),
    )
    output = tmp_path / "merged.json"

    result = run_cli("--merge-report", str(tmp_path / "alice"), "--merge-report", str(explicit), "-o", str(output))

    assert result.returncode == 0, result.stderr
    merged = json.loads(output.read_text(encoding="utf-8"))
    assert [source["filepath"] for source in merged["merged_from"]] == ["/bob/sample.exe", "/alice/sample.exe"]
    create_events = [event for event in merged["entry_points"][0]["events"] if event["event"] == "api"]
    assert [event["args"][0]["display"] for event in create_events] == ["C:\\a.txt", "C:\\b.txt"]
    assert all(event["variant_group"] == "api:kernel32.CreateFileA#1" for event in create_events)


def test_cli_merges_to_stdout_without_output_flag(tmp_path):
    write_report(tmp_path, "a.json", make_report(100, [entry_point()]))

    result = run_cli("--merge-report", str(tmp_path))

    assert result.returncode == 0, result.stderr
    merged = json.loads(result.stdout)
    assert merged["timestamp"] == 100
    assert merged["merged_from"][0]["path"].endswith("a.json")


def test_cli_merge_reports_errors_when_no_reports_found(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    result = run_cli("--merge-report", str(empty), "-o", str(tmp_path / "out.json"))

    assert result.returncode == 1
    assert "no Speakeasy report JSON files found" in result.stderr
    assert not (tmp_path / "out.json").exists()


def test_cli_merge_cannot_be_combined_with_target(tmp_path):
    result = run_cli("-t", str(tmp_path / "sample.exe"), "--merge-report", str(tmp_path))

    assert result.returncode == 2
    assert "--merge-report cannot be combined with --target" in result.stderr
