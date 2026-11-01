import json
import subprocess
import sys

import pytest

from speakeasy.report_diff import IncomparableReports, compare_reports, load_report_file, render_comparison

SHA = "a" * 64
OTHER_SHA = "b" * 64


def _arg(name, display, type_name="str", value=None):
    return {"name": name, "type": type_name, "value": value, "display": display}


def _pos(pc, tick=1, tid=100, pid=200):
    return {"tick": tick, "tid": tid, "pid": pid, "pc": pc}


def _api(pc, api_name, args=None, ret_val=None, tick=1):
    return {
        "pos": _pos(pc, tick=tick),
        "event": "api",
        "api_name": api_name,
        "args": args if args is not None else [],
        "ret_val": ret_val,
    }


def _evt(event_type, pc, tick=1, **payload):
    return {"pos": _pos(pc, tick=tick), "event": event_type, **payload}


def _ep(events=None, dropped=None, ep_type="module_entry", start_addr="0x401000"):
    ep = {"ep_type": ep_type, "start_addr": start_addr}
    if events is not None:
        ep["events"] = events
    if dropped is not None:
        ep["dropped_files"] = dropped
    return ep


def _report(entry_points=None, sha256=SHA):
    return {
        "report_version": "5.0.0",
        "emulation_total_runtime": 0.1,
        "timestamp": 1,
        "arch": "x86",
        "sha256": sha256,
        "entry_points": [] if entry_points is None else entry_points,
    }


def _items(comparison):
    assert comparison.comparable, comparison.reason
    assert len(comparison.runs) == 1
    return comparison.runs[0].items


def _find(items, kind, identity):
    matches = [item for item in items if item.kind == kind and item.identity == identity]
    assert len(matches) == 1, f"{kind} {identity!r} not found exactly once: {items}"
    return matches[0]


def test_identical_reports_have_no_differences():
    ep = _ep(
        events=[_api(0x401000, "kernel32.GetTickCount", ret_val="0x100", tick=1)],
        dropped=[{"path": "C:\\drop.bin", "size": 4, "sha256": "c" * 64}],
    )
    result = compare_reports(_report([ep]), _report([json.loads(json.dumps(ep))]))

    assert result.comparable
    assert result.runs[0].items == []
    assert "No differences found." in render_comparison(result)


def test_api_events_split_into_added_removed_and_changed():
    old_ep = _ep(
        events=[
            _api(0x401100, "kernel32.GetProcAddress", [_arg("lpProcName", "Sleep")], "0x77000010", tick=1),
            _api(0x401200, "kernel32.LoadLibraryA", [_arg("lpLibFileName", "old.dll")], "0x76000000", tick=2),
        ]
    )
    new_ep = _ep(
        events=[
            _api(0x401300, "kernel32.LoadLibraryA", [_arg("lpLibFileName", "new.dll")], "0x76000100", tick=2),
            _api(0x401400, "kernel32.CreateFileA", [_arg("lpFileName", "drop.bin")], "0x80", tick=3),
        ]
    )
    result = compare_reports(_report([old_ep]), _report([new_ep]))
    items = _items(result)

    removed = _find(items, "removed", "[kernel32] GetProcAddress")
    assert "lpProcName=Sleep" in removed.summary
    assert "pc 0x401100" in removed.before_loc

    added = _find(items, "added", "[kernel32] CreateFileA")
    assert "lpFileName=drop.bin" in added.summary
    assert "pc 0x401400" in added.after_loc

    changed = _find(items, "changed", "[kernel32] LoadLibraryA")
    fields = {change.label: change for change in changed.changes}
    assert fields["args[0]"].before == "lpLibFileName=old.dll"
    assert fields["args[0]"].after == "lpLibFileName=new.dll"
    assert fields["ret_val"].before == "0x76000000"
    assert fields["ret_val"].after == "0x76000100"
    assert "pc 0x401200" in changed.before_loc
    assert "pc 0x401300" in changed.after_loc


def test_repeated_actions_align_in_execution_order():
    old_ep = _ep(
        events=[
            _api(0x401000, "kernel32.LoadLibraryA", [_arg("lpLibFileName", "a.dll")], tick=1),
            _api(0x401100, "kernel32.LoadLibraryA", [_arg("lpLibFileName", "b.dll")], tick=2),
        ]
    )
    new_ep = _ep(
        events=[
            _api(0x401000, "kernel32.LoadLibraryA", [_arg("lpLibFileName", "a.dll")], tick=1),
            _api(0x401200, "kernel32.LoadLibraryA", [_arg("lpLibFileName", "c.dll")], tick=2),
            _api(0x401300, "kernel32.LoadLibraryA", [_arg("lpLibFileName", "d.dll")], tick=3),
        ]
    )
    items = _items(compare_reports(_report([old_ep]), _report([new_ep])))

    load_changes = [item for item in items if item.identity == "[kernel32] LoadLibraryA"]
    assert [(item.kind, item.occurrence, item.show_occurrence) for item in load_changes] == [
        ("changed", 2, True),
        ("added", 3, True),
    ]
    change = next(item for item in load_changes if item.kind == "changed")
    assert change.changes[0].before == "lpLibFileName=b.dll"
    assert change.changes[0].after == "lpLibFileName=c.dll"


def test_non_api_events_align_by_subsystem_and_event_name():
    old_ep = _ep(
        events=[
            _evt("file_create", 0x401000, path="C:\\old.bin", handle="0x80", access_flags=["GENERIC_WRITE"]),
            _evt("reg_open_key", 0x401100, path="HKLM\\Software\\Old", handle="0x10"),
        ]
    )
    new_ep = _ep(
        events=[
            _evt("file_create", 0x401010, path="C:\\new.bin", handle="0x80", access_flags=["GENERIC_WRITE"]),
            _evt("net_dns", 0x401200, query="example.org", response="1.2.3.4"),
        ]
    )
    items = _items(compare_reports(_report([old_ep]), _report([new_ep])))

    changed = _find(items, "changed", "[file] file_create")
    path_change = next(change for change in changed.changes if change.label == "path")
    assert path_change.before == "C:\\old.bin"
    assert path_change.after == "C:\\new.bin"
    assert not any(change.label == "access_flags" for change in changed.changes)

    assert _find(items, "removed", "[registry] reg_open_key")
    assert _find(items, "added", "[network] net_dns")


def test_changed_data_ref_is_reported_as_a_content_change():
    old_ep = _ep(events=[_evt("file_write", 0x401000, path="C:\\drop.bin", size=4, data_ref="1" * 64)])
    new_ep = _ep(events=[_evt("file_write", 0x401000, path="C:\\drop.bin", size=4, data_ref="2" * 64)])
    items = _items(compare_reports(_report([old_ep]), _report([new_ep])))

    changed = _find(items, "changed", "[file] file_write")
    data_change = next(change for change in changed.changes if change.label == "data_ref")
    assert data_change.before == "1" * 64
    assert data_change.after == "2" * 64


def test_dropped_files_split_into_added_removed_and_changed():
    old_ep = _ep(
        dropped=[
            {"path": "C:\\gone.bin", "size": 4, "sha256": "1" * 64},
            {"path": "C:\\same.bin", "size": 4, "sha256": "2" * 64},
        ]
    )
    new_ep = _ep(
        dropped=[
            {"path": "C:\\new.bin", "size": 8, "sha256": "3" * 64},
            {"path": "C:\\same.bin", "size": 8, "sha256": "4" * 64},
        ]
    )
    items = _items(compare_reports(_report([old_ep]), _report([new_ep])))

    assert _find(items, "removed", "C:\\gone.bin")
    assert _find(items, "added", "C:\\new.bin")
    changed = _find(items, "changed", "C:\\same.bin")
    fields = {change.label: change for change in changed.changes}
    assert fields["size"].before == "4"
    assert fields["size"].after == "8"
    assert fields["sha256"].before == "2" * 64
    assert fields["sha256"].after == "4" * 64


def test_different_samples_cannot_be_compared():
    result = compare_reports(_report(sha256=SHA), _report(sha256=OTHER_SHA))

    assert not result.comparable
    assert "different samples" in result.reason
    assert SHA in result.reason and OTHER_SHA in result.reason
    assert render_comparison(result).startswith("Cannot compare reports:")


def test_missing_sample_hash_is_incomplete():
    old = _report()
    old["sha256"] = None
    result = compare_reports(old, _report())

    assert not result.comparable
    assert "incomplete" in result.reason


def test_missing_entry_points_is_incomplete():
    old = _report()
    del old["entry_points"]
    result = compare_reports(old, _report())

    assert not result.comparable
    assert "incomplete" in result.reason


def test_run_sets_must_line_up():
    old_ep = _ep(events=[_api(0x401000, "kernel32.Sleep")])
    new_only_ep = _ep(events=[_api(0x402000, "kernel32.Sleep")], ep_type="thread", start_addr="0x402000")
    result = compare_reports(_report([old_ep]), _report([old_ep, new_only_ep]))

    assert not result.comparable
    assert "do not line up" in result.reason
    assert "thread @ 0x402000" in result.reason


def test_event_without_position_is_incomplete():
    good = _ep(events=[_api(0x401000, "kernel32.Sleep")])
    bad = json.loads(json.dumps(good))
    del bad["events"][0]["pos"]

    result = compare_reports(_report([good]), _report([bad]))
    assert not result.comparable
    assert "position" in result.reason


def test_start_addr_int_and_hex_string_align():
    old_ep = _ep(events=[_api(0x401000, "kernel32.Sleep")], start_addr=0x401000)
    new_ep = _ep(events=[_api(0x401000, "kernel32.Sleep")], start_addr="0x401000")

    result = compare_reports(_report([old_ep]), _report([new_ep]))
    assert result.comparable
    assert result.runs[0].label == "module_entry @ 0x401000"


def test_each_run_is_diffed_separately():
    old_eps = [
        _ep([_api(0x401000, "kernel32.Sleep")], ep_type="module_entry", start_addr="0x401000"),
        _ep([_api(0x402000, "kernel32.ExitThread")], ep_type="thread", start_addr="0x402000"),
    ]
    new_eps = [
        _ep([_api(0x401000, "kernel32.Sleep")], ep_type="module_entry", start_addr="0x401000"),
        _ep([_api(0x402010, "kernel32.CreateThread")], ep_type="thread", start_addr="0x402000"),
    ]
    result = compare_reports(_report(old_eps), _report(new_eps))

    assert result.comparable
    assert [run.label for run in result.runs] == ["module_entry @ 0x401000", "thread @ 0x402000"]
    thread_items = result.runs[1].items
    assert _find(thread_items, "removed", "[kernel32] ExitThread")
    assert _find(thread_items, "added", "[kernel32] CreateThread")


def test_repeated_run_identities_align_in_order():
    def pair(value):
        return _ep([_api(0x401000, "kernel32.LoadLibraryA", [_arg("lpLibFileName", value)])])

    old_eps = [pair("a.dll"), pair("b.dll")]
    new_eps = [pair("a.dll"), pair("c.dll")]
    result = compare_reports(_report(old_eps), _report(new_eps))

    assert result.comparable
    assert len(result.runs) == 2
    assert result.runs[0].items == []
    change = _find(result.runs[1].items, "changed", "[kernel32] LoadLibraryA")
    assert change.changes[0].before == "lpLibFileName=b.dll"
    assert change.changes[0].after == "lpLibFileName=c.dll"


def test_rendered_output_lists_buckets_and_locations():
    old_ep = _ep(events=[_api(0x401100, "kernel32.GetProcAddress", [_arg("lpProcName", "Sleep")], tick=1)])
    new_ep = _ep(events=[_api(0x401200, "kernel32.GetProcAddress", [_arg("lpProcName", "Write")], tick=1)])
    result = compare_reports(_report([old_ep]), _report([new_ep]), old_path="old.json", new_path="new.json")

    text = render_comparison(result)
    assert "old.json -> new.json" in text
    assert "Run: module_entry @ 0x401000" in text
    assert "Changed (1):" in text
    assert "~ [kernel32] GetProcAddress" in text
    assert "args[0]: lpProcName=Sleep -> lpProcName=Write" in text
    assert "before: pc 0x401100" in text
    assert "after:  pc 0x401200" in text
    assert "Summary: 1 changed (1 events)" in text


def test_load_report_file_rejects_garbage(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    with pytest.raises(IncomparableReports, match="could not read"):
        load_report_file(str(bad))


def _write_report(tmp_path, name, report):
    path = tmp_path / name
    path.write_text(json.dumps(report))
    return path


def test_cli_diff_report_prints_differences(tmp_path):
    old_ep = _ep(events=[_api(0x401100, "kernel32.GetProcAddress", [_arg("lpProcName", "Sleep")], tick=1)])
    new_ep = _ep(
        events=[
            _api(0x401200, "kernel32.GetProcAddress", [_arg("lpProcName", "Write")], tick=1),
            _api(0x401300, "kernel32.CreateFileA", [_arg("lpFileName", "drop.bin")], tick=2),
        ]
    )
    old_path = _write_report(tmp_path, "old.json", _report([old_ep]))
    new_path = _write_report(tmp_path, "new.json", _report([new_ep]))

    result = subprocess.run(
        [sys.executable, "-m", "speakeasy.cli", "--diff-report", str(old_path), str(new_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Report comparison:" in result.stdout
    assert "Added (1):" in result.stdout
    assert "Changed (1):" in result.stdout
    assert "[kernel32] CreateFileA" in result.stdout


def test_cli_diff_report_rejects_different_samples(tmp_path):
    old_path = _write_report(tmp_path, "old.json", _report(sha256=SHA))
    new_path = _write_report(tmp_path, "new.json", _report(sha256=OTHER_SHA))

    result = subprocess.run(
        [sys.executable, "-m", "speakeasy.cli", "--diff-report", str(old_path), str(new_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "Cannot compare reports" in result.stderr
    assert "different samples" in result.stderr


def test_cli_diff_report_missing_file_exits_2(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "speakeasy.cli",
            "--diff-report",
            str(tmp_path / "nope.json"),
            str(_write_report(tmp_path, "new.json", _report())),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "Report file not found" in result.stderr
